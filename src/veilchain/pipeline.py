"""The end-to-end redaction run: intake, classify, decide, transform, log, seal.

Safety properties enforced here:
  * The input is only ever read. Its SHA-256 is taken at intake and re-checked at the end.
  * The output folder must be new or empty; files are created with exclusive mode, so evidence
    can never be silently overwritten.
  * The ledger and manifest never receive original sensitive values or key material.
  * If Restricted material is found the run still completes (so nothing is left half-written)
    but exits with a distinct code (2) and the manifest status says so: fail closed, not silent.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import __version__
from .bundle import describe_file, new_manifest, write_manifest
from .classify import classify_record
from .clock import utc_now
from .detectors import DetectorSet
from .errors import EXIT_OK, EXIT_RESTRICTED_FOUND, EXIT_VERIFY_FAILED, InputError, OutputError
from .hashing import sha256_file
from .keys import KeyRing
from .ledger import LedgerWriter
from .policy import Policy
from .risk import k_anonymity, record_id_for
from .rules import Rules, load_rules
from .tabular import Table, read_csv_table, read_lines, write_csv, write_lines
from .transform import Event, Redactor

SUPPRESSED = "SUPPRESSED"


@dataclass
class RunOptions:
    input_path: str
    out_dir: str
    keyring: KeyRing
    policy_path: str
    rules_path: str
    mode: Optional[str] = None
    release_level: Optional[str] = None
    token_scheme: str = "hmac"
    text_columns: list[str] = field(default_factory=list)
    known_names_from: Optional[str] = None
    known_names_column: str = "full_name"
    k_min: Optional[int] = None
    explain: bool = False
    add_class_column: bool = False


@dataclass
class RunResult:
    exit_code: int
    out_dir: Path
    status: str
    summary: dict
    explain_lines: list[str]
    manifest_hash: str
    restricted_found: bool


def _prepare_out_dir(path: Path, input_path: Path) -> None:
    if path.exists():
        if not path.is_dir():
            raise OutputError(f"Output path exists and is not a folder: {path}")
        if any(path.iterdir()):
            raise OutputError(
                f"Output folder is not empty: {path}. Choose a new folder so earlier evidence is never overwritten."
            )
    try:
        input_path.resolve().relative_to(path.resolve())
    except ValueError:
        pass
    else:
        raise OutputError("The input file is inside the output folder. Choose a different output folder.")
    path.mkdir(parents=True, exist_ok=True)


def _known_names(path: Optional[str], column: str) -> list[str]:
    if not path:
        return []
    table = read_csv_table(path)
    match = [c for c in table.fieldnames if c.lower() == column.lower()]
    if not match:
        raise InputError(f"Known-names file has no column '{column}'.")
    return [(row.get(match[0]) or "").strip() for row in table.rows if (row.get(match[0]) or "").strip()]


def run_redaction(opts: RunOptions) -> RunResult:
    in_path = Path(opts.input_path)
    out_dir = Path(opts.out_dir)
    policy = Policy.load(opts.policy_path)
    rules = load_rules(opts.rules_path, policy)
    mode = opts.mode or rules.defaults.get("mode", "pseudonymise")
    release_level = opts.release_level or rules.defaults.get("release_level", "Internal")
    text_columns = frozenset(c.strip().lower() for c in opts.text_columns if c.strip())

    # Intake (read-only): parse and hash the input before touching the output folder.
    is_text = in_path.suffix.lower() == ".txt"
    if is_text:
        lines, input_sha, input_bytes = read_lines(in_path)
        table = None
    else:
        table = read_csv_table(in_path)
        input_sha, input_bytes = table.sha256, table.size
        for wanted in text_columns:
            if wanted not in [c.lower() for c in table.fieldnames]:
                raise InputError(f"Text column '{wanted}' is not in the input header.")

    _prepare_out_dir(out_dir, in_path)
    names = _known_names(opts.known_names_from, opts.known_names_column)
    detectors = DetectorSet(rules.record_id_pattern, names)
    redactor = Redactor(policy, rules, opts.keyring, detectors, mode, release_level, opts.token_scheme)

    run_id = uuid.uuid4().hex[:16]
    started = utc_now()
    ledger = LedgerWriter(out_dir / "ledger.jsonl", run_id, opts.keyring.seal_key if opts.keyring.reproducible else None)
    ledger.append("run_start", {
        "input": {"name": in_path.name, "sha256": input_sha, "bytes": input_bytes},
        "policy": {"name": policy.name, "sha256": policy.sha256},
        "rules": {"sha256": rules.sha256},
        "parameters": {"mode": mode, "release_level": release_level, "token_scheme": opts.token_scheme,
                       "text_columns": sorted(text_columns), "k_min": opts.k_min},
        "key": {"source": opts.keyring.source, "key_id": opts.keyring.key_id},
    })

    all_events: list[Event] = []
    explain: list[str] = []
    mismatches: list[dict] = []
    findings: Counter = Counter()
    restricted_entities: Counter = Counter()
    class_counts: Counter = Counter()
    out_rows: list[dict] = []
    out_lines: list[str] = []
    risk_info: Optional[dict] = None
    record_count = 0

    def log_event(ev: Event) -> None:
        all_events.append(ev)
        explain.append(ev.explain())
        ledger.append("keep" if ev.action == "keep" else "transform", ev.ledger_data())
        if ev.action == "remove":
            restricted_entities[ev.entity] += 1

    if is_text:
        # The whole file is processed as ONE text. Line-by-line processing would let a multi-line
        # private key block through (found by the red-team suite, RT-5; see docs/BUILD_LOG.md).
        record_count = len(lines)
        starts, offset = [], 0
        for line in lines:
            starts.append(offset)
            offset += len(line) + 1
        import bisect

        def line_of(position: int) -> int:
            return bisect.bisect_right(starts, position)

        new_text, events = redactor.redact_text("\n".join(lines), "text", "file", line_of=line_of)
        for ev in events:
            log_event(ev)
        out_lines = new_text.split("\n")
    else:
        assert table is not None
        # Column-level decisions are logged once, not once per row.
        for column in table.fieldnames:
            if column.lower() in text_columns:
                ledger.append("column", {"column": column, "kind": "free-text", "note": "classified by content"})
                continue
            rule, known = rules.rule_for(column)
            action, _ = redactor.decide(rule.cls)
            ledger.append("column", {"column": column, "known": known, "class": rule.cls, "entity": rule.entity,
                                     "field_action": action, "why": rule.why})
        for number, kind in table.ragged:
            findings["malformed_row"] += 1
            ledger.append("finding", {"type": "malformed_row", "row": number, "kind": kind,
                                      "handling": "extra cells are kept as _extra_N columns and redacted under default-deny"})

        risk = None
        suppress_ids: set[str] = set()
        if opts.k_min:
            risk = k_anonymity(table, rules, opts.k_min)
            suppress_ids = set(risk.at_risk_records)
            risk_info = {"k": risk.k, "k_min": opts.k_min, "quasi_identifiers": risk.quasi_identifiers,
                         "records_below_k": len(risk.at_risk_records)}
            ledger.append("finding", {"type": "k_anonymity", **risk_info})

        for index, row in enumerate(table.rows, start=1):
            record_count += 1
            rid = record_id_for(row, index)
            new_row: dict[str, str | None] = {}
            cells = []
            for column in table.fieldnames:
                new_value, cc, events = redactor.redact_cell(column, row.get(column), rid, text_columns)
                new_row[column] = new_value
                cells.append(cc)
                for ev in events:
                    log_event(ev)
            rc = classify_record(policy, rules, rid, cells, row)
            class_counts[rc.computed_class] += 1
            if rc.status in ("under-classified", "over-classified", "unknown-label"):
                mismatches.append({"record": rid, "label": rc.asserted_label, "expected_class": rc.expected_class,
                                   "computed_class": rc.computed_class, "status": rc.status})
                findings[rc.status] += 1
                ledger.append("finding", {"type": "label_mismatch", "record": rid, "asserted_label": rc.asserted_label,
                                          "expected_class": rc.expected_class, "computed_class": rc.computed_class,
                                          "status": rc.status, "drivers": rc.drivers})
            if rid in suppress_ids and risk is not None:
                for column in risk.quasi_identifiers:
                    if column in new_row and new_row[column] not in (None, "") and not str(new_row[column]).startswith("["):
                        new_row[column] = SUPPRESSED
                ledger.append("transform", {"entity": "QUASI_IDENTIFIERS", "action": "suppress", "record": rid,
                                            "columns": risk.quasi_identifiers, "reason": f"group smaller than k={opts.k_min}"})
                explain.append(f"[{rid}] quasi-identifiers {', '.join(risk.quasi_identifiers)}: SUPPRESSED. "
                               f"Their combination is shared by fewer than {opts.k_min} records, so it could single the person out.")
            if opts.add_class_column:
                new_row["veilchain_class"] = rc.computed_class
            out_rows.append(new_row)

    # Write outputs (exclusive create).
    out_name = f"redacted_{in_path.name}"
    out_path = out_dir / out_name
    if is_text:
        write_lines(out_path, out_lines)
    else:
        fieldnames = list(table.fieldnames) + (["veilchain_class"] if opts.add_class_column else [])
        write_csv(out_path, fieldnames, out_rows)

    counts_by_action = Counter(ev.action for ev in all_events)
    counts_by_entity = Counter(f"{ev.entity}:{ev.action}" for ev in all_events)
    restricted_found = bool(restricted_entities)
    summary = {
        "records_processed": record_count,
        "release_level": release_level,
        "mode": mode,
        "token_scheme": opts.token_scheme,
        "decisions": dict(sorted(counts_by_action.items())),
        "decisions_by_entity": dict(sorted(counts_by_entity.items())),
        "record_classes": dict(sorted(class_counts.items())),
        "label_mismatches": mismatches,
        "findings": dict(sorted(findings.items())),
        "restricted_found": restricted_found,
        "restricted_entities": dict(sorted(restricted_entities.items())),
        "k_anonymity": risk_info,
        "known_names_loaded": len(names),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    files = {out_name: describe_file(out_path), "summary.json": describe_file(out_dir / "summary.json")}
    if opts.explain:
        header = [f"VeilChain explanation of every decision (policy: {policy.name})", ""]
        (out_dir / "explain.txt").write_text("\n".join(header + explain) + "\n", encoding="utf-8", newline="\n")
        files["explain.txt"] = describe_file(out_dir / "explain.txt")

    # Non-destructive guarantee: the input must be exactly as it was at intake.
    input_unchanged = sha256_file(in_path) == input_sha
    status = "COMPLETE_RESTRICTED_FOUND" if restricted_found else "COMPLETE"
    if not input_unchanged:
        status = "INPUT_CHANGED_DURING_RUN"
        ledger.append("finding", {"type": "input_changed_during_run"})

    ledger.append("run_end", {"status": status, "records": record_count, "decisions": dict(counts_by_action),
                              "output": {"name": out_name, "sha256": files[out_name]["sha256"]},
                              "input_unchanged": input_unchanged})
    seal = ledger.seal()
    files["ledger.jsonl"] = describe_file(out_dir / "ledger.jsonl")

    manifest = new_manifest(
        command="redact",
        run_id=run_id,
        started=started,
        finished=utc_now(),
        status=status,
        parameters={"mode": mode, "release_level": release_level, "token_scheme": opts.token_scheme,
                    "text_columns": sorted(text_columns), "k_min": opts.k_min,
                    "known_names_file": Path(opts.known_names_from).name if opts.known_names_from else None},
        key={"source": opts.keyring.source, "key_id": opts.keyring.key_id, "reproducible": opts.keyring.reproducible},
        inputs=[{"name": in_path.name, "sha256": input_sha, "bytes": input_bytes}],
        policy={"name": policy.name, "sha256": policy.sha256},
        rules={"sha256": rules.sha256},
        files=files,
        ledger={"entries": ledger.count, "head": seal["head"]},
    )
    manifest_hash = write_manifest(out_dir, manifest)

    if not input_unchanged:
        exit_code = EXIT_VERIFY_FAILED
    elif restricted_found:
        exit_code = EXIT_RESTRICTED_FOUND
    else:
        exit_code = EXIT_OK
    return RunResult(exit_code, out_dir, status, summary, explain, manifest_hash, restricted_found)
