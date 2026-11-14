"""Red team: attack VeilChain's own output and report honestly what holds and what does not.

Every attack uses synthetic data generated here. Outcomes:
  DEFENDED  the attack failed;
  PARTIAL   the attack partly worked, or only works under a stated condition (for example a
            stolen key);
  BROKEN    the attack worked: that is a weakness the report must disclose.

Attack list
  RT-1  brute-force reversal of pseudonym tokens (unkeyed hash v0, keyed HMAC v1, stolen key)
  RT-2  leakage scan for originals and their encodings in every output (with a scanner self-test)
  RT-3  linkage through quasi-identifiers (k-anonymity), before and after suppression
  RT-4  obfuscated PII battery (what the detectors catch and what they miss)
  RT-5  secrets: is anything derived from a Restricted value stored anywhere?
  RT-6  ledger and evidence tampering battery (with and without the key)
  RT-7  linkage across releases (same key versus different keys)
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .bundle import MANIFEST_NAME, verify_bundle, write_manifest
from .detectors import DetectorSet, normalise_value
from .errors import OutputError
from .hashing import canonical_json, hmac_hex, sha256_bytes
from .keys import DEMO_KEY, KeyRing
from .ledger import GENESIS, read_entries
from .leakscan import collect_canaries, scan_paths
from .pipeline import RunOptions, run_redaction
from .policy import Policy
from .risk import k_anonymity
from .rules import load_rules
from .synth import generate_records
from .tabular import read_csv_table, write_csv

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class AttackResult:
    id: str
    title: str
    goal: str
    outcome: str
    summary: str
    details: list[str] = field(default_factory=list)


def _make_records(work: Path, n: int = 50, seed: int = 7) -> Path:
    path = work / f"records_{n}_{seed}.csv"
    if not path.exists():  # write_csv never overwrites, so reuse a file made earlier in this run
        write_csv(path, ["record_id", "full_name", "email", "phone", "department", "data_sensitivity"], generate_records(n, seed))
    return path


def _out_csv(records: Path) -> str:
    return f"redacted_{records.name}"


def _redact(work: Path, name: str, input_path: Path, keyring: KeyRing, policy_path: str, rules_path: str, **kw):
    opts = RunOptions(input_path=str(input_path), out_dir=str(work / name), keyring=keyring,
                      policy_path=policy_path, rules_path=rules_path, **kw)
    return run_redaction(opts)


def _tokens(csv_path: Path, column: str) -> set[str]:
    table = read_csv_table(csv_path)
    return {(row.get(column) or "").split("#")[-1] for row in table.rows}


# --- RT-1 ----------------------------------------------------------------------------------
def rt1_token_reversal(work: Path, policy_path: str, rules_path: str) -> AttackResult:
    records = _make_records(work)
    attacker_unknown_key = KeyRing(os.urandom(32), "ephemeral")
    res_v0 = _redact(work, "rt1_v0", records, attacker_unknown_key, policy_path, rules_path, token_scheme="unkeyed")
    res_v1 = _redact(work, "rt1_v1", records, attacker_unknown_key, policy_path, rules_path, token_scheme="hmac")
    v0_tokens = _tokens(res_v0.out_dir / _out_csv(records), "phone")
    v1_tokens = _tokens(res_v1.out_dir / _out_csv(records), "phone")
    # The attacker knows the scheme and the number format (+353-00-NNN-NNNN): 10^6 candidates.
    candidates = [f"+35300{mid:03d}{last:04d}" for mid in range(100) for last in range(10000)]

    def attack(token_set: set[str], fn) -> tuple[int, float]:
        start = time.perf_counter()
        found = sum(1 for cand in candidates if fn(cand) in token_set)
        return found, time.perf_counter() - start

    plain = lambda c: hashlib.sha256(("PHONE\x1f" + c).encode()).hexdigest()[:10]
    v0_found, v0_time = attack(v0_tokens, plain)
    v1_found, v1_time = attack(v1_tokens, plain)
    key = attacker_unknown_key.token_key
    stolen = lambda c: hmac_hex(key, "PHONE", c)[:10]
    stolen_found, stolen_time = attack(v1_tokens, stolen)
    n = len(v0_tokens)
    details = [
        f"Search space: {len(candidates):,} candidate numbers; {n} distinct phone tokens in each output.",
        f"v0 (unkeyed SHA-256 tokens): recovered {v0_found}/{n} in {v0_time:.1f}s with no secret at all.",
        f"v1 (keyed HMAC tokens), attacker without the key: recovered {v1_found}/{n} in {v1_time:.1f}s.",
        f"v1 with the token key stolen: recovered {stolen_found}/{n} in {stolen_time:.1f}s. Key custody is the remaining weakness.",
        "Lesson: hashing a low-entropy value (a phone number) is not protection; a secret key is what makes it infeasible.",
    ]
    outcome = "DEFENDED" if v1_found == 0 else "BROKEN"
    summary = (f"v0 unkeyed tokens: BROKEN ({v0_found}/{n} recovered). v1 HMAC tokens: {'DEFENDED' if v1_found == 0 else 'BROKEN'}. "
               f"With a stolen key: {stolen_found}/{n} recovered.")
    return AttackResult("RT-1", "Brute-force reversal of pseudonym tokens", "Recover real phone numbers from the redacted file",
                        outcome, summary, details)


# --- RT-2 ----------------------------------------------------------------------------------
def rt2_leak_scan(work: Path, policy: Policy, rules, policy_path: str, rules_path: str) -> AttackResult:
    records = _make_records(work)
    res = _redact(work, "rt2", records, KeyRing(DEMO_KEY, "demo"), policy_path, rules_path, explain=True)
    detectors = DetectorSet(rules.record_id_pattern, [])
    canaries = collect_canaries(records, policy, rules, detectors)
    files = [p for p in res.out_dir.iterdir() if p.is_file()]
    findings, scanned = scan_paths(files, canaries)
    # Scanner self-test: plant an encoded original in a copy and confirm the scanner notices.
    copy = work / "rt2_planted"
    shutil.copytree(res.out_dir, copy)
    with open(copy / "explain.txt", "a", encoding="utf-8") as handle:
        handle.write("planted: " + base64.b64encode(canaries[0].encode()).decode() + "\n")
    planted, _ = scan_paths([p for p in copy.iterdir() if p.is_file()], canaries)
    caught = any(f.variant.startswith("base64") for f in planted)
    details = [
        f"{scanned} original sensitive values searched for (and 7 kinds of re-encoding each) across {len(files)} output files, including ledger and manifest.",
        f"Leaks found in the real output: {len(findings)}.",
        f"Scanner self-test (a base64-encoded original planted in a copy): {'caught' if caught else 'MISSED'}.",
    ]
    outcome = "DEFENDED" if not findings and caught else "BROKEN"
    return AttackResult("RT-2", "Leakage scan for originals and their encodings", "Find any original value anywhere in the evidence bundle",
                        outcome, f"{len(findings)} leaks in {len(files)} files; scanner self-test {'passed' if caught else 'FAILED'}.", details)


# --- RT-3 ----------------------------------------------------------------------------------
def rt3_linkage(work: Path, rules, policy_path: str, rules_path: str) -> AttackResult:
    sample = REPO_ROOT / "data" / "customer_records_synthetic.csv"
    if not sample.is_file():
        sample = _make_records(work, 8, 3)
    table = read_csv_table(sample)
    before = k_anonymity(table, rules, 2)
    res = _redact(work, "rt3", sample, KeyRing(DEMO_KEY, "demo"), policy_path, rules_path, k_min=2)
    out_table = read_csv_table(res.out_dir / f"redacted_{sample.name}")
    after = k_anonymity(out_table, rules, 2)
    details = [
        f"Quasi-identifiers: {', '.join(before.quasi_identifiers)}.",
        f"Before suppression: k={before.k}; records that a person who knows these facts could single out: {', '.join(before.at_risk_records) or 'none'}.",
        f"After suppression (k-min 2): k={after.k}; records still unique: {', '.join(after.at_risk_records) or 'none'}.",
        "Cost: the suppressed records lose their department and label, so analysis on those fields is no longer possible for them.",
        "Residual risk: the SUPPRESSED value itself marks a record as unusual. This is a simple check, not formal de-identification.",
    ]
    outcome = "DEFENDED" if after.passes else "PARTIAL"
    return AttackResult("RT-3", "Linkage through quasi-identifiers (k-anonymity)", "Single out one person using department + label",
                        outcome, f"k {before.k} -> {after.k}; at-risk records {len(before.at_risk_records)} -> {len(after.at_risk_records)}.", details)


# --- RT-4 ----------------------------------------------------------------------------------
OBFUSCATION_CASES = [
    ("plain email", "Mail maya.example@example.com now", "EMAIL", True),
    ("UPPER-CASE email", "Mail MAYA.EXAMPLE@EXAMPLE.COM now", "EMAIL", True),
    ("plus-address email", "Mail maya+test@example.com now", "EMAIL", True),
    ("[at]/[dot] email", "Mail maya[at]example[dot]com now", "EMAIL", True),
    ("(at)/(dot) with spaces", "Mail maya (at) example (dot) com now", "EMAIL", True),
    ("spaced dots and @", "Mail maya . example @ example . com now", "EMAIL", True),
    ("zero-width characters", "Mail ma\u200bya@exam\u200bple.com now", "EMAIL", True),
    ("letters spaced out", "Mail m a y a @ e x a m p l e . c o m now", "EMAIL", None),
    ("words: dot / at", "Mail maya dot example at example dot com now", "EMAIL", None),
    ("reversed text", "Mail moc.elpmaxe@aym now", "EMAIL", None),
    ("base64-encoded email", "Mail " + base64.b64encode(b"maya.example@example.com").decode() + " now", "EMAIL", None),
    ("phone with hyphens", "Call +353-00-000-0007 now", "PHONE", True),
    ("phone with dots", "Call +353.00.000.0007 now", "PHONE", True),
    ("phone with no separators", "Call +353000000007 now", "PHONE", True),
    ("full-width digits phone", "Call \uff0b\uff13\uff15\uff13\uff0d\uff10\uff10\uff0d\uff10\uff10\uff10\uff0d\uff10\uff10\uff10\uff17 now", "PHONE", True),
    ("phone, digits only, no plus", "Call 353000000007 now", "PHONE", None),
    ("phone spelled in words", "Call plus three five three zero zero now", "PHONE", None),
    ("card with spaces", "Card 4111 1111 1111 1111 now", "CARD", True),
    ("card split across words", "Card 4111 1111 and 1111 1111 now", "CARD", None),
]


def rt4_obfuscation(rules) -> AttackResult:
    detectors = DetectorSet(rules.record_id_pattern, [])
    lines, caught_expected, missed_unexpected, missed_known = [], 0, [], []
    expected_total = 0
    for label, text, entity, expected in OBFUSCATION_CASES:
        hit = any(d.entity == entity for d in detectors.detect(text))
        mark = "caught" if hit else "MISSED"
        lines.append(f"{label:<28} {mark}")
        if expected is True:
            expected_total += 1
            caught_expected += hit
            if not hit:
                missed_unexpected.append(label)
        elif not hit:
            missed_known.append(label)
    details = [f"{len(OBFUSCATION_CASES)} evasion attempts; the detectors are designed to handle {expected_total} of them."] + lines + [
        "The cases marked MISSED that are not in the 'designed to handle' set are documented limits, not bugs: pattern matching cannot "
        "understand spelled-out, reversed or encoded data. A real deployment needs additional controls (DLP, review) for those.",
    ]
    outcome = "DEFENDED" if not missed_unexpected else "BROKEN"
    summary = (f"{caught_expected}/{expected_total} designed-for evasions caught; "
               f"{len(missed_known)} out-of-scope evasions slip through: {', '.join(missed_known)}.")
    return AttackResult("RT-4", "Obfuscated PII battery", "Hide an email, phone or card number from the detectors", "PARTIAL" if outcome == "DEFENDED" else "BROKEN", summary, details)


# --- RT-5 ----------------------------------------------------------------------------------
def rt5_restricted(work: Path, policy_path: str, rules_path: str) -> AttackResult:
    secrets = ["VCFAKE-9f8e7d6c5b4a39", "VCFAKE-Passw0rd-Zq81xT", "VCFAKE-bearer-A1B2C3D4E5F6G7H8"]
    begin, end = "-----BEGIN " + "FAKE PRIVATE KEY-----", "-----END " + "FAKE PRIVATE KEY-----"
    key_body = "VEILCHAIN-DEMO-NOT-A-REAL-KEY-0123456789"
    text = "\n".join([
        f"deploy log: password={secrets[0]}",
        f"api_key: {secrets[1]}",
        f"Authorization: Bearer {secrets[2]}",
        f"{begin}\n{key_body}\n{end}",
        "contact ops at ops.team@example.com",
    ]) + "\n"
    src = work / "restricted_input.txt"
    src.write_text(text, encoding="utf-8")
    keyring = KeyRing(os.urandom(32), "file")
    res = _redact(work, "rt5", src, keyring, policy_path, rules_path, explain=True)
    derived: list[str] = []
    for value in secrets + [key_body]:
        derived += [value, value.lower(), base64.b64encode(value.encode()).decode(), value.encode().hex(),
                    hashlib.sha256(value.encode()).hexdigest(), hashlib.sha256(value.encode()).hexdigest()[:10],
                    hashlib.sha256(value.encode()).hexdigest()[:16]]
        norm = normalise_value("SECRET", value)
        for label in ("SECRET", "PRIVATE_KEY"):
            derived += [hmac_hex(keyring.audit_key, label, norm)[:16], hmac_hex(keyring.token_key, label, norm)[:10]]
    corpus = "\n".join(p.read_bytes().decode("utf-8", "ignore") for p in res.out_dir.iterdir() if p.is_file())
    leaked = [d for d in derived if d in corpus]
    details = [
        f"Run exit code: {res.exit_code} (2 = Restricted material found); manifest status: {res.status}.",
        f"Searched every output file for {len(derived)} derivations of the secrets (raw, case, base64, hex, plain SHA-256 and prefixes, HMAC tokens and fingerprints).",
        f"Derivations found anywhere: {len(leaked)}.",
        "Design: Restricted values are removed and nothing derived from them (no token, no fingerprint) is logged.",
        "Operational note: redaction does not un-leak a secret. Any secret found in data must be rotated.",
    ]
    ok = res.exit_code == 2 and not leaked
    return AttackResult("RT-5", "Secrets: is anything derived from a Restricted value stored?", "Recover or confirm a secret from the ledger, manifest or output",
                        "DEFENDED" if ok else "BROKEN", f"exit code {res.exit_code}; {len(leaked)} derivations found in outputs.", details)


# --- RT-6 ----------------------------------------------------------------------------------
def _rewrite_consistently(outdir: Path, mutate) -> None:
    """Attacker WITHOUT the key edits a ledger entry, recomputes every hash and fixes the manifest."""
    path = outdir / "ledger.jsonl"
    entries = read_entries(path)
    mutate(entries)
    prev = GENESIS
    for entry in entries:
        entry["prev"] = prev
        if entry["event"] == "seal":
            entry["data"]["head"] = prev  # hash of the entry just before the seal
        body = {k: v for k, v in entry.items() if k != "hash"}
        entry["hash"] = sha256_bytes(canonical_json(body).encode())
        prev = entry["hash"]
    path.write_text("".join(canonical_json(e) + "\n" for e in entries), encoding="utf-8", newline="\n")
    manifest_path = outdir / MANIFEST_NAME
    import json
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["ledger.jsonl"] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
    manifest["ledger"] = {"entries": len(entries), "head": entries[-1]["data"]["head"]}
    write_manifest(outdir, manifest)


def rt6_tamper(work: Path, policy_path: str, rules_path: str) -> AttackResult:
    import json

    records = _make_records(work, 30, 11)
    keyring = KeyRing(os.urandom(32), "file")
    base = _redact(work, "rt6_base", records, keyring, policy_path, rules_path).out_dir
    rows: list[tuple[str, bool, bool, str]] = []  # (attack, detected w/o key, detected with key, note)

    def fresh(name: str) -> Path:
        dest = work / f"rt6_{name}"
        shutil.copytree(base, dest)
        return dest

    def detected(dest: Path, key: KeyRing | None) -> bool:
        return not verify_bundle(dest, key, records).ok

    out_csv = _out_csv(records)

    d = fresh("a")
    lines = (d / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    target = next(i for i, line in enumerate(lines) if '"action":"tokenise"' in line)
    lines[target] = lines[target].replace('"action":"tokenise"', '"action":"keep"', 1)
    (d / "ledger.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows.append(("a. edit one ledger entry in place", detected(d, None), detected(d, keyring), "hash chain"))

    d = fresh("b")
    lines = (d / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    del lines[10]
    (d / "ledger.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows.append(("b. delete one ledger entry", detected(d, None), detected(d, keyring), "chain and sequence numbers"))

    d = fresh("c")
    lines = (d / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    lines[7], lines[8] = lines[8], lines[7]
    (d / "ledger.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows.append(("c. swap two ledger entries", detected(d, None), detected(d, keyring), "chain and sequence numbers"))

    d = fresh("d")
    lines = (d / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    (d / "ledger.jsonl").write_text("\n".join(lines[:-6]) + "\n", encoding="utf-8")
    rows.append(("d. cut the end off the ledger", detected(d, None), detected(d, keyring), "missing seal, manifest count"))

    d = fresh("e")
    (d / "ledger.jsonl").unlink()
    rows.append(("e. delete the ledger", detected(d, None), detected(d, keyring), "missing file"))

    d = fresh("f")
    with open(d / out_csv, "a", encoding="utf-8") as handle:
        handle.write("REC-999,EXTRA,ROW,INSERTED,Support,low\r\n")
    rows.append(("f. alter the redacted output only", detected(d, None), detected(d, keyring), "file hash"))

    d = fresh("g")
    with open(d / out_csv, "a", encoding="utf-8") as handle:
        handle.write("REC-999,EXTRA,ROW,INSERTED,Support,low\r\n")
    manifest_path = d / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][out_csv] = {"sha256": hashlib.sha256((d / out_csv).read_bytes()).hexdigest(), "bytes": (d / out_csv).stat().st_size}
    write_manifest(d, manifest)
    rows.append(("g. alter the output AND update the manifest", detected(d, None), detected(d, keyring), "ledger run_end hash cross-check"))

    d = fresh("h")
    with open(d / out_csv, "a", encoding="utf-8") as handle:
        handle.write("REC-999,EXTRA,ROW,INSERTED,Support,low\r\n")

    def mutate(entries):
        for entry in entries:
            if entry["event"] == "run_end":
                entry["data"]["output"]["sha256"] = hashlib.sha256((d / out_csv).read_bytes()).hexdigest()

    _rewrite_consistently(d, mutate)
    manifest = json.loads((d / MANIFEST_NAME).read_text(encoding="utf-8"))
    manifest["files"][out_csv] = {"sha256": hashlib.sha256((d / out_csv).read_bytes()).hexdigest(), "bytes": (d / out_csv).stat().st_size}
    write_manifest(d, manifest)
    rows.append(("h. rewrite output, ledger chain AND manifest", detected(d, None), detected(d, keyring), "only the seal MAC (needs the key)"))

    details = ["Attack | detected without the key | detected with the key | what caught it"]
    for name, no_key, with_key, note in rows:
        details.append(f"{name} | {'yes' if no_key else 'NO'} | {'yes' if with_key else 'NO'} | {note}")
    undetected_without_key = [n for n, nk, _wk, _ in rows if not nk]
    undetected_with_key = [n for n, _nk, wk, _ in rows if not wk]
    details += [
        "",
        "Honest limit: a hash chain proves consistency, not authenticity. An attacker who can rewrite the ledger, recompute every hash "
        "and fix the manifest produces a bundle that verifies WITHOUT the key. The keyed seal (HMAC) closes that gap for anyone who holds the key, "
        "and publishing the ledger head hash somewhere the attacker cannot reach (for example a git commit) closes it for everyone.",
    ]
    outcome = "DEFENDED" if not undetected_with_key and not undetected_without_key else ("PARTIAL" if not undetected_with_key else "BROKEN")
    summary = (f"{len(rows) - len(undetected_without_key)}/{len(rows)} tampering attacks detected without the key; "
               f"{len(rows) - len(undetected_with_key)}/{len(rows)} with the key. "
               f"Undetected without key: {', '.join(n.split('.')[0] for n in undetected_without_key) or 'none'}.")
    return AttackResult("RT-6", "Ledger and evidence tampering battery", "Alter evidence without verification noticing", outcome, summary, details)


# --- RT-7 ----------------------------------------------------------------------------------
def rt7_cross_release(work: Path, policy_path: str, rules_path: str) -> AttackResult:
    records = _make_records(work, 20, 5)
    k1, k2 = KeyRing(os.urandom(32), "file"), KeyRing(os.urandom(32), "file")
    a = _redact(work, "rt7_a", records, k1, policy_path, rules_path)
    b = _redact(work, "rt7_b", records, k1, policy_path, rules_path)
    c = _redact(work, "rt7_c", records, k2, policy_path, rules_path)
    ta = _tokens(a.out_dir / _out_csv(records), "email")
    tb = _tokens(b.out_dir / _out_csv(records), "email")
    tc = _tokens(c.out_dir / _out_csv(records), "email")
    same_key_links = len(ta & tb)
    diff_key_links = len(ta & tc)
    details = [
        f"Two releases with the SAME key share {same_key_links}/{len(ta)} email tokens (records can be joined across releases).",
        f"Two releases with DIFFERENT keys share {diff_key_links}/{len(ta)} email tokens (releases cannot be joined).",
        "Design choice: use one key when joinability across files is required; use a fresh key per release when unlinkability matters more.",
    ]
    outcome = "DEFENDED" if diff_key_links == 0 else "BROKEN"
    return AttackResult("RT-7", "Linkage across releases", "Join two separately shared files to follow a person over time",
                        outcome, f"same key: {same_key_links}/{len(ta)} linkable; different keys: {diff_key_links}/{len(ta)} linkable.", details)


# --- driver --------------------------------------------------------------------------------
def run_redteam(policy_path: str, rules_path: str) -> list[AttackResult]:
    policy = Policy.load(policy_path)
    rules = load_rules(rules_path, policy)
    with tempfile.TemporaryDirectory(prefix="veilchain_rt_") as tmp:
        work = Path(tmp)
        return [
            rt1_token_reversal(work, policy_path, rules_path),
            rt2_leak_scan(work, policy, rules, policy_path, rules_path),
            rt3_linkage(work, rules, policy_path, rules_path),
            rt4_obfuscation(rules),
            rt5_restricted(work, policy_path, rules_path),
            rt6_tamper(work, policy_path, rules_path),
            rt7_cross_release(work, policy_path, rules_path),
        ]


def render_report(results: list[AttackResult]) -> str:
    lines = ["# VeilChain red-team report", "",
             "All attacks use synthetic data generated at run time. DEFENDED = attack failed; PARTIAL = works only under a stated condition or is a documented limit; BROKEN = attack worked.", "",
             "| ID | Attack | Outcome | Result |", "|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r.id} | {r.title} | {r.outcome} | {r.summary} |")
    for r in results:
        lines += ["", f"## {r.id}: {r.title}", "", f"Attacker goal: {r.goal}.", ""]
        if r.id == "RT-6":
            rows = [d.split(" | ") for d in r.details if " | " in d]
            lines += ["| " + " | ".join(rows[0]) + " |", "|---|---|---|---|"]
            lines += ["| " + " | ".join(row) + " |" for row in rows[1:]]
            lines += [""] + [d for d in r.details if " | " not in d and d]
        elif r.id == "RT-4":
            lines += ["```"] + [d for d in r.details if "  " in d and not d.startswith("The cases") and "evasion attempts" not in d] + ["```", ""]
            lines += [d for d in r.details if d.startswith("The cases") or "evasion attempts" in d]
        else:
            lines += [f"- {d}" for d in r.details]
    return "\n".join(lines) + "\n"


def run_redteam_command(args) -> int:
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise OutputError(f"Output folder is not empty: {out}")
    out.mkdir(parents=True, exist_ok=True)
    print("Running red-team attacks on synthetic data (this takes a few seconds)...\n")
    results = run_redteam(args.policy, args.rules)
    report = render_report(results)
    (out / "redteam_report.md").write_text(report, encoding="utf-8", newline="\n")
    import json
    (out / "redteam_results.json").write_text(
        json.dumps([r.__dict__ for r in results], indent=2, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")
    print(f"{'ID':<6}{'Outcome':<10}Result")
    for r in results:
        print(f"{r.id:<6}{r.outcome:<10}{r.summary}")
    print(f"\nFull report: {out / 'redteam_report.md'}")
    return 0
