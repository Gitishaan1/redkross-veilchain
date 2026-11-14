"""Command-line interface. Output is plain ASCII so it works in any Windows console.

Exit codes
  0  success
  1  verification failed (tampering, missing or changed file, leak found)
  2  run completed, but Restricted material (secrets / private keys) was found and removed
  3  usage, input or configuration error
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .classify import classify_cell, classify_record
from .detectors import DetectorSet
from .errors import EXIT_OK, EXIT_USAGE, EXIT_VERIFY_FAILED, VeilChainError
from .keys import generate_key_file, load_keyring
from .pipeline import RunOptions, _known_names, run_redaction
from .policy import Policy
from .risk import k_anonymity, record_id_for
from .rules import load_rules
from .tabular import read_csv_table

REPO_ROOT = Path(__file__).resolve().parents[2]


def _default(name: str) -> str:
    here = Path("policy") / name
    return str(here if here.exists() else REPO_ROOT / "policy" / name)


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--policy", default=_default("data_classification_policy.json"), help="classification policy JSON")
    p.add_argument("--rules", default=_default("veilchain_rules.json"), help="VeilChain rules JSON")


def _add_key(p: argparse.ArgumentParser) -> None:
    p.add_argument("--key-file", help="file containing a hex key (never keep it inside a git repository)")
    p.add_argument("--demo-key", action="store_true", help="use the PUBLIC demo key (reproducible evidence; never for real data)")


def _add_names(p: argparse.ArgumentParser) -> None:
    p.add_argument("--known-names-from", help="CSV whose names should be recognised inside free text")
    p.add_argument("--known-names-column", default="full_name", help="column with the names (default full_name)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veilchain",
        description="VeilChain: classify and redact synthetic records, with a tamper-evident audit ledger.",
    )
    parser.add_argument("--version", action="version", version=f"veilchain {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("classify", help="show how each field and record would be classified (writes nothing)")
    c.add_argument("input")
    _add_common(c)
    _add_names(c)
    c.add_argument("--text-column", action="append", default=[], help="treat this column as free text (repeatable)")
    c.add_argument("--k-min", type=int, default=None, help="also report records whose quasi-identifier group is smaller than K")

    r = sub.add_parser("redact", help="redact a CSV or .txt file and write an evidence bundle")
    r.add_argument("input")
    r.add_argument("--out", required=True, help="NEW output folder (must not already contain files)")
    _add_common(r)
    _add_key(r)
    _add_names(r)
    r.add_argument("--mode", choices=["pseudonymise", "mask"], help="how to replace Confidential values (default from rules)")
    r.add_argument("--release-level", help="highest class allowed to remain in clear (default from rules)")
    r.add_argument("--token-scheme", choices=["hmac", "unkeyed"], default="hmac",
                   help="'unkeyed' is INSECURE and exists only for the red-team demonstration")
    r.add_argument("--text-column", action="append", default=[], help="treat this column as free text (repeatable)")
    r.add_argument("--k-min", type=int, default=None, help="suppress quasi-identifiers shared by fewer than K records")
    r.add_argument("--explain", action="store_true", help="write explain.txt: every decision with the policy text behind it")
    r.add_argument("--add-class-column", action="store_true", help="append the computed class of each record as a column")

    v = sub.add_parser("verify", help="verify an evidence bundle (hashes, ledger chain, optional leak scan)")
    v.add_argument("outdir")
    _add_common(v)
    _add_key(v)
    _add_names(v)
    v.add_argument("--input", help="the original input file: checks it is unchanged and enables --leak-scan")
    v.add_argument("--leak-scan", action="store_true", help="search all output files for original values (needs --input)")

    k = sub.add_parser("risk", help="k-anonymity report over quasi-identifiers (writes nothing)")
    k.add_argument("input")
    _add_common(k)
    k.add_argument("--k-min", type=int, default=2)

    g = sub.add_parser("keygen", help="create a new random key file (refuses to write inside a git repository)")
    g.add_argument("out")
    g.add_argument("--allow-in-repo", action="store_true")

    rt = sub.add_parser("redteam", help="attack VeilChain's own output and report what holds and what does not")
    _add_common(rt)
    rt.add_argument("--out", required=True, help="NEW folder for the red-team report")

    ev = sub.add_parser("eval", help="measure detector precision and recall on a labelled synthetic corpus")
    _add_common(ev)
    ev.add_argument("--corpus", help="JSONL corpus with ground truth (default: generate one)")
    ev.add_argument("--seed", type=int, default=1337)
    ev.add_argument("--size", type=int, default=400)
    ev.add_argument("--out", help="write the report to this new .md file")

    d = sub.add_parser("demo", help="run the whole story on the provided starter files")
    _add_common(d)
    d.add_argument("--data-dir", default=None, help="folder holding the starter CSV files (default: ./data)")
    d.add_argument("--out", required=True, help="NEW folder for the demo outputs")
    return parser


# ---------------------------------------------------------------------------------------
def _cmd_classify(args) -> int:
    policy = Policy.load(args.policy)
    rules = load_rules(args.rules, policy)
    table = read_csv_table(args.input)
    detectors = DetectorSet(rules.record_id_pattern, _known_names(args.known_names_from, args.known_names_column))
    text_columns = frozenset(c.lower() for c in args.text_column)

    print(f"Policy: {policy.name}  (classes low->high: {', '.join(policy.names)})")
    print(f"Input : {Path(args.input).name}  ({len(table.rows)} records, {len(table.fieldnames)} columns)\n")
    print("COLUMNS (field rule)")
    for column in table.fieldnames:
        if column.lower() in text_columns:
            print(f"  {column:<20} free text: classified by content")
            continue
        rule, known = rules.rule_for(column)
        tag = "" if known else "  (UNKNOWN column: default deny)"
        print(f"  {column:<20} {rule.cls:<13}{tag}")
    print("\nRECORDS (highest class found, compared with the owner's label)")
    problems = 0
    for index, row in enumerate(table.rows, start=1):
        rid = record_id_for(row, index)
        cells = [classify_cell(policy, rules, detectors, c, row.get(c), text_columns) for c in table.fieldnames]
        rc = classify_record(policy, rules, rid, cells, row)
        label = f"label={rc.asserted_label}" if rc.asserted_label is not None else "no label"
        flag = "" if rc.status in ("ok", "unlabelled") else f"  <-- {rc.status.upper()} (label implies {rc.expected_class})"
        problems += bool(flag)
        print(f"  {rid:<10} computed={rc.computed_class:<13} {label:<14} driven by: {', '.join(rc.drivers)}{flag}")
    if args.k_min:
        risk = k_anonymity(table, rules, args.k_min)
        print(f"\nRE-IDENTIFICATION RISK (k-anonymity over {', '.join(risk.quasi_identifiers) or 'no quasi-identifiers'})")
        print(f"  smallest group k = {risk.k}; records in groups smaller than {args.k_min}: {', '.join(risk.at_risk_records) or 'none'}")
    print(f"\n{problems} record(s) whose label disagrees with the computed class.")
    return EXIT_OK


def _print_run(result) -> None:
    s = result.summary
    print(f"Records processed : {s['records_processed']}")
    print(f"Release level     : {s['release_level']}   mode: {s['mode']}   token scheme: {s['token_scheme']}")
    print(f"Decisions         : {s['decisions']}")
    if s["label_mismatches"]:
        print(f"Label mismatches  : {len(s['label_mismatches'])} record(s) look UNDER/OVER-classified by their owner's label")
    if s["k_anonymity"]:
        k = s["k_anonymity"]
        print(f"k-anonymity       : k={k['k']} (threshold {k['k_min']}); {k['records_below_k']} record(s) suppressed")
    print(f"Status            : {result.status}")
    print(f"Evidence bundle   : {result.out_dir}")
    print(f"Manifest SHA-256  : {result.manifest_hash}")
    if result.restricted_found:
        print("\n*** ATTENTION: Restricted material (secrets / private keys) was found and REMOVED.")
        print("*** Removing it from this copy does not un-leak it: treat the original secret as exposed and rotate it.")


def _cmd_redact(args) -> int:
    opts = RunOptions(
        input_path=args.input, out_dir=args.out, keyring=load_keyring(args.key_file, args.demo_key),
        policy_path=args.policy, rules_path=args.rules, mode=args.mode, release_level=args.release_level,
        token_scheme=args.token_scheme, text_columns=args.text_column, known_names_from=args.known_names_from,
        known_names_column=args.known_names_column, k_min=args.k_min, explain=args.explain,
        add_class_column=args.add_class_column,
    )
    if opts.keyring.source == "ephemeral":
        print("NOTE: no key supplied, so a random one-run key was used. Tokens are consistent inside this run but cannot be")
        print("      reproduced later and the ledger seal cannot be authenticated. Use --key-file for a real run.\n")
    if opts.keyring.source == "demo":
        print("WARNING: the demo key is PUBLIC. Use it for demonstrations only.\n")
    if opts.token_scheme == "unkeyed":
        print("WARNING: --token-scheme unkeyed is INSECURE (see 'veilchain redteam'). Demonstration only.\n")
    result = run_redaction(opts)
    _print_run(result)
    if args.explain:
        print("\nFirst decisions (full list in explain.txt):")
        for line in result.explain_lines[:12]:
            print("  " + line)
    return result.exit_code


def _cmd_verify(args) -> int:
    from .bundle import verify_bundle

    policy = rules = detectors = None
    keyring = load_keyring(args.key_file, args.demo_key) if (args.key_file or args.demo_key) else None
    if args.leak_scan:
        if not args.input:
            raise VeilChainError("--leak-scan needs --input (the original file) so it knows what must not appear.")
        policy = Policy.load(args.policy)
        rules = load_rules(args.rules, policy)
        detectors = DetectorSet(rules.record_id_pattern, _known_names(args.known_names_from, args.known_names_column))
    report = verify_bundle(args.outdir, keyring, args.input, args.leak_scan, policy, rules, detectors)
    print(f"Verifying evidence bundle: {Path(args.outdir).name}/\n")
    print(report.render())
    return EXIT_OK if report.ok else EXIT_VERIFY_FAILED


def _cmd_risk(args) -> int:
    policy = Policy.load(args.policy)
    rules = load_rules(args.rules, policy)
    table = read_csv_table(args.input)
    risk = k_anonymity(table, rules, args.k_min)
    if not risk.quasi_identifiers:
        print("No quasi-identifier columns found in this file (see the rules file).")
        return EXIT_OK
    print(f"Quasi-identifiers: {', '.join(risk.quasi_identifiers)}")
    print(f"Smallest group (k): {risk.k}   threshold: {args.k_min}\n")
    for size, ids in risk.groups:
        flag = "  <-- below threshold" if size < args.k_min else ""
        print(f"  group of {size}: {', '.join(ids)}{flag}")
    print("\n" + ("PASS: no record is below the threshold." if risk.passes else
                  f"{len(risk.at_risk_records)} record(s) could be singled out. Use 'redact --k-min {args.k_min}' to suppress them."))
    return EXIT_OK


def _cmd_keygen(args) -> int:
    path = generate_key_file(args.out, args.allow_in_repo)
    print(f"Key written to {path}")
    print("Treat it as a RESTRICTED secret: do not commit it, do not paste it into reports or chats.")
    return EXIT_OK


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    try:
        if args.command == "classify":
            return _cmd_classify(args)
        if args.command == "redact":
            return _cmd_redact(args)
        if args.command == "verify":
            return _cmd_verify(args)
        if args.command == "risk":
            return _cmd_risk(args)
        if args.command == "keygen":
            return _cmd_keygen(args)
        if args.command == "redteam":
            from .redteam import run_redteam_command
            return run_redteam_command(args)
        if args.command == "eval":
            from .evaluate import run_eval_command
            return run_eval_command(args)
        if args.command == "demo":
            from .demo import run_demo
            return run_demo(args)
    except VeilChainError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
