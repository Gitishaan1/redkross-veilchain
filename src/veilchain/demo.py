"""`veilchain demo`: the whole story in one command, on the provided starter files.

Steps: classify -> redact -> verify -> tamper -> detect -> restore -> secrets (fail closed).
All data is synthetic. The demo key is public and is used only so that runs are repeatable.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .bundle import verify_bundle
from .detectors import DetectorSet
from .errors import OutputError
from .keys import DEMO_KEY, KeyRing
from .leakscan import collect_canaries
from .pipeline import RunOptions, _known_names, run_redaction
from .policy import Policy
from .rules import load_rules


def _banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def _show(report) -> None:
    for check in report.checks:
        if check.status in ("FAIL", "WARN") or check.name in ("ledger chain", "leak scan", "input file"):
            print(f"  [{check.status:<4}] {check.name}: {check.detail}")
    print("  RESULT:", "VERIFIED" if report.ok else "VERIFICATION FAILED")


def run_demo(args) -> int:
    data = Path(args.data_dir) if args.data_dir else (Path("data") if Path("data").is_dir() else Path(__file__).resolve().parents[2] / "data")
    records = data / "customer_records_synthetic.csv"
    cases = data / "redaction_test_cases.csv"
    for needed in (records, cases):
        if not needed.is_file():
            raise OutputError(f"Starter file not found: {needed}")
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise OutputError(f"Output folder is not empty: {out}")
    out.mkdir(parents=True, exist_ok=True)

    policy = Policy.load(args.policy)
    rules = load_rules(args.rules, policy)
    keyring = KeyRing(DEMO_KEY, "demo")
    print("VeilChain demo (synthetic data only; the demo key is PUBLIC and used only for repeatability)")

    _banner("1. Redact the customer records (release level Internal, k-anonymity threshold 2)")
    res1 = run_redaction(RunOptions(str(records), str(out / "01_customers"), keyring, args.policy, args.rules, k_min=2, explain=True))
    print((out / "01_customers" / f"redacted_{records.name}").read_text(encoding="utf-8"))
    print(f"  decisions: {res1.summary['decisions']}   label mismatches: {len(res1.summary['label_mismatches'])}   exit code: {res1.exit_code}")

    _banner("2. Redact the four provided test cases (free text, known names, policy explanations)")
    res2 = run_redaction(RunOptions(str(cases), str(out / "02_testcases"), keyring, args.policy, args.rules,
                                    text_columns=["input_text"], known_names_from=str(records), explain=True))
    print((out / "02_testcases" / f"redacted_{cases.name}").read_text(encoding="utf-8"))
    for line in res2.explain_lines:
        if "RED-03" in line:
            print("  explanation for RED-03:", line)

    _banner("3. Verify the evidence bundles (hashes, ledger chain, seal, leak scan of originals)")
    detectors1 = DetectorSet(rules.record_id_pattern, [])
    _show(verify_bundle(res1.out_dir, keyring, records, True, policy, rules, detectors1))
    detectors2 = DetectorSet(rules.record_id_pattern, _known_names(str(records), "full_name"))
    _show(verify_bundle(res2.out_dir, keyring, cases, True, policy, rules, detectors2))

    _banner("4. Tamper with a copy of the bundle: change one character of the redacted file")
    tampered = out / "03_tamper_changed"
    shutil.copytree(res1.out_dir, tampered)
    target = tampered / f"redacted_{records.name}"
    target.write_text(target.read_text(encoding="utf-8").replace("PERSON#", "PERSOX#", 1), encoding="utf-8", newline="")
    _show(verify_bundle(tampered, keyring, records))

    _banner("5. Tamper with the ledger: edit one decision from 'tokenise' to 'keep'")
    tampered2 = out / "03_tamper_ledger"
    shutil.copytree(res1.out_dir, tampered2)
    ledger = tampered2 / "ledger.jsonl"
    ledger.write_text(ledger.read_text(encoding="utf-8").replace('"action":"tokenise"', '"action":"keep"', 1), encoding="utf-8", newline="")
    _show(verify_bundle(tampered2, keyring, records))

    _banner("6. Missing file, then restore by regenerating from the untouched original")
    broken = out / "03_missing_output"
    shutil.copytree(res1.out_dir, broken)
    (broken / f"redacted_{records.name}").unlink()
    _show(verify_bundle(broken, keyring, records))
    res_again = run_redaction(RunOptions(str(records), str(out / "03_restored"), keyring, args.policy, args.rules, k_min=2, explain=True))
    same = (res_again.summary == res1.summary) and (
        (res_again.out_dir / f"redacted_{records.name}").read_bytes() == (res1.out_dir / f"redacted_{records.name}").read_bytes())
    print(f"  regenerated output is byte-identical to the original run: {'YES' if same else 'NO'}")
    _show(verify_bundle(res_again.out_dir, keyring, records))

    _banner("7. Secrets: Restricted material fails closed")
    secret_dir = out / "04_secrets_work"
    secret_dir.mkdir()
    begin, end = "-----BEGIN " + "FAKE PRIVATE KEY-----", "-----END " + "FAKE PRIVATE KEY-----"
    text = ("deploy log: password=VCFAKE-9f8e7d6c5b4a39\n"
            f"{begin}\nVEILCHAIN-DEMO-NOT-A-REAL-KEY-0123456789\n{end}\n"
            "contact ops at ops.team@example.com\n")
    source = secret_dir / "fake_secrets.txt"
    source.write_text(text, encoding="utf-8")
    res3 = run_redaction(RunOptions(str(source), str(out / "04_secrets"), keyring, args.policy, args.rules, explain=True))
    print((out / "04_secrets" / "redacted_fake_secrets.txt").read_text(encoding="utf-8"))
    print(f"  exit code: {res3.exit_code} (2 means: Restricted material found and removed)   status: {res3.status}")
    print("  ledger fingerprints stored for Restricted entries: none (nothing derived from a secret is kept)")
    shutil.rmtree(secret_dir)  # the fake input is not kept; only the redacted result and evidence remain

    print("\nDemo finished. Outputs are in:", out)
    return 0
