"""Integrity and evidence: unchanged, changed, missing, restored, tampered, forged."""

import base64
import hashlib
import json
import os
import urllib.parse

import pytest

from veilchain.bundle import MANIFEST_NAME, verify_bundle, write_manifest
from veilchain.detectors import DetectorSet
from veilchain.keys import KeyRing
from veilchain.leakscan import collect_canaries, scan_paths
from veilchain.policy import Policy
from veilchain.rules import load_rules

from helpers import POLICY, RULES, copy_bundle, redact

OUT = "redacted_customer_records_synthetic.csv"


@pytest.fixture
def bundle(tmp_path, records, demo_keyring):
    return redact(records, tmp_path / "run", demo_keyring, explain=True, k_min=2).out_dir


def statuses(report):
    return {c.name: c.status for c in report.checks}


@pytest.mark.tm("TM-19", "Integrity", "Unchanged bundle and untouched original", "Every check passes (exit code 0)")
def test_unchanged_bundle_verifies(bundle, records, demo_keyring, cli, observe):
    code, out, _ = cli("verify", str(bundle), "--demo-key", "--input", str(records), "--leak-scan")
    assert code == 0 and "VERIFIED" in out
    report = verify_bundle(bundle, demo_keyring, records)
    observe(f"exit code {code}; checks: {len(report.checks)}; failures: 0")


@pytest.mark.tm("TM-20", "Integrity", "One character changed in the redacted output", "Verification fails, naming the changed file (exit code 1)")
def test_changed_output_is_detected(bundle, tmp_path, demo_keyring, records, cli, observe):
    bad = copy_bundle(bundle, tmp_path / "bad")
    f = bad / OUT
    f.write_text(f.read_text(encoding="utf-8").replace("PERSON#", "PERSOX#", 1), encoding="utf-8", newline="")
    code, out, _ = cli("verify", str(bad), "--demo-key")
    assert code == 1 and "CHANGED" in out
    observe(f"exit code {code}: {[l.strip() for l in out.splitlines() if 'CHANGED' in l][0][:80]}")


@pytest.mark.tm("TM-21", "Integrity", "A listed output file is deleted", "Verification fails with MISSING (exit code 1)")
def test_missing_output_is_detected(bundle, tmp_path, cli, observe):
    bad = copy_bundle(bundle, tmp_path / "gone")
    (bad / OUT).unlink()
    code, out, _ = cli("verify", str(bad), "--demo-key")
    assert code == 1 and "MISSING" in out
    observe(f"exit code {code}; MISSING reported")


@pytest.mark.tm("TM-22", "Resilience", "Restore: output deleted, then regenerated from the untouched original with the same key", "Regenerated output is byte-identical and the new bundle verifies")
def test_successful_restore(tmp_path, records, demo_keyring, bundle, cli, observe):
    first_hash = hashlib.sha256((bundle / OUT).read_bytes()).hexdigest()
    redo = redact(records, tmp_path / "redo", demo_keyring, explain=True, k_min=2)
    assert hashlib.sha256((redo.out_dir / OUT).read_bytes()).hexdigest() == first_hash
    code, out, _ = cli("verify", str(redo.out_dir), "--demo-key", "--input", str(records))
    assert code == 0
    observe(f"identical sha256 {first_hash[:16]}...; verify exit code {code}")


@pytest.mark.tm("TM-23", "Integrity", "Failed verification: a decision in the ledger is edited from tokenise to keep", "Chain check fails and names the modified entry (exit code 1)")
def test_ledger_edit_detected(bundle, tmp_path, cli, observe):
    bad = copy_bundle(bundle, tmp_path / "led")
    p = bad / "ledger.jsonl"
    p.write_text(p.read_text(encoding="utf-8").replace('"action":"tokenise"', '"action":"keep"', 1), encoding="utf-8")
    code, out, _ = cli("verify", str(bad), "--demo-key")
    assert code == 1 and "was modified" in out
    observe(f"exit code {code}: {[l.strip() for l in out.splitlines() if 'ledger chain' in l][0][:110]}")


@pytest.mark.tm("TM-24", "Integrity", "Ledger: entry deleted, two entries swapped, tail cut off, file deleted", "Each is detected")
def test_other_ledger_attacks(bundle, tmp_path, observe):
    results = {}
    lines = (bundle / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    variants = {
        "delete": lines[:10] + lines[11:], "swap": lines[:7] + [lines[8], lines[7]] + lines[9:], "truncate": lines[:-6],
    }
    for name, new in variants.items():
        d = copy_bundle(bundle, tmp_path / name)
        (d / "ledger.jsonl").write_text("\n".join(new) + "\n", encoding="utf-8")
        results[name] = not verify_bundle(d, None).ok
    d = copy_bundle(bundle, tmp_path / "rm")
    (d / "ledger.jsonl").unlink()
    results["file deleted"] = not verify_bundle(d, None).ok
    assert all(results.values())
    observe(f"detected: {results}")


@pytest.mark.tm("TM-25", "Integrity", "Seal MAC with the right key, the wrong key and no key", "Right key: authenticated; wrong key: FAIL; no key: chain consistent but flagged as not authenticated")
def test_seal_mac(tmp_path, records, observe):
    real = KeyRing(os.urandom(32), "file")
    out = redact(records, tmp_path / "o", real).out_dir
    good = statuses(verify_bundle(out, real))
    wrong = statuses(verify_bundle(out, KeyRing(os.urandom(32), "file")))
    none = statuses(verify_bundle(out, None))
    assert good["ledger seal MAC"] == "PASS" and wrong["ledger seal MAC"] == "FAIL" and none["ledger seal MAC"] == "INFO"
    observe(f"right key {good['ledger seal MAC']}, wrong key {wrong['ledger seal MAC']}, no key {none['ledger seal MAC']}")


@pytest.mark.tm("TM-26", "Integrity", "Original input changed after the run", "verify --input fails: the original no longer matches the hash recorded at intake")
def test_input_changed_after_run(bundle, tmp_path, records, demo_keyring, observe):
    changed = tmp_path / "changed.csv"
    changed.write_bytes(records.read_bytes() + b"REC-007,New Person,new@example.com,+353-00-000-0007,Support,low\r\n")
    report = verify_bundle(bundle, demo_keyring, changed)
    assert statuses(report)["input file"] == "FAIL" and not report.ok
    observe("input file check: FAIL (hash differs from intake)")


@pytest.mark.tm("TM-27", "Integrity", "Manifest edited without updating manifest.sha256, and manifest.sha256 removed", "First: FAIL; second: WARN (the manifest itself cannot be checked)")
def test_manifest_tampering(bundle, tmp_path, observe):
    d = copy_bundle(bundle, tmp_path / "m1")
    m = d / MANIFEST_NAME
    m.write_text(m.read_text(encoding="utf-8").replace('"status": "COMPLETE"', '"status": "FINE"'), encoding="utf-8")
    s1 = statuses(verify_bundle(d, None))["manifest hash"]
    d2 = copy_bundle(bundle, tmp_path / "m2")
    (d2 / "manifest.sha256").unlink()
    s2 = statuses(verify_bundle(d2, None))["manifest hash"]
    assert s1 == "FAIL" and s2 == "WARN"
    observe(f"edited manifest: {s1}; missing manifest.sha256: {s2}")


@pytest.mark.tm("TM-28", "Retest after fix", "Output edited AND manifest updated to match (gap found by red-team RT-6g)", "Caught by the cross-check against the hash recorded inside the ledger")
def test_consistent_manifest_forgery_is_caught(bundle, tmp_path, observe):
    d = copy_bundle(bundle, tmp_path / "forged")
    with open(d / OUT, "a", encoding="utf-8") as h:
        h.write("REC-999,X,Y,Z,Support,low\r\n")
    manifest = json.loads((d / MANIFEST_NAME).read_text(encoding="utf-8"))
    manifest["files"][OUT] = {"sha256": hashlib.sha256((d / OUT).read_bytes()).hexdigest(), "bytes": (d / OUT).stat().st_size}
    write_manifest(d, manifest)
    report = verify_bundle(d, None)
    st = statuses(report)
    assert not report.ok and st["ledger vs outputs"] == "FAIL" and st["manifest hash"] == "PASS"
    observe("manifest hash PASS (forged consistently) but ledger vs outputs FAIL")


@pytest.mark.tm("TM-29", "Privacy of evidence", "Leak scan: clean bundle, then originals planted in several encodings", "Clean bundle passes; plain, base64, hex, URL-encoded and digits-only plants are all found")
def test_leak_scan_finds_encoded_originals(bundle, tmp_path, records, demo_keyring, observe):
    policy = Policy.load(POLICY)
    rules = load_rules(RULES, policy)
    det = DetectorSet(rules.record_id_pattern, [])
    canaries = collect_canaries(records, policy, rules, det)
    clean, scanned = scan_paths([p for p in bundle.iterdir() if p.is_file()], canaries)
    assert not clean and scanned >= 10
    found_variants = set()
    for label, encode in {"raw": lambda v: v, "base64": lambda v: base64.b64encode(v.encode()).decode(), "hex": lambda v: v.encode().hex(),
                          "url_encoded": lambda v: urllib.parse.quote(v, safe=""), "digits_only": lambda v: "".join(c for c in v if c.isdigit())}.items():
        d = copy_bundle(bundle, tmp_path / f"plant_{label}")
        phone = "+353-00-000-0001" if label == "digits_only" else "maya.example@example.com"
        (d / "extra.txt").write_text("note " + encode(phone) + "\n", encoding="utf-8")
        hits, _ = scan_paths([p for p in d.iterdir() if p.is_file()], canaries)
        assert hits, label
        found_variants |= {h.variant for h in hits}
    observe(f"clean: 0 leaks across {scanned} canaries; planted variants found: {sorted(found_variants)}")


def test_unlisted_file_is_a_warning(bundle, tmp_path):
    d = copy_bundle(bundle, tmp_path / "extra")
    (d / "surprise.txt").write_text("hello", encoding="utf-8")
    assert statuses(verify_bundle(d, None))["file surprise.txt"] == "WARN"


def test_demo_key_and_restricted_are_flagged(tmp_path, demo_keyring):
    src = tmp_path / "s.txt"
    src.write_text("password=VCFAKE-abcdef123456\n", encoding="utf-8")
    d = redact(src, tmp_path / "o", demo_keyring).out_dir
    st = statuses(verify_bundle(d, demo_keyring))
    assert st["key source"] == "WARN" and st["restricted material"] == "WARN"
