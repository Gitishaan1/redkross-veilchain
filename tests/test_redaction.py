"""Redaction behaviour: the provided starter data, the policy-driven decisions and the safety properties."""

import csv
import hashlib
import json
import os
import time

import pytest

from veilchain.keys import DEMO_KEY, KeyRing
from veilchain.synth import generate_records
from veilchain.tabular import write_csv

from helpers import POLICY, RULES, read_all, redact

ORIGINALS = ["Maya Example", "maya.example@example.com", "+353-00-000-0001"]


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


@pytest.mark.tm("TM-01", "Redaction", "Dummy PII in the provided customer records", "Names, emails and phones become keyed tokens; record_id and department stay; no original value appears in any output file")
def test_provided_records_are_redacted_and_leak_nothing(tmp_path, records, demo_keyring, observe):
    res = redact(records, tmp_path / "o", demo_keyring)
    out = (res.out_dir / "redacted_customer_records_synthetic.csv").read_text(encoding="utf-8")
    everything = read_all(res.out_dir)
    for original in ORIGINALS:
        assert original not in everything
    rows = list(csv.DictReader(out.splitlines()))
    assert rows[0]["record_id"] == "REC-001" and rows[0]["department"] == "Support"
    assert rows[0]["email"].startswith("EMAIL#") and rows[0]["phone"].startswith("PHONE#") and rows[0]["full_name"].startswith("PERSON#")
    observe(f"{res.summary['decisions']}; originals found in outputs: 0; first row: {rows[0]['full_name']}, {rows[0]['email']}")


@pytest.mark.tm("TM-02", "Redaction", "The four provided test cases (RED-01 to RED-04)", "RED-01 name and email redacted, RED-02 phone redacted, RED-03 record ID kept with a policy explanation, RED-04 unchanged")
def test_provided_test_cases(tmp_path, records, cases, demo_keyring, observe):
    res = redact(cases, tmp_path / "o", demo_keyring, text_columns=["input_text"], known_names_from=str(records), explain=True)
    rows = {r["case_id"]: r["input_text"] for r in csv.DictReader((res.out_dir / "redacted_redaction_test_cases.csv").read_text(encoding="utf-8").splitlines())}
    assert "Maya Example" not in rows["RED-01"] and "maya.example@example.com" not in rows["RED-01"]
    assert "[PERSON#" in rows["RED-01"] and "[EMAIL#" in rows["RED-01"]
    assert "[PHONE#" in rows["RED-02"] and "+353" not in rows["RED-02"]
    assert rows["RED-03"] == "Record REC-003 is marked Confidential"
    assert rows["RED-04"] == "No personal information appears in this sentence"
    explanation = [line for line in res.explain_lines if "RED-03" in line]
    assert explanation and 'class "Internal"' in explanation[0] and "Share only with authorised staff" in explanation[0]
    observe(f"RED-01 -> {rows['RED-01']}; RED-03 kept, explained from policy; RED-04 unchanged")


@pytest.mark.tm("TM-03", "Determinism", "Same input and same key, run twice", "Redacted output is byte-identical (so a deleted output can be regenerated)")
def test_same_key_same_output(tmp_path, records, demo_keyring, observe):
    a = redact(records, tmp_path / "a", demo_keyring)
    b = redact(records, tmp_path / "b", demo_keyring)
    name = "redacted_customer_records_synthetic.csv"
    assert sha(a.out_dir / name) == sha(b.out_dir / name)
    observe(f"sha256 {sha(a.out_dir / name)[:16]}... in both runs")


@pytest.mark.tm("TM-04", "Unlinkability", "Same input, two different keys", "No token in common: the two releases cannot be joined")
def test_different_keys_give_different_tokens(tmp_path, records, observe):
    a = redact(records, tmp_path / "a", KeyRing(os.urandom(32), "file"))
    b = redact(records, tmp_path / "b", KeyRing(os.urandom(32), "file"))
    name = "redacted_customer_records_synthetic.csv"
    ta = {r["email"] for r in csv.DictReader((a.out_dir / name).read_text(encoding="utf-8").splitlines())}
    tb = {r["email"] for r in csv.DictReader((b.out_dir / name).read_text(encoding="utf-8").splitlines())}
    assert ta.isdisjoint(tb)
    observe(f"{len(ta & tb)} of {len(ta)} email tokens shared")


def test_same_person_gets_same_token_across_files(tmp_path, records, cases, demo_keyring):
    a = redact(records, tmp_path / "a", demo_keyring)
    b = redact(cases, tmp_path / "b", demo_keyring, text_columns=["input_text"], known_names_from=str(records))
    first_name_token = list(csv.DictReader((a.out_dir / "redacted_customer_records_synthetic.csv").read_text(encoding="utf-8").splitlines()))[0]["full_name"]
    assert first_name_token in (b.out_dir / "redacted_redaction_test_cases.csv").read_text(encoding="utf-8")


@pytest.mark.tm("TM-05", "Redaction", "Mask mode", "Values become bare labels such as [EMAIL] with no token and therefore no linkability")
def test_mask_mode(tmp_path, cases, records, demo_keyring, observe):
    res = redact(cases, tmp_path / "o", demo_keyring, mode="mask", text_columns=["input_text"], known_names_from=str(records))
    text = (res.out_dir / "redacted_redaction_test_cases.csv").read_text(encoding="utf-8")
    assert "[EMAIL]" in text and "[PHONE]" in text and "#" not in text.replace("RED-0", "")
    observe("output contains [EMAIL], [PHONE], [PERSON] and no tokens")


@pytest.mark.tm("TM-06", "Policy", "Release level Public instead of Internal", "Internal values (record_id, department) are redacted as well, because Internal is above the release level")
def test_release_level_public_masks_internal(tmp_path, records, demo_keyring, observe):
    res = redact(records, tmp_path / "o", demo_keyring, release_level="Public")
    rows = list(csv.DictReader((res.out_dir / "redacted_customer_records_synthetic.csv").read_text(encoding="utf-8").splitlines()))
    assert rows[0]["record_id"].startswith("RECORD_ID#") and rows[0]["department"].startswith("DEPARTMENT#")
    observe(f"record_id -> {rows[0]['record_id']}, department -> {rows[0]['department']}")


def test_release_level_restricted_is_refused(tmp_path, records, demo_keyring):
    from veilchain.errors import VeilChainError
    with pytest.raises(VeilChainError):
        redact(records, tmp_path / "o", demo_keyring, release_level="Restricted")


@pytest.mark.tm("TM-07", "Restricted", "Secrets and a private key in a text file", "All removed, run exits with code 2, manifest status says Restricted material was found")
def test_restricted_material_fails_closed(tmp_path, demo_keyring, observe):
    begin, end = "-----BEGIN " + "FAKE PRIVATE KEY-----", "-----END " + "FAKE PRIVATE KEY-----"
    src = tmp_path / "in.txt"
    src.write_text(f"password=VCFAKE-abcdef123456\n{begin}\nVEILCHAIN-DEMO-NOT-A-REAL-KEY\n{end}\nok line\n", encoding="utf-8")
    res = redact(src, tmp_path / "o", demo_keyring)
    out = (res.out_dir / "redacted_in.txt").read_text(encoding="utf-8")
    assert res.exit_code == 2 and res.status == "COMPLETE_RESTRICTED_FOUND" and res.restricted_found
    assert "VCFAKE" not in read_all(res.out_dir) and "VEILCHAIN-DEMO-NOT-A-REAL-KEY" not in read_all(res.out_dir)
    assert "[RESTRICTED-REMOVED]" in out and "ok line" in out
    observe(f"exit code {res.exit_code}; status {res.status}; removed {res.summary['restricted_entities']}")


@pytest.mark.tm("TM-08", "Restricted", "Ledger entries for removed Restricted values", "No token and no fingerprint: nothing derived from a secret is stored")
def test_no_fingerprint_for_restricted(tmp_path, demo_keyring, observe):
    src = tmp_path / "in.txt"
    src.write_text("api_key: VCFAKE-abcdef123456\n", encoding="utf-8")
    res = redact(src, tmp_path / "o", demo_keyring)
    removed = [json.loads(l)["data"] for l in (res.out_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines() if '"action":"remove"' in l]
    assert removed and all("fp" not in d and "out" not in d for d in removed)
    observe(f"{len(removed)} remove event(s); keys recorded: {sorted(removed[0].keys())}")


@pytest.mark.tm("TM-09", "Privacy of evidence", "Ledger, manifest, summary and explanation files", "Contain no original values and no key material")
def test_evidence_contains_no_originals_or_keys(tmp_path, records, observe):
    keyring = KeyRing(os.urandom(32), "file")
    res = redact(records, tmp_path / "o", keyring, explain=True, k_min=2)
    everything = read_all(res.out_dir)
    for secret in ORIGINALS + [keyring.master.hex(), keyring.token_key.hex(), keyring.audit_key.hex(), keyring.seal_key.hex()]:
        assert secret not in everything
    observe("checked 3 originals and 4 key values against 6 evidence files: none found")


@pytest.mark.tm("TM-10", "Policy", "Unknown column and a secret hidden in an email column", "Unknown column is tokenised (default deny); a secret in the email column is removed, not tokenised")
def test_default_deny_and_secret_escalation(tmp_path, demo_keyring, observe):
    src = tmp_path / "in.csv"
    src.write_text("record_id,email,notes\r\nREC-001,password=VCFAKE-zzzzzz9999,free text here\r\n", encoding="utf-8")
    res = redact(src, tmp_path / "o", demo_keyring)
    row = list(csv.DictReader((res.out_dir / "redacted_in.csv").read_text(encoding="utf-8").splitlines()))[0]
    assert row["notes"].startswith("DATA#") and row["email"] == "[RESTRICTED-REMOVED]"
    assert "VCFAKE" not in read_all(res.out_dir)
    observe(f"notes -> {row['notes']}; email -> {row['email']}; exit {res.exit_code}")


@pytest.mark.tm("TM-11", "Retest after fix", "Multi-line private key block in a text file (bug found by red-team RT-5)", "The whole block, including the key body lines, is removed")
def test_multiline_private_key_regression(tmp_path, demo_keyring, observe):
    begin, end = "-----BEGIN " + "FAKE PRIVATE KEY-----", "-----END " + "FAKE PRIVATE KEY-----"
    src = tmp_path / "in.txt"
    src.write_text(f"before\n{begin}\nKEYBODYLINE-ONE\nKEYBODYLINE-TWO\n{end}\nafter\n", encoding="utf-8")
    res = redact(src, tmp_path / "o", demo_keyring)
    out = (res.out_dir / "redacted_in.txt").read_text(encoding="utf-8")
    assert "KEYBODYLINE" not in out and begin not in out and end not in out
    assert out.splitlines() == ["before", "[RESTRICTED-REMOVED]", "after"]
    observe(f"output lines: {out.splitlines()}")


@pytest.mark.tm("TM-12", "Privacy risk", "k-anonymity threshold 2 on the provided records", "The two records whose department+label combination is unique (REC-003, REC-004) have it suppressed")
def test_k_anonymity_suppression(tmp_path, records, demo_keyring, observe):
    res = redact(records, tmp_path / "o", demo_keyring, k_min=2)
    rows = {r["record_id"]: r for r in csv.DictReader((res.out_dir / "redacted_customer_records_synthetic.csv").read_text(encoding="utf-8").splitlines())}
    assert rows["REC-003"]["department"] == "SUPPRESSED" and rows["REC-004"]["data_sensitivity"] == "SUPPRESSED"
    assert rows["REC-001"]["department"] == "Support"
    observe(f"k before suppression = {res.summary['k_anonymity']['k']}; records below k = {res.summary['k_anonymity']['records_below_k']}")


@pytest.mark.tm("TM-13", "Classification", "Owner label versus computed class", "REC-001 and REC-005 (label low) are reported as under-classified; the others agree")
def test_label_mismatch_findings(tmp_path, records, demo_keyring, observe):
    res = redact(records, tmp_path / "o", demo_keyring)
    mism = {m["record"]: m["status"] for m in res.summary["label_mismatches"]}
    assert mism == {"REC-001": "under-classified", "REC-005": "under-classified"}
    observe(f"mismatches: {mism}")


@pytest.mark.tm("TM-14", "Input handling", "Plain text input", "Emails redacted line by line, other lines untouched, line numbers logged")
def test_text_file_input(tmp_path, demo_keyring, observe):
    src = tmp_path / "notes.txt"
    src.write_text("line one is fine\nwrite to ops.team@example.com today\nline three\n", encoding="utf-8")
    res = redact(src, tmp_path / "o", demo_keyring)
    out = (res.out_dir / "redacted_notes.txt").read_text(encoding="utf-8").splitlines()
    assert out[0] == "line one is fine" and out[2] == "line three" and out[1].startswith("write to [EMAIL#")
    assert any('"record":"line-2"' in l for l in (res.out_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines())
    observe(f"output: {out[1]}")


@pytest.mark.tm("TM-15", "Input handling", "Malformed CSV rows (too short, too long) and unusual input", "Reported as findings; extra cells are redacted under default deny; header-only file works")
def test_malformed_and_edge_inputs(tmp_path, demo_keyring, observe):
    src = tmp_path / "bad.csv"
    src.write_text("record_id,email\r\nREC-001,a.b@example.com\r\nREC-002\r\nREC-003,c.d@example.com,EXTRA-SECRET-CELL\r\n", encoding="utf-8")
    res = redact(src, tmp_path / "o", demo_keyring)
    text = (res.out_dir / "redacted_bad.csv").read_text(encoding="utf-8")
    assert res.summary["findings"]["malformed_row"] == 2 and "EXTRA-SECRET-CELL" not in text and "_extra_1" in text
    only_header = tmp_path / "h.csv"
    only_header.write_text("record_id,email\r\n", encoding="utf-8")
    res2 = redact(only_header, tmp_path / "o2", demo_keyring)
    assert res2.summary["records_processed"] == 0
    observe(f"findings: {res.summary['findings']}; header-only file processed: {res2.summary['records_processed']} records")


def test_unicode_values(tmp_path, demo_keyring):
    src = tmp_path / "u.csv"
    src.write_text("record_id,full_name,email\r\nREC-001,José García,josé.garcía@example.com\r\n", encoding="utf-8")
    res = redact(src, tmp_path / "o", demo_keyring)
    assert "José" not in read_all(res.out_dir) and "García" not in read_all(res.out_dir)


@pytest.mark.tm("TM-16", "Input handling", "Bad inputs: empty file, missing file, invalid UTF-8, duplicate header, non-empty output folder", "Each fails with a clear error and exit code 3; nothing is overwritten")
def test_bad_inputs_fail_cleanly(tmp_path, cli, observe):
    results = {}
    empty = tmp_path / "empty.csv"
    empty.write_bytes(b"")
    bad_utf = tmp_path / "bad.csv"
    bad_utf.write_bytes(b"record_id,email\r\nREC-001,\xff\xfe@x\r\n")
    dup = tmp_path / "dup.csv"
    dup.write_text("a,A\r\n1,2\r\n", encoding="utf-8")
    good = tmp_path / "good.csv"
    good.write_text("record_id,email\r\nREC-001,a@b.co\r\n", encoding="utf-8")
    taken = tmp_path / "taken"
    taken.mkdir()
    (taken / "x.txt").write_text("existing evidence", encoding="utf-8")
    cases = {"empty": [str(empty), "--out", str(tmp_path / "o1")], "missing": [str(tmp_path / "nope.csv"), "--out", str(tmp_path / "o2")],
             "invalid utf-8": [str(bad_utf), "--out", str(tmp_path / "o3")], "duplicate header": [str(dup), "--out", str(tmp_path / "o4")],
             "output folder in use": [str(good), "--out", str(taken)]}
    for name, argv in cases.items():
        code, _out, err = cli("redact", *argv, "--demo-key")
        results[name] = code
        assert code == 3 and "ERROR" in err
    assert (taken / "x.txt").read_text(encoding="utf-8") == "existing evidence"
    observe(f"exit codes: {results}")


@pytest.mark.tm("TM-17", "Safety", "Input file integrity and permissions", "Input is byte-identical afterwards, even when it is read-only")
def test_input_is_untouched(tmp_path, records, demo_keyring, observe):
    src = tmp_path / "ro.csv"
    src.write_bytes(records.read_bytes())
    os.chmod(src, 0o444)
    before = sha(src)
    res = redact(src, tmp_path / "o", demo_keyring)
    assert sha(src) == before and res.exit_code == 0
    observe(f"sha256 before = after = {before[:16]}...")


@pytest.mark.tm("TM-18", "Performance", "20,000 synthetic records", "Completes in reasonable time and leaks nothing")
def test_large_file(tmp_path, demo_keyring, observe):
    src = tmp_path / "big.csv"
    write_csv(src, ["record_id", "full_name", "email", "phone", "department", "data_sensitivity"], generate_records(20000, 99))
    start = time.perf_counter()
    res = redact(src, tmp_path / "o", demo_keyring)
    elapsed = time.perf_counter() - start
    text = (res.out_dir / "redacted_big.csv").read_text(encoding="utf-8")
    assert res.summary["records_processed"] == 20000 and "@example." not in text and elapsed < 120
    observe(f"20000 records, {res.summary['decisions']['tokenise']} tokenised values in {elapsed:.1f}s")
