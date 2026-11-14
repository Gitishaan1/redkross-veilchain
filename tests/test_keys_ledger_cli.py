"""Key handling, ledger mechanics and CLI behaviour."""

import json
import os

import pytest

from veilchain.errors import KeyMaterialError
from veilchain.keys import DEMO_KEY, generate_key_file, load_keyring, parse_key_text
from veilchain.ledger import LedgerWriter, verify_ledger


@pytest.mark.tm("TM-30", "Key handling", "Short key, non-hex key, missing key file, keygen inside a git repository, keygen overwrite", "Each is refused; a good key file loads; keys are never written inside a repo by default")
def test_key_handling(tmp_path, observe):
    refused = []
    for bad in ["abcd", "zz" * 20, ""]:
        with pytest.raises(KeyMaterialError):
            parse_key_text(bad)
        refused.append("bad key text")
    with pytest.raises(KeyMaterialError):
        load_keyring(str(tmp_path / "missing.key"))
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    with pytest.raises(KeyMaterialError, match="git repository"):
        generate_key_file(str(repo / "k.key"))
    outside = tmp_path / "safe" / "k.key"
    generate_key_file(str(outside))
    with pytest.raises(KeyMaterialError, match="overwrite"):
        generate_key_file(str(outside))
    ring = load_keyring(str(outside))
    assert ring.source == "file" and len(ring.master) == 32 and ring.reproducible
    observe(f"{len(refused)} bad keys refused; keygen in repo refused; overwrite refused; good key loads ({ring.key_id})")


def test_key_resolution_order_and_independence(tmp_path, monkeypatch):
    monkeypatch.setenv("VEILCHAIN_KEY", "ab" * 32)
    assert load_keyring().source == "env" and load_keyring(demo=True).source == "demo"
    monkeypatch.delenv("VEILCHAIN_KEY")
    eph = load_keyring()
    assert eph.source == "ephemeral" and not eph.reproducible
    ring = load_keyring(demo=True)
    assert len({ring.token_key, ring.audit_key, ring.seal_key}) == 3  # domain separation
    assert ring.master == DEMO_KEY and len(ring.key_id) == 12


def test_ledger_chain_basics_and_no_overwrite(tmp_path):
    path = tmp_path / "l.jsonl"
    w = LedgerWriter(path, "run1", b"k" * 32)
    for i in range(3):
        w.append("transform", {"i": i})
    w.seal()
    report = verify_ledger(path, b"k" * 32)
    assert report.ok and report.entries == 4 and report.mac_ok
    with pytest.raises(FileExistsError):
        LedgerWriter(path, "run2")
    with pytest.raises(RuntimeError):
        w.append("late", {})


def test_ledger_without_seal_is_flagged(tmp_path):
    path = tmp_path / "l.jsonl"
    w = LedgerWriter(path, "run1")
    w.append("transform", {"i": 1})
    w.close()
    report = verify_ledger(path)
    assert not report.ok and any("no seal" in p for p in report.problems)


def test_cli_classify_flags_mismatches(cli, records):
    code, out, _ = cli("classify", str(records), "--k-min", "2")
    assert code == 0 and out.count("UNDER-CLASSIFIED") == 2 and "REC-003" in out


def test_cli_risk_and_version(cli, records):
    code, out, _ = cli("risk", str(records), "--k-min", "2")
    assert code == 0 and "below threshold" in out
    code, out, _ = cli("--version")
    assert out.startswith("veilchain") or code == 0


def test_cli_redact_exit_codes_and_secret_attention(cli, tmp_path):
    src = tmp_path / "s.txt"
    src.write_text("token=VCFAKE-abcdef123456\n", encoding="utf-8")
    code, out, _ = cli("redact", str(src), "--out", str(tmp_path / "o"), "--demo-key")
    assert code == 2 and "ATTENTION" in out and "rotate" in out
    code, out, err = cli("redact", str(src), "--out", str(tmp_path / "o"), "--demo-key")  # folder now in use
    assert code == 3


def test_cli_leak_scan_needs_input(cli, tmp_path, records):
    code, _out, err = cli("redact", str(records), "--out", str(tmp_path / "o"), "--demo-key")
    code, _out, err = cli("verify", str(tmp_path / "o"), "--demo-key", "--leak-scan")
    assert code == 3 and "--input" in err
