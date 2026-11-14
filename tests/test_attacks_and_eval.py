"""The red-team suite and the detector evaluation, run as tests so regressions are caught."""

import pytest

from veilchain.evaluate import build_detectors, evaluate
from veilchain.policy import Policy
from veilchain.redteam import run_redteam
from veilchain.rules import load_rules
from veilchain.synth import generate_corpus, person_name

from helpers import POLICY, RULES


@pytest.fixture(scope="module")
def results():
    return {r.id: r for r in run_redteam(POLICY, RULES)}


@pytest.mark.tm("TM-31", "Retest after fix", "Brute-force reversal of tokens: v0 unkeyed hashes versus v1 keyed HMAC (red-team RT-1)", "v0 is broken (all numbers recovered); v1 resists an attacker without the key")
def test_rt1_unkeyed_broken_hmac_defended(results, observe):
    r = results["RT-1"]
    assert r.outcome == "DEFENDED" and "BROKEN (50/50 recovered)" in r.summary and "With a stolen key: 50/50" in r.summary
    observe(r.summary)


@pytest.mark.tm("TM-32", "Attack", "Leak scan against the real output, plus scanner self-test (RT-2)", "No leaks; the scanner catches a planted base64 original")
def test_rt2(results, observe):
    r = results["RT-2"]
    assert r.outcome == "DEFENDED"
    observe(r.summary)


@pytest.mark.tm("TM-33", "Attack", "Secrets stored anywhere? 7 derivations of each secret searched in every output (RT-5)", "Nothing derived from a Restricted value is stored; exit code 2")
def test_rt5(results, observe):
    r = results["RT-5"]
    assert r.outcome == "DEFENDED" and "exit code 2" in r.summary
    observe(r.summary)


@pytest.mark.tm("TM-34", "Attack", "Eight ledger and evidence tampering attacks (RT-6)", "All detected with the key; only a full consistent rewrite goes unnoticed without the key (documented limit)")
def test_rt6(results, observe):
    r = results["RT-6"]
    assert r.outcome == "PARTIAL" and "with the key" in r.summary and "Undetected without key: h" in r.summary
    assert "8/8 with the key" in r.summary
    observe(r.summary)


def test_rt3_rt4_rt7(results):
    assert results["RT-3"].outcome == "DEFENDED"
    assert results["RT-4"].outcome == "PARTIAL" and "12/12 designed-for evasions caught" in results["RT-4"].summary
    assert results["RT-7"].outcome == "DEFENDED"


@pytest.mark.tm("TM-35", "Detection quality", "Precision and recall on 400 labelled synthetic lines (seed 1337)", "Standard PII found with recall 1.00; known false positives and misses are measured, not hidden")
def test_detector_quality(observe):
    policy = Policy.load(POLICY)
    rules = load_rules(RULES, policy)
    known = [person_name(i) for i in range(10)]
    result = evaluate(generate_corpus(400, 1337, known), build_detectors(rules, known))
    rows = {(r["group"], r["entity"]): r for r in result["rows"]}
    for entity in ("EMAIL", "CARD", "PERSON", "SECRET", "RECORD_ID", "PHONE"):
        assert rows[("standard", entity)]["recall"] == 1.0
    assert rows[("standard", "CARD")]["precision"] == 1.0 and rows[("standard", "EMAIL")]["precision"] == 1.0
    assert rows[("standard", "PHONE")]["fp"] > 0  # honest: a part number shaped like a phone number is flagged
    assert rows[("unknown name", "PERSON")]["recall"] == 0.0  # honest: unknown names cannot be found
    observe(f"PHONE precision {rows[('standard', 'PHONE')]['precision']:.2f} (FP {rows[('standard', 'PHONE')]['fp']}); EMAIL evasion recall {rows[('evasion', 'EMAIL')]['recall']:.2f}; unknown-name recall 0.00")
