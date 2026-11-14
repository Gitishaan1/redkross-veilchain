"""Policy and rules loading: valid files work; broken files fail early with clear errors."""

import json

import pytest

from veilchain.errors import PolicyError, RulesError
from veilchain.policy import Policy
from veilchain.rules import load_rules


def test_provided_policy_loads_with_four_ordered_classes(policy_path):
    policy = Policy.load(policy_path)
    assert policy.names == ["Public", "Internal", "Confidential", "Restricted"]
    assert policy.top.name == "Restricted" and policy.rank("Confidential") > policy.rank("Internal")
    assert "redact before sharing" in policy.cite("Confidential")


def test_missing_policy_file(tmp_path):
    with pytest.raises(PolicyError, match="not found"):
        Policy.load(tmp_path / "nope.json")


def test_malformed_policy_json(tmp_path):
    p = tmp_path / "p.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid JSON"):
        Policy.load(p)


def test_policy_without_classes_or_with_duplicates(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps({"classes": []}), encoding="utf-8")
    with pytest.raises(PolicyError):
        Policy.load(p)
    p.write_text(json.dumps({"classes": [{"name": "A", "handling": "x"}, {"name": "A", "handling": "y"}]}), encoding="utf-8")
    with pytest.raises(PolicyError, match="Duplicate"):
        Policy.load(p)


def test_rules_load_and_unknown_column_is_default_deny(policy_path, rules_path):
    policy = Policy.load(policy_path)
    rules = load_rules(rules_path, policy)
    rule, known = rules.rule_for("some_new_column")
    assert not known and rule.cls == "Confidential"
    assert rules.rule_for("EMAIL")[1] is True  # case-insensitive match


def test_rules_that_name_a_class_missing_from_the_policy_are_rejected(tmp_path, policy_path, rules_path):
    policy = Policy.load(policy_path)
    data = json.loads(open(rules_path, encoding="utf-8").read())
    data["entity_classes"]["EMAIL"] = "Top-Secret"
    p = tmp_path / "r.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(RulesError, match="Top-Secret"):
        load_rules(p, policy)


def test_rules_missing_required_section(tmp_path, policy_path):
    policy = Policy.load(policy_path)
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"field_rules": {}}), encoding="utf-8")
    with pytest.raises(RulesError, match="missing"):
        load_rules(p, policy)
