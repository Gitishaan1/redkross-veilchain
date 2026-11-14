"""Load the VeilChain rules and check them against the policy (fail early, fail clearly)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .errors import RulesError
from .hashing import sha256_bytes
from .policy import Policy


@dataclass(frozen=True)
class FieldRule:
    name: str
    cls: str
    entity: str | None
    why: str
    quasi_identifier: bool
    asserted_label: bool


@dataclass
class Rules:
    field_rules: dict[str, FieldRule]
    unknown_field: FieldRule
    entity_classes: dict[str, str]
    entity_why: dict[str, str]
    record_id_pattern: re.Pattern
    label_map: dict[str, str]
    never_store_class: str
    defaults: dict
    sha256: str
    path: str
    extra: dict = field(default_factory=dict)

    def rule_for(self, column: str) -> tuple[FieldRule, bool]:
        """Return (rule, known). Column names are matched case-insensitively."""
        key = column.strip().lower()
        if key in self.field_rules:
            return self.field_rules[key], True
        return self.unknown_field, False

    @property
    def quasi_identifiers(self) -> list[str]:
        return [n for n, r in self.field_rules.items() if r.quasi_identifier]

    @property
    def label_columns(self) -> list[str]:
        return [n for n, r in self.field_rules.items() if r.asserted_label]


def _field_rule(name: str, raw: dict) -> FieldRule:
    if "class" not in raw:
        raise RulesError(f'Field rule "{name}" is missing "class".')
    return FieldRule(
        name=name,
        cls=str(raw["class"]),
        entity=raw.get("entity"),
        why=str(raw.get("why", "")),
        quasi_identifier=bool(raw.get("quasi_identifier", False)),
        asserted_label=bool(raw.get("asserted_label", False)),
    )


def load_rules(path: str | Path, policy: Policy) -> Rules:
    p = Path(path)
    if not p.is_file():
        raise RulesError(f"Rules file not found: {path}")
    raw = p.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RulesError(f"Rules file is not valid JSON: {exc}") from exc
    for required in ("field_rules", "unknown_field", "entity_classes", "label_map", "never_store_class"):
        if required not in data:
            raise RulesError(f'Rules file is missing "{required}".')

    field_rules = {str(k).lower(): _field_rule(str(k).lower(), v) for k, v in data["field_rules"].items()}
    unknown = _field_rule("<unknown>", data["unknown_field"])
    entity_classes = {str(k): str(v) for k, v in data["entity_classes"].items()}
    label_map = {str(k).lower(): str(v) for k, v in data["label_map"].items()}
    never_store = str(data["never_store_class"])

    # Consistency: every class named in the rules must exist in the policy.
    referenced = (
        [r.cls for r in field_rules.values()] + [unknown.cls] + list(entity_classes.values())
        + list(label_map.values()) + [never_store]
    )
    for cls in referenced:
        if not policy.has(cls):
            raise RulesError(f'Rules refer to class "{cls}", which is not defined in the policy ({", ".join(policy.names)}).')

    try:
        pattern = re.compile(data.get("record_id_pattern", r"\bREC-\d{3,}\b"))
    except re.error as exc:
        raise RulesError(f"Invalid record_id_pattern: {exc}") from exc

    return Rules(
        field_rules=field_rules,
        unknown_field=unknown,
        entity_classes=entity_classes,
        entity_why={str(k): str(v) for k, v in data.get("entity_why", {}).items()},
        record_id_pattern=pattern,
        label_map=label_map,
        never_store_class=never_store,
        defaults=dict(data.get("defaults", {})),
        sha256=sha256_bytes(raw),
        path=str(p),
    )
