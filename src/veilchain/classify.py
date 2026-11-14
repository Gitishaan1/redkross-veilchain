"""Classification: decide which policy class each field, cell and record belongs to.

Principles:
  * Field rules say what a column is meant to hold; content detection checks what it actually
    holds. The effective class of a cell is the HIGHER of the two (never silently downgrade).
  * Unknown columns are Confidential by default (default deny).
  * The data owner's asserted label (low/medium/high) is compared with the computed class and
    any disagreement is reported as a finding. It is never trusted blindly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .detectors import DetectorSet, Detection
from .policy import Policy
from .rules import Rules


@dataclass
class CellClassification:
    column: str
    known_column: bool
    field_class: str
    entity: str | None  # whole-cell entity from the field rule (for example EMAIL)
    why: str
    detections: list[Detection] = field(default_factory=list)  # content findings inside the cell
    effective_class: str = ""


def classify_cell(
    policy: Policy,
    rules: Rules,
    detectors: DetectorSet,
    column: str,
    value: str | None,
    text_columns: frozenset[str] = frozenset(),
) -> CellClassification:
    rule, known = rules.rule_for(column)
    text = value or ""
    if column.lower() in text_columns:
        # Free-text column: classified by what it contains, not by its name.
        lowest = policy.names[0]
        result = CellClassification(column, True, lowest, None, "Free-text column: classified by content.")
        result.detections = detectors.detect(text)
        classes = [lowest]
    else:
        result = CellClassification(column, known, rule.cls, rule.entity, rule.why)
        # Every cell is scanned, even in columns declared as one entity: a secret pasted into an
        # "email" or unknown column must still be caught and escalated.
        result.detections = detectors.detect(text)
        classes = [rule.cls] if text.strip() else [policy.names[0]]
    for det in result.detections:
        classes.append(rules.entity_classes.get(det.entity, rules.unknown_field.cls))
    result.effective_class = policy.highest(classes)
    return result


@dataclass
class RecordClassification:
    record_id: str
    computed_class: str
    asserted_label: str | None
    expected_class: str | None
    status: str  # ok | under-classified | over-classified | unlabelled | unknown-label
    drivers: list[str]  # column names that determined the computed class


def classify_record(
    policy: Policy,
    rules: Rules,
    record_id: str,
    cells: list[CellClassification],
    raw_row: dict[str, str | None],
) -> RecordClassification:
    computed = policy.highest([c.effective_class for c in cells] or [policy.names[0]])
    drivers = [c.column for c in cells if c.effective_class == computed]
    label = None
    for column in rules.label_columns:
        for key, val in raw_row.items():
            if key and key.lower() == column:
                label = (val or "").strip()
    if label is None:
        return RecordClassification(record_id, computed, None, None, "unlabelled", drivers)
    expected = rules.label_map.get(label.lower())
    if expected is None:
        return RecordClassification(record_id, computed, label, None, "unknown-label", drivers)
    if policy.rank(computed) > policy.rank(expected):
        status = "under-classified"
    elif policy.rank(computed) < policy.rank(expected):
        status = "over-classified"
    else:
        status = "ok"
    return RecordClassification(record_id, computed, label, expected, status, drivers)
