"""Re-identification risk: a simple k-anonymity check over quasi-identifiers.

Removing names is not enough if a combination of harmless-looking fields (for example
department + sensitivity label) is unique to one person. A group of size 1 means that anyone
who knows those two facts about a person can pick out their row.

This is a SIMPLE check, not formal de-identification (see NIST SP 800-188, which discusses
k-anonymity, quasi-identifiers and re-identification studies, and cautions that tools that
merely mask values do not by themselves provide de-identification).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .rules import Rules
from .tabular import Table


@dataclass
class RiskReport:
    quasi_identifiers: list[str]
    k: int  # smallest group size (0 if there are no quasi-identifiers)
    k_min: int
    groups: list[tuple[int, list[str]]] = field(default_factory=list)  # (size, record ids)
    at_risk_records: list[str] = field(default_factory=list)

    @property
    def passes(self) -> bool:
        return not self.at_risk_records


def record_id_for(row: dict, index: int) -> str:
    lowered = {k.lower(): v for k, v in row.items() if k}
    for key in ("record_id", "case_id", "id"):
        if lowered.get(key):
            return str(lowered[key]).strip()
    return f"row-{index}"


def k_anonymity(table: Table, rules: Rules, k_min: int) -> RiskReport:
    columns = [c for c in table.fieldnames if c.lower() in rules.quasi_identifiers]
    if not columns:
        return RiskReport([], 0, k_min)
    buckets: dict[tuple, list[str]] = defaultdict(list)
    for index, row in enumerate(table.rows, start=1):
        key = tuple((row.get(c) or "").strip().lower() for c in columns)
        buckets[key].append(record_id_for(row, index))
    groups = sorted(((len(ids), ids) for ids in buckets.values()), key=lambda g: (g[0], g[1]))
    smallest = groups[0][0] if groups else 0
    at_risk = [rid for size, ids in groups if size < k_min for rid in ids]
    return RiskReport(columns, smallest, k_min, groups, at_risk)
