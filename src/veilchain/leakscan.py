"""Leakage scan: prove that original sensitive values do not appear in any output file.

The scanner is given the ORIGINAL sensitive values ("canaries", taken from the input file at
verification time; never stored by VeilChain) and searches every output artefact for each
canary and for common re-encodings of it: lower/upper case, whitespace removed, digits only,
URL-encoded, base64 (standard and URL-safe, with and without padding) and hex.

Canaries are never printed. Findings use an opaque id derived with a throw-away random key.
"""

from __future__ import annotations

import base64
import os
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .classify import classify_cell
from .detectors import DetectorSet
from .hashing import hmac_hex
from .policy import Policy
from .rules import Rules
from .tabular import read_csv_table, read_lines

MIN_CANARY_LEN = 4


@dataclass(frozen=True)
class LeakFinding:
    file: str
    canary_id: str
    variant: str
    count: int


def _variants(value: str) -> list[tuple[str, str, bool]]:
    """(variant name, variant text, case_sensitive) for one canary value."""
    out: list[tuple[str, str, bool]] = [("raw", value, False)]
    squeezed = "".join(value.split())
    if squeezed != value:
        out.append(("whitespace_removed", squeezed, False))
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) >= 8 and digits != value:
        out.append(("digits_only", digits, False))
    quoted = urllib.parse.quote(value, safe="")
    if quoted != value:
        out.append(("url_encoded", quoted, False))
    raw_bytes = value.encode("utf-8")
    b64 = base64.b64encode(raw_bytes).decode("ascii")
    out.append(("base64", b64, True))
    out.append(("base64_no_padding", b64.rstrip("="), True))
    out.append(("base64_urlsafe", base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("="), True))
    out.append(("hex", raw_bytes.hex(), False))
    # Deduplicate while keeping order.
    seen, unique = set(), []
    for name, text, cs in out:
        if text and (text, cs) not in seen:
            seen.add((text, cs))
            unique.append((name, text, cs))
    return unique


def collect_canaries(
    input_path: str | Path,
    policy: Policy,
    rules: Rules,
    detectors: DetectorSet,
    text_columns: frozenset[str] = frozenset(),
    release_level: str = "Internal",
) -> list[str]:
    """Original values that must not appear in outputs: everything above the release level."""
    release_rank = policy.rank(release_level)
    values: set[str] = set()
    path = Path(input_path)

    def consider(cls: str, text: str) -> None:
        text = text.strip()
        if len(text) >= MIN_CANARY_LEN and policy.rank(cls) > release_rank:
            values.add(text)

    if path.suffix.lower() == ".txt":
        lines, _digest, _size = read_lines(path)
        for line in lines:
            for det in detectors.detect(line):
                cls = rules.entity_classes.get(det.entity, rules.unknown_field.cls)
                consider(cls, line[det.start:det.end])
        return sorted(values)

    table = read_csv_table(path)
    for row in table.rows:
        for column in table.fieldnames:
            raw = row.get(column) or ""
            if not raw.strip():
                continue
            cc = classify_cell(policy, rules, detectors, column, raw, text_columns)
            if column.lower() not in text_columns and cc.effective_class != "":
                consider(cc.field_class, raw)  # whole-cell value of a sensitive column
                if policy.rank(cc.effective_class) > policy.rank(cc.field_class):
                    consider(cc.effective_class, raw)
            for det in cc.detections:
                cls = rules.entity_classes.get(det.entity, rules.unknown_field.cls)
                consider(cls, raw[det.start:det.end])
    return sorted(values)


def scan_paths(paths: Iterable[Path], canaries: list[str]) -> tuple[list[LeakFinding], int]:
    """Scan files for canaries. Returns (findings, number_of_canaries_scanned)."""
    session_key = os.urandom(16)  # throw-away: ids are comparable within this scan only
    prepared = []
    for value in canaries:
        cid = "canary#" + hmac_hex(session_key, value)[:8]
        prepared.append((cid, _variants(value)))
    findings: list[LeakFinding] = []
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8", errors="ignore")
        lowered = text.lower()
        for cid, variants in prepared:
            for name, variant, case_sensitive in variants:
                count = text.count(variant) if case_sensitive else lowered.count(variant.lower())
                if count:
                    findings.append(LeakFinding(path.name, cid, name, count))
    return findings, len(prepared)
