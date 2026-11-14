"""Reading and writing CSV and text files safely.

Inputs are opened read-only. Malformed rows are reported (not silently dropped) and any
unexpected extra cells are kept as extra columns so they are redacted under default-deny
instead of slipping through.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from pathlib import Path

from .errors import InputError
from .hashing import sha256_bytes


@dataclass
class Table:
    fieldnames: list[str]
    rows: list[dict[str, str | None]]
    ragged: list[tuple[int, str]] = field(default_factory=list)  # (data row number, "short"|"long")
    sha256: str = ""
    size: int = 0


def read_bytes(path: str | Path) -> tuple[bytes, str]:
    p = Path(path)
    if not p.is_file():
        raise InputError(f"Input file not found: {path}")
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise InputError(f"Cannot read input file: {exc}") from exc
    return raw, sha256_bytes(raw)


def decode_text(raw: bytes, path: str | Path) -> str:
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputError(f"Input is not valid UTF-8 text: {path} ({exc.reason} at byte {exc.start})") from exc


def read_csv_table(path: str | Path) -> Table:
    raw, digest = read_bytes(path)
    if not raw.strip():
        raise InputError(f"Input file is empty: {path}")
    text = decode_text(raw, path)
    reader = csv.DictReader(io.StringIO(text, newline=""), restkey="_extra", restval=None)
    try:
        header = reader.fieldnames
    except csv.Error as exc:
        raise InputError(f"Could not read CSV header: {exc}") from exc
    if not header:
        raise InputError("CSV has no header row.")
    cleaned = [h.strip() if h else "" for h in header]
    if any(not h for h in cleaned):
        raise InputError("CSV header contains an empty column name.")
    lowered = [h.lower() for h in cleaned]
    if len(set(lowered)) != len(lowered):
        raise InputError("CSV header contains duplicate column names.")
    rows: list[dict[str, str | None]] = []
    ragged: list[tuple[int, str]] = []
    max_extra = 0
    try:
        for number, row in enumerate(reader, start=1):
            extra = row.pop("_extra", None)
            if any(v is None for v in row.values()):
                ragged.append((number, "short"))
            if extra:
                ragged.append((number, "long"))
                max_extra = max(max_extra, len(extra))
                for i, cell in enumerate(extra, start=1):
                    row[f"_extra_{i}"] = cell
            rows.append({c: row.get(h) for c, h in zip(cleaned, header)} | {k: v for k, v in row.items() if k.startswith("_extra_")})
    except csv.Error as exc:
        raise InputError(f"Malformed CSV: {exc}") from exc
    fieldnames = cleaned + [f"_extra_{i}" for i in range(1, max_extra + 1)]
    return Table(fieldnames, rows, ragged, digest, len(raw))


def read_lines(path: str | Path) -> tuple[list[str], str, int]:
    raw, digest = read_bytes(path)
    if not raw.strip():
        raise InputError(f"Input file is empty: {path}")
    text = decode_text(raw, path)
    return text.splitlines(), digest, len(raw)


def write_csv(path: str | Path, fieldnames: list[str], rows: list[dict[str, str | None]]) -> None:
    with open(path, "x", encoding="utf-8", newline="") as handle:  # "x": never overwrite
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\r\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: ("" if v is None else v) for k, v in row.items()})


def write_lines(path: str | Path, lines: list[str]) -> None:
    with open(path, "x", encoding="utf-8", newline="") as handle:
        handle.write("\n".join(lines) + "\n")
