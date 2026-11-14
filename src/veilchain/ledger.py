"""A tamper-evident audit ledger (JSON Lines, one entry per line).

Each entry stores the hash of the entry before it, like links in a chain:

    entry_n.hash = SHA-256( canonical_json( entry_n without "hash", including "prev" = entry_{n-1}.hash ) )

Changing, deleting or re-ordering any entry breaks every hash after it, so `verify_ledger`
notices. The last line is a "seal" entry. If a key is available the seal also carries an HMAC
of the chain head, which an attacker cannot recompute without the key.

What this does NOT give you (stated honestly):
  * A hash chain proves consistency, not authenticity. Someone who can rewrite the whole file
    AND recompute every hash produces a valid-looking chain. The seal MAC (needs the key) or an
    external copy of the head hash (for example committed to git) closes that gap.
  * The ledger never contains original sensitive values, only event types, locations, keyed
    fingerprints and output tokens.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .clock import utc_now
from .hashing import canonical_json, constant_time_equal, hmac_hex, sha256_bytes

GENESIS = "0" * 64


class LedgerWriter:
    """Append-only writer. Refuses to overwrite an existing ledger file."""

    def __init__(self, path: Path | str, run_id: str, seal_key: Optional[bytes] = None):
        self.path = Path(path)
        self.run_id = run_id
        self.seal_key = seal_key
        self._prev = GENESIS
        self._seq = 0
        self._handle = open(self.path, "x", encoding="utf-8", newline="\n")  # "x" = fail if it exists
        self._sealed = False

    def append(self, event: str, data: dict) -> str:
        if self._sealed:
            raise RuntimeError("Ledger is sealed; no further entries may be appended.")
        entry = {"seq": self._seq, "ts": utc_now(), "run": self.run_id, "event": event, "data": data, "prev": self._prev}
        entry_hash = sha256_bytes(canonical_json(entry).encode("utf-8"))
        line = dict(entry, hash=entry_hash)
        self._handle.write(canonical_json(line) + "\n")
        self._prev = entry_hash
        self._seq += 1
        return entry_hash

    @property
    def head(self) -> str:
        return self._prev

    @property
    def count(self) -> int:
        return self._seq

    def seal(self) -> dict:
        """Write the final entry. Returns the seal data."""
        data = {"entries_before_seal": self._seq, "head": self._prev}
        if self.seal_key is not None:
            data["mac"] = hmac_hex(self.seal_key, "ledger-head", self._prev, str(self._seq))
        self.append("seal", data)
        self._sealed = True
        self._handle.flush()
        self._handle.close()
        return data

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.flush()
            self._handle.close()


@dataclass
class LedgerReport:
    ok: bool
    entries: int = 0
    head: Optional[str] = None
    sealed: bool = False
    mac_checked: bool = False
    mac_ok: Optional[bool] = None
    problems: list[str] = field(default_factory=list)
    first_bad_seq: Optional[int] = None


def read_entries(path: Path | str) -> list[dict]:
    entries = []
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            entries.append(json.loads(line))
    return entries


def verify_ledger(path: Path | str, seal_key: Optional[bytes] = None) -> LedgerReport:
    """Check the chain. Never raises for tampering; it reports what it found."""
    report = LedgerReport(ok=True)
    p = Path(path)
    if not p.is_file():
        report.ok = False
        report.problems.append("ledger file is missing")
        return report
    try:
        entries = read_entries(p)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        report.ok = False
        report.problems.append(f"ledger is not valid JSON Lines: {exc}")
        return report
    if not entries:
        report.ok = False
        report.problems.append("ledger is empty")
        return report

    prev = GENESIS
    for index, entry in enumerate(entries):
        claimed = entry.get("hash")
        body = {k: v for k, v in entry.items() if k != "hash"}
        if entry.get("seq") != index:
            report.problems.append(f"entry {index}: sequence number is {entry.get('seq')} (an entry was removed, added or re-ordered)")
            report.first_bad_seq = report.first_bad_seq if report.first_bad_seq is not None else index
        if entry.get("prev") != prev:
            report.problems.append(f"entry {index}: link to the previous entry is broken")
            report.first_bad_seq = report.first_bad_seq if report.first_bad_seq is not None else index
        recomputed = sha256_bytes(canonical_json(body).encode("utf-8"))
        if claimed is None or not constant_time_equal(str(claimed), recomputed):
            report.problems.append(f"entry {index}: content does not match its hash (entry was modified)")
            report.first_bad_seq = report.first_bad_seq if report.first_bad_seq is not None else index
        prev = claimed if isinstance(claimed, str) else recomputed
    report.entries = len(entries)
    report.head = prev

    last = entries[-1]
    if last.get("event") != "seal":
        report.problems.append("ledger has no seal entry at the end (it may have been truncated)")
    else:
        report.sealed = True
        data = last.get("data", {})
        if data.get("entries_before_seal") != len(entries) - 1:
            report.problems.append("seal entry count does not match the number of entries")
        head_expected = entries[-2].get("hash") if len(entries) > 1 else None
        if data.get("head") != head_expected:
            report.problems.append("seal entry head hash does not match the chain")
        if seal_key is not None:
            report.mac_checked = True
            expected = hmac_hex(seal_key, "ledger-head", str(data.get("head")), str(data.get("entries_before_seal")))
            report.mac_ok = "mac" in data and constant_time_equal(str(data.get("mac")), expected)
            if not report.mac_ok:
                report.problems.append("seal MAC does not verify with the supplied key (ledger was rewritten, or the wrong key was used)")
    report.ok = not report.problems
    return report
