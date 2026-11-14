"""Hash helpers built on hashlib and hmac from the Python standard library.

A plain hash (SHA-256) proves that two byte strings are identical. It does NOT prove the
original was trustworthy. A keyed hash (HMAC) additionally needs a secret to compute,
which is what stops an attacker brute-forcing low-entropy values such as phone numbers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

_CHUNK = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path | str) -> str:
    """Hash a file in binary mode (read-only)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(obj: Any) -> str:
    """Stable JSON: sorted keys, no extra whitespace, ASCII only. Used for hash chaining."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def hmac_hex(key: bytes, *parts: str) -> str:
    """HMAC-SHA256 over the parts joined with an unambiguous separator (0x1f)."""
    message = "\x1f".join(parts).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
