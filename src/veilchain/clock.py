"""Time source. Honours VEILCHAIN_FIXED_TIME so tests can be deterministic."""

from __future__ import annotations

import os
from datetime import datetime, timezone


def utc_now() -> str:
    fixed = os.environ.get("VEILCHAIN_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
