"""Small helpers shared by the test modules."""

from __future__ import annotations

import shutil
from pathlib import Path

from veilchain.pipeline import RunOptions, run_redaction

POLICY = str(Path(__file__).resolve().parents[1] / "policy" / "data_classification_policy.json")
RULES = str(Path(__file__).resolve().parents[1] / "policy" / "veilchain_rules.json")


def redact(input_path, out_dir, keyring, **kw):
    return run_redaction(RunOptions(input_path=str(input_path), out_dir=str(out_dir), keyring=keyring,
                                    policy_path=POLICY, rules_path=RULES, **kw))


def read_all(folder: Path) -> str:
    return "\n".join(p.read_bytes().decode("utf-8", "ignore") for p in sorted(Path(folder).iterdir()) if p.is_file())


def copy_bundle(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst)
    return dst
