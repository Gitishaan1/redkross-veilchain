"""Key handling.

Keys are treated as RESTRICTED material (the policy lists authentication secrets as
Restricted: never store in training reports). Therefore:
  * keys are never written into outputs, ledgers or manifests (only a short key id is);
  * `keygen` refuses to write a key inside a git repository;
  * three independent sub-keys are derived from one master key (domain separation), so the
    tokens in a shared output file cannot be correlated with fingerprints in the ledger.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import KeyMaterialError

ENV_VAR = "VEILCHAIN_KEY"
MIN_KEY_BYTES = 16
_HEX = re.compile(r"^[0-9a-fA-F]+$")

# The demo key is PUBLIC (it is in the source code). It exists only so that the demo and the
# evidence files are reproducible. Never use it for real data.
DEMO_KEY = hashlib.sha256(b"veilchain-public-demo-key-NOT-A-SECRET").digest()


def _derive(master: bytes, label: bytes) -> bytes:
    return hmac.new(master, b"veilchain/" + label, hashlib.sha256).digest()


@dataclass(frozen=True)
class KeyRing:
    master: bytes
    source: str  # "file" | "env" | "demo" | "ephemeral"

    @property
    def token_key(self) -> bytes:
        return _derive(self.master, b"token/v1")

    @property
    def audit_key(self) -> bytes:
        return _derive(self.master, b"audit/v1")

    @property
    def seal_key(self) -> bytes:
        return _derive(self.master, b"seal/v1")

    @property
    def key_id(self) -> str:
        """Short, non-reversible identifier so reviewers can tell which key was used."""
        return _derive(self.master, b"key-id/v1").hex()[:12]

    @property
    def reproducible(self) -> bool:
        return self.source != "ephemeral"


def parse_key_text(text: str) -> bytes:
    cleaned = "".join(text.split())
    if not cleaned or not _HEX.match(cleaned) or len(cleaned) % 2:
        raise KeyMaterialError("Key must be hexadecimal text (an even number of 0-9a-f characters).")
    raw = bytes.fromhex(cleaned)
    if len(raw) < MIN_KEY_BYTES:
        raise KeyMaterialError(f"Key too short: need at least {MIN_KEY_BYTES} bytes ({MIN_KEY_BYTES * 2} hex characters).")
    return raw


def load_keyring(key_file: str | None = None, demo: bool = False) -> KeyRing:
    """Resolve the key: --key-file, then --demo-key, then the environment, else ephemeral."""
    if key_file:
        path = Path(key_file)
        if not path.is_file():
            raise KeyMaterialError(f"Key file not found: {key_file}")
        return KeyRing(parse_key_text(path.read_text(encoding="utf-8")), "file")
    if demo:
        return KeyRing(DEMO_KEY, "demo")
    env = os.environ.get(ENV_VAR)
    if env:
        return KeyRing(parse_key_text(env), "env")
    return KeyRing(os.urandom(32), "ephemeral")


def _inside_git_repo(path: Path) -> bool:
    for parent in [path.resolve()] + list(path.resolve().parents):
        if (parent / ".git").exists():
            return True
    return False


def generate_key_file(out_path: str, allow_in_repo: bool = False) -> str:
    """Create a new random key file. Refuses to write inside a git repository by default."""
    path = Path(out_path)
    if path.exists():
        raise KeyMaterialError(f"Refusing to overwrite existing file: {out_path}")
    if _inside_git_repo(path.parent) and not allow_in_repo:
        raise KeyMaterialError(
            "Refusing to write a key inside a git repository (it could be committed by accident). "
            "Choose a folder outside the repository, or pass --allow-in-repo if you are sure."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)  # no effect on some Windows setups; best effort
    except OSError:
        pass
    return str(path)
