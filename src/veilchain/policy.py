"""Load and validate the organisation's data-classification policy (JSON).

The policy is the single source of truth for class names, their order (lowest to highest
sensitivity, as listed in the file) and the handling statement attached to each class.
VeilChain quotes these handling statements when it explains a decision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .errors import PolicyError
from .hashing import sha256_bytes


@dataclass(frozen=True)
class PolicyClass:
    name: str
    rank: int  # position in the file; higher = more sensitive
    handling: str
    examples: tuple[str, ...]


class Policy:
    def __init__(self, name: str, notice: str, classes: list[PolicyClass], sha256: str, path: str):
        self.name = name
        self.notice = notice
        self.classes = classes
        self.sha256 = sha256
        self.path = path
        self._by_name = {c.name: c for c in classes}

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        p = Path(path)
        if not p.is_file():
            raise PolicyError(f"Policy file not found: {path}")
        raw = p.read_bytes()
        try:
            data = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PolicyError(f"Policy file is not valid JSON: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("classes"), list) or not data["classes"]:
            raise PolicyError('Policy must be a JSON object with a non-empty "classes" list.')
        classes: list[PolicyClass] = []
        seen: set[str] = set()
        for index, item in enumerate(data["classes"]):
            if not isinstance(item, dict) or not item.get("name") or not item.get("handling"):
                raise PolicyError(f'Class #{index + 1} needs both a "name" and a "handling" statement.')
            name = str(item["name"])
            if name in seen:
                raise PolicyError(f'Duplicate class name in policy: "{name}".')
            seen.add(name)
            classes.append(PolicyClass(name, index, str(item["handling"]), tuple(item.get("examples", []))))
        return cls(str(data.get("policy_name", "Unnamed policy")), str(data.get("notice", "")), classes, sha256_bytes(raw), str(p))

    # --- lookups -----------------------------------------------------------------------
    @property
    def names(self) -> list[str]:
        return [c.name for c in self.classes]

    @property
    def top(self) -> PolicyClass:
        """Highest class (Restricted in the Northstar policy)."""
        return self.classes[-1]

    def get(self, name: str) -> PolicyClass:
        try:
            return self._by_name[name]
        except KeyError:
            raise PolicyError(f'Unknown class "{name}". Policy defines: {", ".join(self.names)}.') from None

    def has(self, name: str) -> bool:
        return name in self._by_name

    def rank(self, name: str) -> int:
        return self.get(name).rank

    def highest(self, names: list[str]) -> str:
        return max(names, key=self.rank)

    def cite(self, class_name: str) -> str:
        """A short, quotable justification taken from the policy itself."""
        c = self.get(class_name)
        return f'{self.name}, class "{c.name}": "{c.handling}"'
