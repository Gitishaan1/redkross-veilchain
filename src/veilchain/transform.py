"""The redaction engine: turn a classification into an action, apply it, and describe it.

Actions
  keep       the class is at or below the release level, so the value may remain.
  tokenise   replace with a keyed pseudonym such as EMAIL#7f3a9c21d4 (same input, same token).
  mask       replace with a bare label such as [EMAIL] (no linkability at all).
  remove     Restricted material: replace with [RESTRICTED-REMOVED]. Nothing derived from the
             original (no token, no fingerprint) is kept anywhere.

The engine never returns, logs or stores the original sensitive value in an Event.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .classify import CellClassification, classify_cell
from .detectors import DetectorSet, normalise_value
from .errors import VeilChainError
from .hashing import hmac_hex, sha256_bytes
from .keys import KeyRing
from .policy import Policy
from .rules import Rules

TOKEN_HEX_LEN = 10
FINGERPRINT_HEX_LEN = 16
REMOVED_LABEL = "RESTRICTED-REMOVED"
VALID_MODES = ("pseudonymise", "mask")
VALID_SCHEMES = ("hmac", "unkeyed")


@dataclass
class Event:
    entity: str
    cls: str
    action: str  # keep | tokenise | mask | remove
    column: str
    record_id: str
    locator: str
    detector: str
    reason: str  # why the action was chosen
    cite: str  # quote from the policy
    token: Optional[str] = None  # what the output now contains (never the original)
    fingerprint: Optional[str] = None  # keyed fingerprint for the audit ledger (never for Restricted)

    def ledger_data(self) -> dict:
        data = {
            "entity": self.entity,
            "class": self.cls,
            "action": self.action,
            "column": self.column,
            "record": self.record_id,
            "loc": self.locator,
            "detector": self.detector,
        }
        if self.token:
            data["out"] = self.token
        if self.fingerprint:
            data["fp"] = self.fingerprint
        return data

    def explain(self) -> str:
        verb = {
            "keep": "KEPT",
            "tokenise": "TOKENISED",
            "mask": "MASKED",
            "remove": "REMOVED",
        }[self.action]
        return f"[{self.record_id}] {self.entity} ({self.cls}) in {self.column}: {verb}. {self.reason} Policy: {self.cite}"


class Redactor:
    def __init__(
        self,
        policy: Policy,
        rules: Rules,
        keys: KeyRing,
        detectors: DetectorSet,
        mode: str = "pseudonymise",
        release_level: str = "Internal",
        token_scheme: str = "hmac",
    ):
        if mode not in VALID_MODES:
            raise VeilChainError(f"Unknown mode '{mode}'. Use one of: {', '.join(VALID_MODES)}.")
        if token_scheme not in VALID_SCHEMES:
            raise VeilChainError(f"Unknown token scheme '{token_scheme}'. Use one of: {', '.join(VALID_SCHEMES)}.")
        if not policy.has(release_level):
            raise VeilChainError(f"Unknown release level '{release_level}'. Policy defines: {', '.join(policy.names)}.")
        if release_level == rules.never_store_class:
            raise VeilChainError(f"Release level cannot be '{release_level}': that class is never released.")
        self.policy = policy
        self.rules = rules
        self.keys = keys
        self.detectors = detectors
        self.mode = mode
        self.release_level = release_level
        self.token_scheme = token_scheme

    # -- decisions -----------------------------------------------------------------------
    def decide(self, class_name: str) -> tuple[str, str]:
        """Return (action, reason) for data of the given class."""
        if class_name == self.rules.never_store_class:
            return "remove", f"{class_name} material is never stored or released; nothing derived from it is kept."
        if self.policy.rank(class_name) <= self.policy.rank(self.release_level):
            return "keep", f"{class_name} is at or below the release level ({self.release_level})."
        action = "mask" if self.mode == "mask" else "tokenise"
        return action, f"{class_name} is above the release level ({self.release_level}), so it is redacted before sharing."

    # -- rendering -----------------------------------------------------------------------
    def _token(self, entity: str, normalised: str) -> str:
        if self.token_scheme == "unkeyed":
            # INSECURE baseline kept only so the red-team suite can demonstrate the attack.
            digest = sha256_bytes((entity + "\x1f" + normalised).encode("utf-8"))
        else:
            digest = hmac_hex(self.keys.token_key, entity, normalised)
        return f"{entity}#{digest[:TOKEN_HEX_LEN]}"

    def _render(self, entity: str, raw: str, action: str, in_text: bool) -> tuple[str, Optional[str], Optional[str]]:
        """Return (replacement, token, fingerprint). Original value is used only to derive these."""
        if action == "remove":
            return f"[{REMOVED_LABEL}]", None, None
        normalised = normalise_value(entity, raw)
        fingerprint = hmac_hex(self.keys.audit_key, entity, normalised)[:FINGERPRINT_HEX_LEN]
        if action == "mask":
            return f"[{entity}]", None, fingerprint
        token = self._token(entity, normalised)
        return (f"[{token}]" if in_text else token), token, fingerprint

    def _event(self, entity, cls, action, reason, cite, column, record_id, locator, detector, token, fingerprint) -> Event:
        return Event(entity, cls, action, column, record_id, locator, detector, reason, cite, token, fingerprint)

    # -- free text -----------------------------------------------------------------------
    def redact_text(
        self,
        text: str,
        column: str = "text",
        record_id: str = "-",
        detections=None,
        line_of=None,
    ) -> tuple[str, list[Event]]:
        """Redact one piece of text. `line_of(offset)` (optional) maps a character offset to a
        line number, so a whole multi-line file can be processed at once and still be logged per line."""
        detections = self.detectors.detect(text) if detections is None else detections
        events: list[Event] = []
        pieces: list[tuple[int, int, str]] = []
        for number, det in enumerate(detections, start=1):
            cls = self.rules.entity_classes.get(det.entity, self.rules.unknown_field.cls)
            action, reason = self.decide(cls)
            cite = self.policy.cite(cls)
            locator = f"{column}#{number}"
            if line_of is not None:
                record_id = f"line-{line_of(det.start)}"
            if action == "keep":
                events.append(self._event(det.entity, cls, action, reason, cite, column, record_id, locator, det.detector, None, None))
                continue
            replacement, token, fp = self._render(det.entity, text[det.start:det.end], action, in_text=True)
            pieces.append((det.start, det.end, replacement))
            events.append(self._event(det.entity, cls, action, reason, cite, column, record_id, locator, det.detector, token, fp))
        out = text
        for start, end, replacement in sorted(pieces, reverse=True):
            out = out[:start] + replacement + out[end:]
        return out, events

    # -- table cells ---------------------------------------------------------------------
    def redact_cell(
        self,
        column: str,
        value: Optional[str],
        record_id: str,
        text_columns: frozenset[str] = frozenset(),
    ) -> tuple[str, CellClassification, list[Event]]:
        cc = classify_cell(self.policy, self.rules, self.detectors, column, value, text_columns)
        raw = value or ""
        if not raw.strip():
            return raw, cc, []

        if column.lower() in text_columns:
            new_text, events = self.redact_text(raw, column, record_id, cc.detections)
            return new_text, cc, events

        rule, _known = self.rules.rule_for(column)
        action, reason = self.decide(cc.effective_class)

        # Case 1: the field itself must be transformed (class above release level, or Restricted
        # content found inside it). The whole cell is replaced, which is the safe choice.
        field_action, _ = self.decide(rule.cls)
        if rule.entity or field_action != "keep" or action == "remove":
            if action == "keep":
                return raw, cc, []
            entity = rule.entity or column.upper().replace(" ", "_")
            if action == "remove":
                # Name the entity that triggered removal (for example SECRET), not the column.
                for det in cc.detections:
                    if self.rules.entity_classes.get(det.entity) == self.rules.never_store_class:
                        entity = det.entity
                        break
            cls = cc.effective_class
            replacement, token, fp = self._render(entity, raw, action, in_text=False)
            event = self._event(entity, cls, action, reason, self.policy.cite(cls), column, record_id, f"{column}", "field_rule", token, fp)
            return replacement, cc, [event]

        # Case 2: the field may stay, but content inside it may still need redaction.
        new_text, events = self.redact_text(raw, column, record_id, cc.detections)
        return new_text, cc, events
