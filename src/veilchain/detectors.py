"""Pattern detectors for sensitive entities in free text.

Detectors are deliberately simple and explainable (regular expressions plus validation),
not machine learning. Their limits are measured, not hidden: see `veilchain eval` and
`veilchain redteam`.

Entities: EMAIL, PHONE, CARD (Luhn-validated), SECRET, PRIVATE_KEY, PERSON (known subjects
only), RECORD_ID (pattern comes from the rules file).

Evasion handling: text is matched on a normalised view (Unicode NFKC, zero-width characters
removed) and matches are mapped back to the original text, so the original layout of the
rest of the line is preserved.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable

# Higher number = wins when two detections overlap.
PRIORITY = {
    "PRIVATE_KEY": 100,
    "SECRET": 90,
    "CARD": 80,
    "EMAIL": 70,
    "PHONE": 60,
    "PERSON": 50,
    "RECORD_ID": 10,
}

ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"}

# --- patterns -------------------------------------------------------------------------
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
EMAIL_BRACKET_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+\s*[\[(]\s*at\s*[\])]\s*[A-Za-z0-9\-]+"
    r"(?:\s*(?:\.|[\[(]\s*dot\s*[\])])\s*[A-Za-z0-9\-]+)+",
    re.IGNORECASE,
)
EMAIL_SPACED_RE = re.compile(
    r"[A-Za-z0-9_%+\-]+(?:\s*\.\s*[A-Za-z0-9_%+\-]+)*\s*@\s*[A-Za-z0-9\-]+(?:\s*\.\s*[A-Za-z0-9\-]+)*\s*\.\s*[A-Za-z]{2,}"
)

PHONE_INTL_RE = re.compile(r"(?<![\w+])\+\d{1,3}(?:[\s\-.]?\(?\d{1,4}\)?){2,5}(?!\d)")
PHONE_PAREN_RE = re.compile(r"(?<![\w.:/+\-])\(\d{2,4}\)[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}(?!\w)")
PHONE_GROUPED_RE = re.compile(r"(?<![\w.:/+\-])\d{2,4}[\s\-]\d{3,4}[\s\-]\d{3,4}(?![\w])")
_DATE_LIKE = re.compile(r"^\d{4}[-/ ]\d{2}[-/ ]\d{2}$|^\d{2}[-/ ]\d{2}[-/ ]\d{4}$")

CARD_RE = re.compile(r"(?<![\w])(?:\d[ \-]?){12,18}\d(?![\w])")

SECRET_ASSIGN_RE = re.compile(
    r"""(?ix)
    \b(?:api[_\- ]?key|apikey|secret(?:[_\- ]?key)?|access[_\- ]?token|auth[_\- ]?token|
        client[_\- ]?secret|token|passwd|password|pwd)\b
    \s*[:=]\s*
    (?P<q>['"]?)
    (?P<val>[^\s'",;]{6,})
    (?P=q)
    """
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+(?P<val>[A-Za-z0-9\-._~+/]{16,}=*)")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----|[\s\S]*$)"
)
# Values that look like placeholders, not secrets ("password: required").
_PLACEHOLDER_VALUES = {"required", "optional", "none", "null", "true", "false", "redacted", "hidden", "masked", "changeme"}


@dataclass(frozen=True)
class Detection:
    entity: str
    start: int  # indices into the ORIGINAL text
    end: int
    detector: str


def luhn_ok(digits: str) -> bool:
    """Luhn checksum used by payment card numbers. Filters out most random digit strings."""
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        n = int(char)
        if index % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _part_of_longer_digit_run(text: str, start: int, end: int) -> bool:
    """True if the match is directly joined (by a space or hyphen) to more digits."""
    if start >= 2 and text[start - 1] in " -" and text[start - 2].isdigit():
        return True
    if end + 1 < len(text) and text[end] in " -" and text[end + 1].isdigit():
        return True
    return False


def normalise_with_map(text: str) -> tuple[str, list[int]]:
    """Return (normalised text, index_map) where index_map[i] is the original index of char i."""
    out: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        if ch in ZERO_WIDTH:
            continue
        norm = unicodedata.normalize("NFKC", ch)
        for n in norm:
            out.append(n)
            index_map.append(i)
    return "".join(out), index_map


def normalise_value(entity: str, raw: str) -> str:
    """Canonical form of a value, so the same real-world value always gets the same token."""
    s = unicodedata.normalize("NFKC", raw)
    s = "".join(ch for ch in s if ch not in ZERO_WIDTH).strip()
    if entity == "EMAIL":
        s = s.lower()
        s = re.sub(r"\s*[\[(]\s*at\s*[\])]\s*", "@", s)
        s = re.sub(r"\s*[\[(]\s*dot\s*[\])]\s*", ".", s)
        return re.sub(r"\s+", "", s)
    if entity == "PHONE":
        plus = "+" if s.startswith("+") else ""
        return plus + re.sub(r"\D", "", s)
    if entity == "CARD":
        return re.sub(r"\D", "", s)
    if entity == "PERSON":
        return re.sub(r"\s+", " ", s).casefold()
    return s


class DetectorSet:
    def __init__(self, record_id_pattern: re.Pattern | None = None, known_names: Iterable[str] = ()):
        self.record_id_pattern = record_id_pattern
        names = sorted({" ".join(n.split()) for n in known_names if n and n.strip()}, key=len, reverse=True)
        self.known_names = names
        self._name_re = None
        if names:
            alternatives = "|".join(r"\s+".join(re.escape(part) for part in name.split()) for name in names)
            self._name_re = re.compile(r"(?<!\w)(?:" + alternatives + r")(?!\w)", re.IGNORECASE)

    # -- raw candidate matches (indices are into the NORMALISED text) ---------------------
    def _candidates(self, norm: str) -> list[tuple[str, int, int, str]]:
        found: list[tuple[str, int, int, str]] = []

        for m in PRIVATE_KEY_RE.finditer(norm):
            found.append(("PRIVATE_KEY", m.start(), m.end(), "private_key_block"))
        for m in SECRET_ASSIGN_RE.finditer(norm):
            if m.group("val").lower() not in _PLACEHOLDER_VALUES:
                found.append(("SECRET", m.start("val"), m.end("val"), "secret_assignment"))
        for m in BEARER_RE.finditer(norm):
            found.append(("SECRET", m.start("val"), m.end("val"), "bearer_token"))

        for m in CARD_RE.finditer(norm):
            digits = re.sub(r"\D", "", m.group(0))
            if luhn_ok(digits):
                found.append(("CARD", m.start(), m.end(), "card_luhn"))

        for m in EMAIL_RE.finditer(norm):
            found.append(("EMAIL", m.start(), m.end(), "email"))
        for m in EMAIL_BRACKET_RE.finditer(norm):
            found.append(("EMAIL", m.start(), m.end(), "email_bracket_obfuscation"))
        for m in EMAIL_SPACED_RE.finditer(norm):
            found.append(("EMAIL", m.start(), m.end(), "email_spaced"))

        for regex, name in ((PHONE_INTL_RE, "phone_intl"), (PHONE_PAREN_RE, "phone_paren"), (PHONE_GROUPED_RE, "phone_grouped")):
            for m in regex.finditer(norm):
                text = m.group(0)
                digits = re.sub(r"\D", "", text)
                if not 8 <= len(digits) <= 15:
                    continue
                if _DATE_LIKE.match(text.strip()):
                    continue
                # A grouped number that is just part of a longer digit sequence (for example a
                # 16-digit order number) is not a phone number.
                if name != "phone_intl" and _part_of_longer_digit_run(norm, m.start(), m.end()):
                    continue
                found.append(("PHONE", m.start(), m.end(), name))

        if self._name_re is not None:
            for m in self._name_re.finditer(norm):
                found.append(("PERSON", m.start(), m.end(), "known_subject"))

        if self.record_id_pattern is not None:
            for m in self.record_id_pattern.finditer(norm):
                found.append(("RECORD_ID", m.start(), m.end(), "record_id_pattern"))
        return found

    @staticmethod
    def _resolve(candidates: list[tuple[str, int, int, str]]) -> list[tuple[str, int, int, str]]:
        """Greedy overlap resolution: higher priority first, then longer, then earlier."""
        ordered = sorted(candidates, key=lambda c: (-PRIORITY.get(c[0], 0), -(c[2] - c[1]), c[1]))
        chosen: list[tuple[str, int, int, str]] = []
        for cand in ordered:
            if all(cand[2] <= kept[1] or cand[1] >= kept[2] for kept in chosen):
                chosen.append(cand)
        return sorted(chosen, key=lambda c: c[1])

    def detect(self, text: str) -> list[Detection]:
        """Find sensitive spans. Returned indices refer to the ORIGINAL text."""
        if not text:
            return []
        norm, index_map = normalise_with_map(text)
        if not norm:
            return []
        out: list[Detection] = []
        for entity, start, end, detector in self._resolve(self._candidates(norm)):
            orig_start = index_map[start]
            orig_end = index_map[end - 1] + 1
            out.append(Detection(entity, orig_start, orig_end, detector))
        return out
