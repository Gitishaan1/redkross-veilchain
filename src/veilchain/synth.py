"""Synthetic data generators (deterministic for a given seed).

Everything produced here is fictional:
  * names combine obviously fictional first names with surnames such as "Example" or "Dummy";
  * email addresses use the reserved example.com / example.net / example.org domains;
  * phone numbers use the non-routable pattern +353-00-NNN-NNNN (area code 00 does not exist);
  * card numbers are the publicly documented payment-test numbers;
  * secrets carry the visible marker VCFAKE and cannot work anywhere.

Private-key-looking blocks are only built in memory when asked for (never written by default),
so committed data files do not trip secret scanners.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

FIRST = ["Maya", "Noah", "Ivy", "Leo", "Zara", "Omar", "Nina", "Hugo", "Aria", "Theo", "Lena", "Ravi", "Sofia", "Kian",
         "Mira", "Jonas", "Esme", "Dev", "Talia", "Oscar", "Priya", "Felix", "Anya", "Milo", "Ruth", "Sami", "Cleo",
         "Arjun", "Elsa", "Rory", "Yara", "Luca", "Nora", "Idris", "Wren", "Tomas", "Hana", "Ezra", "Lila", "Boris"]
LAST = ["Example", "Sample", "Testcase", "Placeholder", "Fictional", "Mockup", "Trainee", "Demo", "Specimen", "Dummy",
        "Prototype", "Simulated"]
DOMAINS = ["example.com", "example.net", "example.org"]
DEPARTMENTS = ["Support", "Finance", "Engineering", "People Ops", "Legal", "Sales"]
LABELS = ["low", "medium", "high"]

# Publicly documented payment-card TEST numbers (Luhn-valid).
TEST_CARDS = ["4111111111111111", "5555555555554444", "378282246310005", "6011111111111117", "4012888888881881"]


def person_name(i: int) -> str:
    combos = len(FIRST) * len(LAST)
    first = FIRST[i % len(FIRST)]
    last = LAST[(i // len(FIRST)) % len(LAST)]
    round_ = i // combos
    return f"{first} {last}" + (f" {round_ + 1}" if round_ else "")


def person_email(i: int) -> str:
    first = FIRST[i % len(FIRST)].lower()
    last = LAST[(i // len(FIRST)) % len(LAST)].lower()
    round_ = i // (len(FIRST) * len(LAST))
    return f"{first}.{last}{round_ + 1 if round_ else ''}@{DOMAINS[i % len(DOMAINS)]}"


def phone_number(i: int) -> str:
    return f"+353-00-{(i // 10000) % 1000:03d}-{i % 10000:04d}"


def generate_records(n: int, seed: int = 1337) -> list[dict]:
    """Rows in the same shape as the provided customer_records_synthetic.csv."""
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        rows.append({
            "record_id": f"REC-{i + 1:03d}",
            "full_name": person_name(i),
            "email": person_email(i),
            "phone": phone_number(i + 1),
            "department": rng.choice(DEPARTMENTS),
            "data_sensitivity": rng.choices(LABELS, weights=[3, 3, 2])[0],
        })
    return rows


# --- labelled text corpus ------------------------------------------------------------------
@dataclass
class Span:
    entity: str
    start: int
    end: int
    known: bool = True  # False = the detector has no way to know this (for example an unlisted name)


@dataclass
class Sample:
    id: str
    kind: str  # positive | evasion | negative
    text: str
    spans: list[Span] = field(default_factory=list)


def _build(parts) -> tuple[str, list[Span]]:
    text, spans = "", []
    for part in parts:
        if isinstance(part, str):
            text += part
        else:
            entity, value, known = (part + (True,))[:3] if len(part) == 2 else part
            spans.append(Span(entity, len(text), len(text) + len(value), known))
            text += value
    return text, spans


def _bad_luhn_card(rng: random.Random) -> str:
    from .detectors import luhn_ok

    while True:
        digits = "4" + "".join(str(rng.randrange(10)) for _ in range(15))
        if not luhn_ok(digits):
            return f"{digits[0:4]} {digits[4:8]} {digits[8:12]} {digits[12:16]}"


def _private_key_block() -> str:
    # Built from pieces so this source file never contains a literal key header.
    begin, end = "-----BEGIN " + "FAKE PRIVATE KEY-----", "-----END " + "FAKE PRIVATE KEY-----"
    return f"{begin}\nVEILCHAIN-DEMO-NOT-A-REAL-KEY-0123456789\n{end}"


def generate_corpus(size: int = 400, seed: int = 1337, known_names: list[str] | None = None,
                    include_private_keys: bool = False) -> list[Sample]:
    """A labelled corpus: positives, evasions (obfuscated PII) and hard negatives."""
    rng = random.Random(seed)
    known = known_names or [person_name(i) for i in range(10)]
    samples: list[Sample] = []

    def make(kind: str, parts) -> None:
        text, spans = _build(parts)
        samples.append(Sample(f"S{len(samples) + 1:04d}", kind, text, spans))

    def an_email() -> str:
        return person_email(rng.randrange(0, 400))

    def a_phone() -> str:
        number = phone_number(rng.randrange(1, 9999))
        return rng.choice([number, number.replace("-", " "), number.replace("-", ".")])

    def a_local_phone() -> str:
        n = rng.randrange(1, 9999)
        return rng.choice([f"(00) 000 {n:04d}", f"00 000 {n:04d}", f"00-000-{n:04d}"])

    def a_card() -> str:
        card = rng.choice(TEST_CARDS)
        return rng.choice([card, " ".join(card[i:i + 4] for i in range(0, len(card), 4)), "-".join(card[i:i + 4] for i in range(0, len(card), 4))])

    def a_secret() -> str:
        return "VCFAKE-" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(14))

    def unknown_name() -> str:
        return f"{rng.choice(['Quentin', 'Imogen', 'Bram', 'Odile', 'Percy'])} {rng.choice(['Whitlock', 'Marchetti', 'Okafor', 'Lindqvist'])}"

    positives = [
        lambda: ["Contact ", ("PERSON", rng.choice(known)), " at ", ("EMAIL", an_email()), " about the invoice."],
        lambda: ["Please send the report to ", ("EMAIL", an_email()), " by Friday."],
        lambda: ["Call ", ("PHONE", a_phone()), " for follow-up."],
        lambda: ["Reach ", ("PERSON", unknown_name(), False), " on ", ("PHONE", a_local_phone()), "."],
        lambda: ["Customer ", ("PERSON", rng.choice(known)), " called from ", ("PHONE", a_phone()), "."],
        lambda: ["Card on file: ", ("CARD", a_card()), " (test number)."],
        lambda: ["Config note: password=", ("SECRET", a_secret()), " must be rotated."],
        lambda: ["Set api_key: ", ("SECRET", a_secret()), " in the staging file."],
        lambda: ["Authorization: Bearer ", ("SECRET", a_secret() + "ABCDEF")],
        lambda: ["Escalated record ", ("RECORD_ID", f"REC-{rng.randrange(1, 999):03d}"), " to the audit team."],
        lambda: ["Forward to ", ("EMAIL", an_email().upper()), " and copy ", ("EMAIL", an_email().replace("@", "+tag@")), "."],
    ]
    if include_private_keys:
        positives.append(lambda: ["Found in log: ", ("PRIVATE_KEY", _private_key_block()), " (end of log)."])

    evasions = [
        lambda: ["Mail ", ("EMAIL", an_email().replace("@", "[at]").replace(".", "[dot]")), " today."],
        lambda: ["Mail ", ("EMAIL", an_email().replace("@", " (at) ").replace(".", " (dot) ")), " today."],
        lambda: ["Mail ", ("EMAIL", " . ".join(an_email().split(".")[:1]) + " @ example . com"), " today."],
        lambda: ["Mail ", ("EMAIL", "ma\u200bya.exa\u200bmple@example.com"), " today."],
        lambda: ["Call ", ("PHONE", "\uff0b\uff13\uff15\uff13\uff0d\uff10\uff10\uff0d\uff10\uff10\uff10\uff0d\uff10\uff10\uff10\uff12"), " now."],
        lambda: ["Mail ", ("EMAIL", "m a y a @ e x a m p l e . c o m", False), " today."],
        lambda: ["Mail ", ("EMAIL", "maya dot example at example dot com", False), " today."],
        lambda: ["Mail ", ("EMAIL", "moc.elpmaxe@aym", False), " today."],
    ]

    negatives = [
        lambda: ["Order ORD-20261107-0042 shipped on 2026-11-07 at 12:30:45."],
        lambda: ["Server 192.168.10.25 rebooted; version 3.12.4 installed."],
        lambda: [f"Invoice number {_bad_luhn_card(rng)} was approved."],
        lambda: ["The email policy requires encryption and the phone line is busy."],
        lambda: ["Meeting @ 5 pm . Thanks"],
        lambda: ["Password: required for all accounts; password policy applies."],
        lambda: ["Ticket 123456789012 was closed by the service desk."],
        lambda: ["Part number 12-345-6789 is back-ordered."],
        lambda: ["Quarterly review scheduled for 2026-12-03; no personal data involved."],
        lambda: ["The Example department updated the Sample procedure."],
    ]

    n_pos = int(size * 0.55)
    n_evasion = int(size * 0.2)
    n_neg = size - n_pos - n_evasion
    for _ in range(n_pos):
        make("positive", rng.choice(positives)())
    for _ in range(n_evasion):
        make("evasion", rng.choice(evasions)())
    for _ in range(n_neg):
        make("negative", rng.choice(negatives)())
    rng.shuffle(samples)
    for number, sample in enumerate(samples, start=1):
        sample.id = f"S{number:04d}"
    return samples
