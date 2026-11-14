"""Unit tests for the detectors: positives, hard negatives and evasions."""

import re

import pytest

from veilchain.detectors import DetectorSet, luhn_ok, normalise_value

REC = re.compile(r"\bREC-\d{3,}\b")


@pytest.fixture
def det():
    return DetectorSet(REC, ["Maya Example", "Noah Sample"])


def entities(det, text):
    return [(d.entity, text[d.start:d.end]) for d in det.detect(text)]


@pytest.mark.parametrize("text,expected", [
    ("mail maya.example@example.com now", "maya.example@example.com"),
    ("mail MAYA.EXAMPLE@EXAMPLE.COM now", "MAYA.EXAMPLE@EXAMPLE.COM"),
    ("mail maya+tag@mail.example.org now", "maya+tag@mail.example.org"),
    ("mail a@b.co.", "a@b.co"),  # trailing full stop is not part of the address
])
def test_email_variants(det, text, expected):
    assert ("EMAIL", expected) in entities(det, text)


@pytest.mark.parametrize("text", [
    "Call +353-00-000-0002 now", "Call +353 00 000 0002 now", "Call +353.00.000.0002 now",
    "Call +353000000002 now", "Call (00) 000 0002 now", "Call 00 000 0002 now",
])
def test_phone_formats(det, text):
    assert any(e == "PHONE" for e, _ in entities(det, text))


@pytest.mark.parametrize("text", [
    "ORD-20261107-0042 shipped", "meeting on 2026-11-07", "at 12:30:45 today", "server 192.168.10.25 up",
    "version 3.12.4 installed", "ticket 123456789012 closed", "The email policy and the phone line",
])
def test_hard_negatives_are_not_flagged(det, text):
    assert entities(det, text) == []


def test_luhn_valid_card_detected_and_invalid_rejected(det):
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")
    assert ("CARD", "4111 1111 1111 1111") in entities(det, "card 4111 1111 1111 1111 ok")
    assert entities(det, "invoice 4111 1111 1111 1112 ok") == []  # 16 digits but fails the checksum


@pytest.mark.parametrize("text", ["password=VCFAKE-abc12345", "api_key: 'VCFAKE-abc12345'", "Authorization: Bearer VCFAKEtoken1234567890"])
def test_secrets_detected(det, text):
    assert any(e == "SECRET" for e, _ in entities(det, text))


def test_placeholder_password_is_not_a_secret(det):
    assert entities(det, "password: required for everyone") == []


def test_multiline_private_key_block_is_one_detection(det):
    begin, end = "-----BEGIN " + "FAKE PRIVATE KEY-----", "-----END " + "FAKE PRIVATE KEY-----"
    text = f"x\n{begin}\nBODYLINE1\nBODYLINE2\n{end}\ny"
    found = [(d.entity, text[d.start:d.end]) for d in det.detect(text)]
    assert found == [("PRIVATE_KEY", f"{begin}\nBODYLINE1\nBODYLINE2\n{end}")]


def test_unterminated_private_key_removes_everything_after_the_header(det):
    begin = "-----BEGIN " + "FAKE PRIVATE KEY-----"
    text = f"a\n{begin}\nBODY1\nBODY2"
    found = det.detect(text)
    assert len(found) == 1 and text[found[0].start:found[0].end].endswith("BODY2")


def test_zero_width_and_fullwidth_evasions_are_normalised(det):
    assert any(e == "EMAIL" for e, _ in entities(det, "ma\u200bya@example.com"))
    assert any(e == "PHONE" for e, _ in entities(det, "\uff0b\uff13\uff15\uff13\uff0d\uff10\uff10\uff0d\uff10\uff10\uff10\uff0d\uff10\uff10\uff10\uff12"))


def test_bracket_obfuscation_maps_back_to_original_span(det):
    text = "mail maya[at]example[dot]com today"
    found = entities(det, text)
    assert found == [("EMAIL", "maya[at]example[dot]com")]


def test_same_real_value_gets_same_normalised_form():
    forms = ["maya.example[at]example[dot]com", "MAYA.EXAMPLE@EXAMPLE.COM"]
    assert normalise_value("EMAIL", forms[0]) == normalise_value("EMAIL", "maya.example@example.com") == normalise_value("EMAIL", forms[1])
    assert normalise_value("PHONE", "+353-00-000-0001") == normalise_value("PHONE", "+353 00 000 0001")


def test_known_names_are_matched_case_insensitively_and_only_if_known(det):
    assert ("PERSON", "maya example") in entities(det, "ask maya example today")
    assert entities(det, "ask Quentin Whitlock today") == []  # unknown name: a documented limit


def test_record_id_and_clean_text(det):
    assert ("RECORD_ID", "REC-003") in entities(det, "Record REC-003 is marked Confidential")
    assert entities(det, "No personal information appears in this sentence") == []
    assert entities(det, "") == []


def test_overlap_priority_card_beats_phone(det):
    found = entities(det, "number 4111 1111 1111 1111 end")
    assert [e for e, _ in found] == ["CARD"]
