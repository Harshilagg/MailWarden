import pytest

from mailwarden.core.redact import for_llm, redact_text
from tests.fixtures.emails import make


@pytest.mark.parametrize(
    "raw, must_not_contain",
    [
        ("reach me at priya.sharma@acme.com", "priya.sharma"),
        ("priya [at] acme [dot] com", "priya"),
        ("priya (at) acme (dot) co", "priya"),
        ("call +91 98765 43210", "98765"),
        ("call 98765-43210", "43210"),
        ("office (022) 2345 6789", "2345"),
        ("ref 426391837261", "426391837261"),
        ("card 4111 1111 1111 1111", "4111"),
        ("id 4​8​2​9​1​3", "4829"),
        ("full width ４８２９１３", "482913"),
        ("password: hunter2", "hunter2"),
        ("Password - Tr0ub4dor&3", "Tr0ub4dor"),
        ("your pin is 8812", "8812"),
        ("api_key=sk-live-abcdef0123456789", "abcdef"),
        ("token ya29.a0AfH6SMBxyz", "a0AfH6"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc", "eyJzdWIi"),
        ("github ghp_1234567890abcdefghij", "1234567890"),
        ("aws AKIAABCDEFGHIJKLMNOP", "AKIAABCD"),
        ("opaque Zm9vYmFyYmF6cXV4MTIzNDU2", "Zm9vYmFy"),
        ("https://user:secret@evil.example.com/reset?token=abc", "secret"),
        ("https://careers.acme.com/apply?candidate=88123&sig=zz", "88123"),
        ("see www.acme.com/jobs/12345", "12345"),
        ("short link bit.ly/3xYzAbC", "3xYzAbC"),
        ("PAN ABCDE1234F", "ABCDE1234F"),
        ("IFSC HDFC0001234", "HDFC0001234"),
        ("username: harshil_agg", "harshil_agg"),
    ],
)
def test_redacts(raw, must_not_contain):
    assert must_not_contain not in redact_text(raw)


def test_link_keeps_domain_only():
    assert redact_text("apply at https://jobs.lever.co/acme/1234?x=y") == "apply at [LINK:jobs.lever.co]"


def test_useful_context_survives():
    text = redact_text("Round 2 interview on Oct 3 at 10:30 IST for the Backend Engineer role at Acme, 90 minutes.")
    for kept in ("Round 2", "Oct 3", "10:30", "Backend Engineer", "Acme", "90 minutes"):
        assert kept in text


def test_dates_keep_day_month_but_not_year_digits():
    out = redact_text("deadline 2026-10-15")
    assert "2026" not in out and "10-15" in out


def test_terminal_escape_sequences_removed():
    assert "\x1b" not in redact_text("hello \x1b[31mred\x1b[0m \x1b]0;title\x07")


def test_bidi_override_removed():
    assert "‮" not in redact_text("invoice‮fdp.exe")


def test_truncation_and_no_half_placeholders():
    msg = make("a@acme.com", "A", "Subject", "word " * 400 + "https://acme.com/x")
    text = for_llm(msg, max_body_chars=1500)
    body = text.split("\n\n", 1)[1]
    assert len(body) <= 1502
    assert "[LIN" not in body or "[LINK:" in body


def test_for_llm_shape_and_sender_address_dropped():
    msg = make("recruiter.jane@acme.com", "Jane", "Interview", "See you Monday")
    text = for_llm(msg, max_body_chars=1500)
    assert text.startswith("From domain: acme.com\nSubject: Interview\n\n")
    assert "recruiter.jane" not in text and "Jane" not in text
