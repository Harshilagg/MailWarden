import io
import logging

import pytest

from mailwarden.security.log_filter import install_logging, scrub


@pytest.mark.parametrize(
    "raw, leaked",
    [
        ("mail from alice.smith+jobs@example.co.in arrived", "alice.smith"),
        ("your OTP is 482913", "482913"),
        ("card ending 4421 debited", "4421"),
        ("call +91 98765 43210", "98765"),
        ("Authorization: Bearer ya29.a0AfH6SMBx-secret_value", "a0AfH6SMBx"),
        ("token ya29.A0ARrdaM-abc123", "A0ARrdaM"),
        ("refresh 1//0gLx-abcdefghijk", "0gLx"),
        ("client GOCSPX-AbCdEfGh123", "AbCdEfGh"),
        ("groq gsk_abcDEF123456", "abcDEF"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_part", "eyJzdWIi"),
        ("password=hunter2", "hunter2"),
        ('{"client_secret": "shhh"}', "shhh"),
        ("api_key: sk-live-abc", "sk-live-abc"),
        ("the password is Tr0ub4dor", "Tr0ub4dor"),
        ("opaque aB3dE5gH7jK9mN1pQ3rS5tU7vW9", "aB3dE5gH7jK9"),
    ],
)
def test_scrub_removes_sensitive_values(raw, leaked):
    assert leaked not in scrub(raw)


def test_scrub_keeps_ordinary_text():
    assert scrub("synced account personal: 12 new") == "synced account personal: 12 new"
    path = "/Users/someone/Library/Application Support/mailwarden-config/config.toml"
    assert scrub(path) == path


@pytest.fixture
def captured():
    buf = io.StringIO()
    install_logging(logging.DEBUG, stream=buf)
    yield buf
    install_logging(logging.WARNING)


def test_filter_applies_to_args_and_child_loggers(captured):
    logging.getLogger("mailwarden.providers.gmail").info("from %s code %s", "bob@corp.com", 739201)
    out = captured.getvalue()
    assert "bob@corp.com" not in out and "739201" not in out
    assert "[EMAIL]" in out and "[NUM]" in out


def test_filter_scrubs_exception_tracebacks(captured):
    try:
        raise RuntimeError("refresh failed for token ya29.leakme and user eve@x.org, otp 123456")
    except RuntimeError:
        logging.getLogger("mailwarden").exception("boom")
    out = captured.getvalue()
    for leaked in ("ya29.leakme", "eve@x.org", "123456"):
        assert leaked not in out
    assert "RuntimeError" in out
