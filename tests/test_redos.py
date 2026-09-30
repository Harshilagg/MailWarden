"""Crafted mail must not be able to stall processing (regex denial of service)."""

import time

import pytest

from mailwarden.core.job_alerts import parse_job_anchors, parse_view_job_blocks
from mailwarden.core.recruiting import looks_like_job_alert, recruiting_markers, sender_label
from mailwarden.core.redact import redact_text, strip_footer
from mailwarden.core.sensitivity_gate import scan_text
from mailwarden.providers.html_text import HtmlParseError, html_links, html_to_text
from mailwarden.security.log_filter import scrub

N = 100_000
HOSTILE = {
    "letters": "a" * N,
    "dotted": "a." * (N // 2),
    "at-signs": "a@" * (N // 2),
    "digits": "1" * N,
    "spaced-digits": "1 " * (N // 2),
    "share-spam": "share " * (N // 6),
    "punctuation": "!!! ,,, " * (N // 8),
    "secret-words": "code otp pin " * (N // 13),
    "dashes": "-" * N,
    "brackets": "[" * N,
    "html": "<div>" * (N // 5),
}

FUNCTIONS = {
    "scan_text": scan_text,
    "redact_text": redact_text,
    "strip_footer": strip_footer,
    "markers": lambda t: recruiting_markers("x.com", t[:1000], t),
    "job_alert": lambda t: looks_like_job_alert(t[:1000], t),
    "view_job": parse_view_job_blocks,
    "anchors": lambda t: parse_job_anchors([(t[:200], "https://x.com/job/" + t[:500])]),
    "sender_label": lambda t: sender_label(t[:500], "a@b.com"),
    "scrub": scrub,
    "html": lambda t: (_html_or_refused(t), html_links(t)),
}


def _html_or_refused(t):
    try:
        return html_to_text(t)
    except HtmlParseError:
        return ""  # refused (too deep): the message is then held as unparsed


@pytest.mark.parametrize("fn", FUNCTIONS, ids=list(FUNCTIONS))
@pytest.mark.parametrize("kind", HOSTILE, ids=list(HOSTILE))
def test_linear_time_on_hostile_input(fn, kind):
    start = time.perf_counter()
    FUNCTIONS[fn](HOSTILE[kind])
    assert time.perf_counter() - start < 3.0, f"{fn} too slow on {kind}"


def test_overly_nested_html_is_held_not_processed():
    import base64

    from mailwarden.core.models import GateDecision, Tier
    from mailwarden.core.sensitivity_gate import evaluate
    from mailwarden.providers.gmail import parse_message

    html = "<div>" * 5000 + "Hello"
    data = {"id": "x1", "internalDate": "0", "payload": {
        "mimeType": "text/html", "headers": [{"name": "From", "value": "a@b.com"}],
        "body": {"data": base64.urlsafe_b64encode(html.encode()).decode()}}}
    msg = parse_message("local", "p", data)
    assert msg.content_complete is False
    assert evaluate(msg, Tier.DEFAULT).decision is GateDecision.SENSITIVE
