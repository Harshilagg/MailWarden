"""Redaction of SAFE mail before it is handed to any LLM.

Replaces: URLs (keeping the domain as [LINK:domain]), email addresses,
phone numbers, every run of 4+ digits, and anything resembling a token,
key or password. Then truncates to subject + the first N body characters.
The sender's domain is kept as context; the sender's address is not.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from mailwarden.core.models import FetchedMessage
from mailwarden.core.text import clean

_URL = re.compile(r"(?i)\b(?:(?:https?|ftp)://|www\.)[^\s<>\"'`)\]}]+")
# Lookbehinds make these start only at token boundaries, so a long run of
# letters/digits costs O(n) instead of O(n^2) (no regex DoS from crafted mail).
_BARE_LINK = re.compile(
    r"(?i)(?<![a-z0-9.-])(?:[a-z0-9-]+\.)+(?:com|in|io|co|org|net|ly|me|app|dev|ai|gl|to|link|page|xyz)/[^\s<>\"'`)\]}]*"
)
_EMAIL = re.compile(r"(?i)(?<![a-z0-9._%+'-])[a-z0-9._%+'-]+\s*(?:@|\[at\]|\(at\)|\{at\})\s*(?:[a-z0-9-]+\s*(?:\.|\[dot\]|\(dot\))\s*)+[a-z]{2,}")
_SECRET_VALUE = re.compile(
    r"(?i)\b(password|passwd|pwd|passcode|pass|pin|otp|code|token|api[\s_-]?key|secret|key|username|user\s?id|login\s?id)"
    r"(\s*(?:is|:|=|-|–)\s*)(\S+)"
)
_KNOWN_TOKENS = re.compile(
    r"\b(?:ya29\.[\w.-]+|1//[\w.-]+|GOCSPX-[\w-]+|gsk_\w+|sk-[\w-]{16,}|ghp_\w+|gho_\w+|github_pat_\w+|"
    r"xox[abpr]-[\w-]+|AKIA[0-9A-Z]{16}|AIza[\w-]{30,}|eyJ[\w-]+\.[\w-]+\.[\w-]*)"
)
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9_\-+/=])[A-Za-z0-9_\-+/=]{16,}")
_ID_FORMATS = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b|\b[A-Z]{4}0[A-Z0-9]{6}\b")
_NUMBERISH = re.compile(r"\+?\(?\d(?:[\s().-]{0,2}\d)+")
_DATE_SHAPES = re.compile(r"\d{4}-\d{1,2}-\d{1,2}|\d{1,2}[.-]\d{1,2}[.-]\d{2,4}")
_DIGIT_RUN = re.compile(r"\d{4,}")
_FOOTER = re.compile(
    r"(?im)^[^\S\n]*(?:[-_*=|]+[^\S\n]*)?(?:to\s+)?(?:unsubscribe\b|manage\s+(?:your\s+)?(?:e-?mail|job\s+alert|notification|subscription)"
    r"|you\s+(?:are\s+)?receiv(?:ing|ed)\s+(?:this|these)|this\s+(?:e-?mail|message)\s+was\s+(?:sent|intended)"
    r"|privacy\s+policy|terms\s*(?:and|&)\s*conditions|disclaimer\b|©|copyright\b|download\s+(?:our|the)\s+app"
    r"|if\s+you\s+(?:no\s+longer|don'?t)\s+want|view\s+(?:this\s+)?(?:e-?mail\s+)?in\s+(?:your\s+)?browser)"
)
_MIN_KEEP = 200
# Lines dropped wherever they appear (they identify the recipient, add nothing).
_DROP_LINES = re.compile(
    r"(?im)^.*\bthis\s+(?:e-?mail|message)\s+was\s+intended\s+for\b.*$\n?"
)


def strip_footer(text: str) -> str:
    """Drop newsletter/legal footers: fewer tokens and less data leaving the machine."""
    text = _DROP_LINES.sub("", text)
    for m in _FOOTER.finditer(text):
        if m.start() >= _MIN_KEEP:
            return text[: m.start()].rstrip()
    return text


def _link(m: re.Match[str]) -> str:
    raw = m.group(0)
    try:
        host = urlsplit(raw if "://" in raw else f"http://{raw}").hostname
    except ValueError:
        host = None
    return f"[LINK:{host}]" if host else "[LINK]"


def _long_token(m: re.Match[str]) -> str:
    s = m.group(0)
    has_digit = any(c.isdigit() for c in s)
    has_alpha = any(c.isalpha() for c in s)
    mixed_case = any(c.isupper() for c in s[1:]) and any(c.islower() for c in s)
    if (has_digit and has_alpha) or (mixed_case and len(s) >= 20):
        return "[TOKEN]"
    return s


def _numberish(m: re.Match[str]) -> str:
    span = m.group(0)
    if _DATE_SHAPES.fullmatch(span):
        return _DIGIT_RUN.sub("[NUM]", span)  # keep day/month, drop the year digits
    digits = sum(c.isdigit() for c in span)
    if digits >= 8 and (span.startswith("+") or 10 <= digits <= 13):
        return "[PHONE]"
    if digits >= 4:
        return "[NUM]"
    return span


def redact_text(text: str) -> str:
    text = clean(text)
    text = _URL.sub(_link, text)
    text = _BARE_LINK.sub(_link, text)
    text = _EMAIL.sub("[EMAIL]", text)
    text = _KNOWN_TOKENS.sub("[TOKEN]", text)
    text = _SECRET_VALUE.sub(r"\1\2[REDACTED]", text)
    text = _ID_FORMATS.sub("[ID]", text)
    text = _LONG_TOKEN.sub(_long_token, text)
    text = _NUMBERISH.sub(_numberish, text)
    text = _DIGIT_RUN.sub("[NUM]", text)  # anything left, e.g. digits glued to letters
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def _cut(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit]
    # Never leave half a placeholder like "[LIN" behind.
    open_at = cut.rfind("[")
    if open_at > cut.rfind("]"):
        cut = cut[:open_at]
    return cut.rstrip() + " …"


def for_llm(msg: FetchedMessage, max_body_chars: int) -> str:
    """The exact text an LLM would receive for this (already gated SAFE) message."""
    subject = _cut(redact_text(msg.subject[:1000]), 300)
    # Only redact what could possibly be sent (redaction never grows text by more than ~2x
    # per placeholder, so 3x the budget is plenty), bounding work on very large bodies.
    body = _cut(redact_text(strip_footer(msg.body_text)[: max_body_chars * 3 + 200]), max_body_chars)
    domain = msg.sender_domain or "unknown"
    return f"From domain: {domain}\nSubject: {subject}\n\n{body}"
