"""Log scrubbing: a second safety net behind "never log sensitive things".

Scrubs email addresses, digit runs (4+), bearer/OAuth/API tokens, JWTs,
key=value secrets and long high-entropy strings from every record,
including formatted args and exception tracebacks.
"""

from __future__ import annotations

import logging
import re
import sys

_SECRET_WORDS = (
    r"password|passwd|pwd|passcode|secret|token|api[_-]?key|apikey|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization|auth|otp|code_verifier|code"
)

_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (re.compile(r"\bya29\.[A-Za-z0-9._-]+"), "[TOKEN]"),
    (re.compile(r"\b1//[A-Za-z0-9._-]+"), "[TOKEN]"),
    (re.compile(r"\bGOCSPX-[A-Za-z0-9_-]+"), "[TOKEN]"),
    (re.compile(r"\bgsk_[A-Za-z0-9]+"), "[TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), "[JWT]"),
    (
        re.compile(rf"(?i)\b({_SECRET_WORDS})(\"?\s*[:=]\s*\"?|\s+is\s+)([^\s,;\"'&]+)"),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
]
# Long mixed alphanumeric strings look like keys; checked by function below.
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9_\-+=])[A-Za-z0-9_\-+=]{24,}")
_DIGITS = re.compile(r"\d{4,}")


def _long_token(m: re.Match[str]) -> str:
    s = m.group(0)
    if any(c.isdigit() for c in s) and any(c.isalpha() for c in s):
        return "[SECRET]"
    return s


def scrub(text: str) -> str:
    for pattern, repl in _RULES:
        text = pattern.sub(repl, text)
    text = _LONG_TOKEN.sub(_long_token, text)
    return _DIGITS.sub("[NUM]", text)


class ScrubbingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        record.msg = scrub(message)
        record.args = None
        if record.exc_info:
            formatted = logging.Formatter().formatException(record.exc_info)
            record.exc_text = scrub(formatted)
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = scrub(record.exc_text)
        if record.stack_info:
            record.stack_info = scrub(record.stack_info)
        return True


def install_logging(level: int = logging.INFO, stream=None) -> logging.Handler:
    """Configure root logging with the scrubber attached to the handler."""
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.addFilter(ScrubbingFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(level)
    # urllib3 debug logs include full URLs; keep it quiet.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.captureWarnings(True)
    return handler
