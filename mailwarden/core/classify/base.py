"""LLM backend interface and the retry-once policy."""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod

from pydantic import ValidationError

from mailwarden.core.models import Classification

log = logging.getLogger(__name__)


class BackendError(RuntimeError):
    pass


class BackendUnavailable(BackendError):
    """Transient: network down, rate-limited, server error. Message stays pending."""


class InvalidOutput(BackendError):
    """The model returned something that is not exactly the Classification schema."""


class LLMBackend(ABC):
    name: str
    model: str
    #: True if text handed to this backend leaves the machine.
    remote: bool

    @abstractmethod
    def classify(self, redacted_text: str) -> Classification:
        """Classify ONE already-gated, already-redacted email.

        Raises InvalidOutput or BackendUnavailable.
        """

    def extract_jobs(self, redacted_text: str) -> str:
        """Return raw JSON listing the jobs in ONE redacted, SAFE job-alert email.

        Raises InvalidOutput or BackendUnavailable. Optional for backends.
        """
        raise NotImplementedError

    def score_fit(self, messages: list[dict[str, str]]) -> str:
        """Return raw JSON rating one job against the profile (see core/fit.py). Optional."""
        raise NotImplementedError

    def check(self) -> None:
        """Fail fast if the backend is unusable (missing key, server not running)."""


_PLACEHOLDER_WORDS = {
    "LINK": "a link", "EMAIL": "an email address", "PHONE": "a phone number",
}
_PLACEHOLDER = re.compile(r"\[(LINK|EMAIL|PHONE|NUM|TOKEN|REDACTED|ID)(?::[^\]]*)?\]")


_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _day_month(day: str, month: str) -> str:
    d, m = int(day), int(month)
    return f"{d} {_MONTHS[m - 1]}" if 1 <= m <= 12 and 1 <= d <= 31 else ""


def tidy_model_text(text: str) -> str:
    """Remove redaction placeholders from model text before it is stored or shown."""
    # Dates whose year was redacted: "[NUM]-10-12" (ISO) and "12/10/[NUM]" (day first).
    text = re.sub(r"\[NUM\]-(\d{1,2})-(\d{1,2})", lambda m: _day_month(m.group(2), m.group(1)), text)
    text = re.sub(r"(\d{1,2})[/.-](\d{1,2})[/.-]\[NUM\]", lambda m: _day_month(m.group(1), m.group(2)), text)
    text = _PLACEHOLDER.sub(lambda m: _PLACEHOLDER_WORDS.get(m.group(1), ""), text)
    text = re.sub(r"https?://\S+", "a link", text)
    text = re.sub(r"\(\s*\)|\[\s*\]", "", text)
    text = re.sub(r"\s+([,.;:!?])", r"\1", text)
    text = re.sub(r"([,;:])\1+", r"\1", text)
    return re.sub(r"\s{2,}", " ", text).strip(" ,;:-")


def parse_output(raw: str) -> Classification:
    """Parse model output strictly. Anything but the exact schema is rejected.

    Placeholders the model echoed back are cleaned out of free-text fields.
    """
    try:
        c = Classification.model_validate_json(raw)
    except (ValidationError, ValueError):
        raise InvalidOutput("model output did not match the schema") from None
    company = tidy_model_text(c.company) if c.company else None
    role = tidy_model_text(c.role) if c.role else None
    summary = tidy_model_text(c.summary)
    if summary and not summary.endswith((".", "!", "?")):
        summary += "."
    return c.model_copy(update={"company": company or None, "role": role or None, "summary": summary})


def classify_with_retry(backend: LLMBackend, redacted_text: str) -> Classification | None:
    """Try twice; None means 'unclassified'. BackendUnavailable propagates."""
    for attempt in (1, 2):
        try:
            return backend.classify(redacted_text)
        except InvalidOutput:
            log.warning("invalid classifier output (attempt %d of 2)", attempt)
    return None
