"""LLM backend interface and the retry-once policy."""

from __future__ import annotations

import logging
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

    def check(self) -> None:
        """Fail fast if the backend is unusable (missing key, server not running)."""


def parse_output(raw: str) -> Classification:
    """Parse model output strictly. Anything but the exact schema is rejected."""
    try:
        return Classification.model_validate_json(raw)
    except (ValidationError, ValueError):
        raise InvalidOutput("model output did not match the schema") from None


def classify_with_retry(backend: LLMBackend, redacted_text: str) -> Classification | None:
    """Try twice; None means 'unclassified'. BackendUnavailable propagates."""
    for attempt in (1, 2):
        try:
            return backend.classify(redacted_text)
        except InvalidOutput:
            log.warning("invalid classifier output (attempt %d of 2)", attempt)
    return None
