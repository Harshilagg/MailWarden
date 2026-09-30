"""LLM backend interface (implementations arrive in phase 3)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mailwarden.core.models import Classification


class LLMBackend(ABC):
    name: str
    #: True if text handed to this backend leaves the machine.
    remote: bool

    @abstractmethod
    def classify(self, redacted_text: str) -> Classification:
        """Classify ONE already-gated, already-redacted email."""
