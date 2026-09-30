"""Delivery interfaces (implemented in phase 4)."""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from dataclasses import dataclass

from mailwarden.core.models import Stage


@dataclass(frozen=True)
class JobAlert:
    """Everything a notification may contain. No summary, links or subjects."""

    user_id: str
    message_id: str
    company: str | None
    stage: Stage | None
    deadline: dt.date | None


class Notifier(ABC):
    @abstractmethod
    def notify(self, alert: JobAlert) -> None: ...


class DigestSink(ABC):
    @abstractmethod
    def write(self, user_id: str, digest_markdown: str, generated_at: dt.datetime) -> None: ...
