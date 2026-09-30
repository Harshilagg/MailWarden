"""Delivery interfaces (implemented in phase 4)."""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from dataclasses import dataclass

from mailwarden.core.models import Stage
from mailwarden.delivery.format import short_date


@dataclass(frozen=True)
class JobAlert:
    """Everything a notification may contain. No summary, links or subjects.

    ``held`` marks job mail the sensitivity gate kept away from the LLM; its
    company/stage come from local rules only.
    """

    user_id: str
    account: str
    message_id: str
    company: str | None
    stage: Stage | None
    deadline: dt.date | None
    held: bool = False

    def title(self) -> str:
        parts = [self.company or "Job email", str(self.stage) if self.stage else None]
        if self.held:
            parts.append("needs your attention")
        elif self.deadline:
            parts.append(f"due {short_date(self.deadline)}")
        return " · ".join(p for p in parts if p)


class Notifier(ABC):
    @abstractmethod
    def notify(self, alert: JobAlert) -> None: ...


class DigestSink(ABC):
    @abstractmethod
    def write(self, user_id: str, digest_markdown: str, generated_at: dt.datetime) -> None: ...
