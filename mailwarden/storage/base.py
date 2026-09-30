"""Storage interfaces. Every method is scoped by user_id for future multi-tenancy."""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from dataclasses import dataclass

from mailwarden.core.models import Account, Application, EmailMeta, Stage


class AccountRegistry(ABC):
    @abstractmethod
    def list(self, user_id: str) -> list[Account]: ...

    @abstractmethod
    def get(self, user_id: str, name: str) -> Account | None: ...

    @abstractmethod
    def add(self, account: Account) -> None: ...

    @abstractmethod
    def remove(self, user_id: str, name: str) -> bool: ...


@dataclass(frozen=True)
class ApplicationEvent:
    stage: Stage
    message_id: str
    occurred_at: dt.datetime


class Repository(ABC):
    """Persistent store for message metadata, sync state and applications.

    Never stores bodies or subjects. SENSITIVE rows hold only sender name,
    received time and account (enforced by EmailMeta and by the store).
    """

    # sync state
    @abstractmethod
    def get_sync_cursor(self, user_id: str, account: str) -> str | None: ...

    @abstractmethod
    def set_sync_cursor(self, user_id: str, account: str, cursor: str) -> None: ...

    # messages
    @abstractmethod
    def is_processed(self, user_id: str, account: str, message_id: str) -> bool:
        """True if the message is stored with a final (non-pending) status."""

    @abstractmethod
    def save_email_meta(self, meta: EmailMeta) -> None:
        """Insert or finalise a message row (idempotent)."""

    @abstractmethod
    def mark_pending(self, user_id: str, account: str, message_ids: list[str]) -> None:
        """Record ids to retry next run. Never downgrades a processed row."""

    @abstractmethod
    def list_pending(self, user_id: str, account: str, limit: int) -> list[str]: ...

    @abstractmethod
    def list_email_meta(self, user_id: str, since: dt.datetime | None = None) -> list[EmailMeta]: ...

    @abstractmethod
    def get_email_meta(self, user_id: str, account: str, message_id: str) -> EmailMeta | None: ...

    @abstractmethod
    def dismiss(self, user_id: str, account: str, message_id: str) -> bool:
        """Mark an urgent item as handled. Returns False if no such message."""

    # digests
    @abstractmethod
    def save_digest(self, user_id: str, generated_at: dt.datetime, period_start: dt.datetime, body_json: str) -> None: ...

    @abstractmethod
    def latest_digest(self, user_id: str) -> tuple[dt.datetime, dt.datetime, str] | None:
        """(generated_at, period_start, body_json) of the newest digest."""

    # applications
    @abstractmethod
    def find_application(self, user_id: str, company_key: str, role_key: str) -> Application | None: ...

    @abstractmethod
    def upsert_application(
        self,
        app: Application,
        *,
        event_stage: Stage,
        account: str,
        message_id: str,
        occurred_at: dt.datetime,
        domain: str | None,
    ) -> None: ...

    @abstractmethod
    def list_applications(self, user_id: str) -> list[Application]: ...

    @abstractmethod
    def application_history(self, user_id: str, company: str, role: str | None) -> list[ApplicationEvent]: ...

    @abstractmethod
    def application_domains(self, user_id: str) -> set[str]: ...

    # lifecycle
    @abstractmethod
    def delete_account_data(self, user_id: str, account: str) -> None: ...

    @abstractmethod
    def close(self) -> None: ...
