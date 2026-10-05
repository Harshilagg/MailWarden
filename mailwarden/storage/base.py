"""Storage interfaces. Every method is scoped by user_id for future multi-tenancy."""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from dataclasses import dataclass

from mailwarden.core.models import Account, Application, EmailMeta, JobPost, Stage, StoredJob


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

    @abstractmethod
    def delete_message(self, user_id: str, account: str, message_id: str) -> None:
        """Forget one message (and jobs extracted from it) so it can be reprocessed."""

    # job alerts
    @abstractmethod
    def save_jobs(self, user_id: str, *, account: str, message_id: str, sender: str,
                  received_at: dt.datetime, posts: list[JobPost], keys: list[str],
                  source_type: str | None = None, source_name: str | None = None) -> int:
        """Store jobs, de-duplicated by key across senders. Returns how many were new."""

    @abstractmethod
    def list_jobs(self, user_id: str, *, include_dismissed: bool = False, since: dt.datetime | None = None,
                  limit: int | None = None) -> list[StoredJob]: ...

    @abstractmethod
    def dismiss_job(self, user_id: str, job_id: int) -> bool: ...

    @abstractmethod
    def get_job(self, user_id: str, job_id: int) -> StoredJob | None: ...

    @abstractmethod
    def save_jd(self, user_id: str, job_id: int, *, status: str, reason: str | None, source: str | None,
                text: str | None) -> None:
        """Record a job description (status "ok") or why none is available ("unavailable")."""

    @abstractmethod
    def save_score(self, user_id: str, job_id: int, *, score: float, level: str, detail: dict,
                   input_hash: str) -> None: ...

    # calibration labels (your good/bad judgement of a job)
    @abstractmethod
    def save_label(self, user_id: str, job_id: int, label: str, *, score: float | None, level: str | None) -> None: ...

    @abstractmethod
    def list_labels(self, user_id: str) -> list[tuple[int, str, float | None]]: ...

    # small per-user state (e.g. when the daily job notice was last sent)
    @abstractmethod
    def get_state(self, user_id: str, key: str) -> str | None: ...

    @abstractmethod
    def set_state(self, user_id: str, key: str, value: str) -> None: ...

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
