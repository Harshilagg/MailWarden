"""Storage interfaces. Every method is scoped by user_id for future multi-tenancy."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mailwarden.core.models import Account, Application, EmailMeta


class AccountRegistry(ABC):
    @abstractmethod
    def list(self, user_id: str) -> list[Account]: ...

    @abstractmethod
    def get(self, user_id: str, name: str) -> Account | None: ...

    @abstractmethod
    def add(self, account: Account) -> None: ...

    @abstractmethod
    def remove(self, user_id: str, name: str) -> bool: ...


class Repository(ABC):
    """Persistent store for message metadata, sync state and applications.

    Implemented in phase 3 (SQLCipher). Never stores bodies or subjects.
    """

    @abstractmethod
    def get_sync_cursor(self, user_id: str, account: str) -> str | None: ...

    @abstractmethod
    def set_sync_cursor(self, user_id: str, account: str, cursor: str) -> None: ...

    @abstractmethod
    def has_message(self, user_id: str, message_id: str) -> bool: ...

    @abstractmethod
    def save_email_meta(self, meta: EmailMeta) -> None: ...

    @abstractmethod
    def list_email_meta(self, user_id: str, since_iso: str | None = None) -> list[EmailMeta]: ...

    @abstractmethod
    def upsert_application(self, app: Application) -> None: ...

    @abstractmethod
    def list_applications(self, user_id: str) -> list[Application]: ...

    @abstractmethod
    def delete_account_data(self, user_id: str, account: str) -> None: ...
