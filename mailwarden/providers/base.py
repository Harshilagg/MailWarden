"""Mail provider interface. Providers are read-only by construction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from mailwarden.core.models import Account, FetchedMessage, ProviderKind


class ProviderError(RuntimeError):
    pass


class ReauthRequired(ProviderError):
    """The stored grant is no longer valid; the user must run add-account again."""


@dataclass(frozen=True)
class SyncResult:
    message_ids: list[str]
    cursor: str
    full_sync: bool


class MailProvider(ABC):
    kind: ProviderKind

    @abstractmethod
    def verify_access(self, account: Account) -> frozenset[str]:
        """Check the grant and return its scopes. Must raise if scopes are too broad."""

    @abstractmethod
    def list_new(self, account: Account, cursor: str | None) -> SyncResult:
        """Return ids of messages newer than ``cursor`` (or a recent window if None)."""

    @abstractmethod
    def list_recent(self, account: Account, limit: int) -> list[str]:
        """Ids of the most recent ``limit`` messages, ignoring any cursor."""

    @abstractmethod
    def get_message(self, account: Account, message_id: str) -> FetchedMessage:
        """Fetch headers and text body. Never downloads attachment content."""
