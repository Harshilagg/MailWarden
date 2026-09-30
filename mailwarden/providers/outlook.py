"""Microsoft Graph provider (delegated Mail.Read only). Implemented in phase 5."""

from __future__ import annotations

from mailwarden.core.models import Account, FetchedMessage, ProviderKind
from mailwarden.providers.base import MailProvider, SyncResult

GRAPH_SCOPE = "Mail.Read"


class OutlookProvider(MailProvider):
    kind = ProviderKind.OUTLOOK

    def verify_access(self, account: Account) -> frozenset[str]:
        raise NotImplementedError("Outlook support arrives in phase 5")

    def list_new(self, account: Account, cursor: str | None) -> SyncResult:
        raise NotImplementedError("Outlook support arrives in phase 5")

    def get_message(self, account: Account, message_id: str) -> FetchedMessage:
        raise NotImplementedError("Outlook support arrives in phase 5")
