"""Composition root: the one place concrete implementations are wired together."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mailwarden.config import Settings, home_dir, load_settings
from mailwarden.core.models import Account, ProviderKind
from mailwarden.providers.base import MailProvider, ProviderError
from mailwarden.providers.gmail import GmailProvider
from mailwarden.providers.google_oauth import GoogleCredentials, OAuthClient
from mailwarden.security.net import AllowlistedSession, allowed_hosts
from mailwarden.security.secrets import SecretKeys, SecretStore
from mailwarden.storage.base import AccountRegistry
from mailwarden.storage.keyring_accounts import KeyringAccountRegistry


@dataclass
class App:
    home: Path
    settings: Settings
    secrets: SecretStore
    session: AllowlistedSession
    accounts: AccountRegistry
    providers: dict[ProviderKind, MailProvider] = field(default_factory=dict)

    @property
    def user_id(self) -> str:
        return self.settings.user_id

    def google_client(self) -> OAuthClient:
        raw = self.secrets.get(SecretKeys.oauth_client(self.user_id, ProviderKind.GMAIL))
        if not raw:
            raise ProviderError(
                "no Google OAuth client stored; pass --client-secrets <file> to add-account"
            )
        return OAuthClient.from_secret(raw)

    def google_credentials(self, account: Account) -> GoogleCredentials:
        refresh = self.secrets.get(SecretKeys.oauth_refresh(account.user_id, account.name))
        if not refresh:
            raise ProviderError(f"no stored token for account {account.name!r}; run add-account")
        return GoogleCredentials(self.google_client(), refresh, self.session)

    def provider_for(self, account: Account) -> MailProvider:
        try:
            return self.providers[account.provider]
        except KeyError:
            raise ProviderError(f"provider {account.provider} is not enabled") from None


def build_app(home: Path | None = None, secrets: SecretStore | None = None) -> App:
    home = home or home_dir()
    settings = load_settings(home)
    secrets = secrets or SecretStore()
    session = AllowlistedSession(allowed_hosts(settings))
    app = App(home, settings, secrets, session, KeyringAccountRegistry(secrets))
    app.providers[ProviderKind.GMAIL] = GmailProvider(
        session,
        app.google_credentials,
        full_sync_days=settings.gmail.full_sync_days,
        max_messages=settings.gmail.max_messages_per_run,
    )
    return app
