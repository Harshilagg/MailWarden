"""Composition root: the one place concrete implementations are wired together."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mailwarden.config import Settings, home_dir, load_sender_rules, load_settings
from mailwarden.core.classify.base import LLMBackend
from mailwarden.core.classify.groq import GroqBackend
from mailwarden.core.classify.ollama import OllamaBackend
from mailwarden.core.classify.ratelimit import RateLimitedBackend
from mailwarden.core.models import Account, ProviderKind
from mailwarden.core.pipeline import Pipeline
from mailwarden.providers.base import MailProvider, ProviderError
from mailwarden.providers.gmail import GmailProvider
from mailwarden.providers.google_oauth import GoogleCredentials, OAuthClient
from mailwarden.security.net import AllowlistedSession, allowed_hosts
from mailwarden.security.secrets import SecretKeys, SecretStore
from mailwarden.storage.base import AccountRegistry, Repository
from mailwarden.storage.keyring_accounts import KeyringAccountRegistry
from mailwarden.storage.sqlite_store import SQLCipherRepository

DB_RELATIVE_PATH = Path("data") / "mailwarden.db"


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

    def rules(self):
        return load_sender_rules(self.home)

    def pipeline(self, llm: LLMBackend | None = None) -> Pipeline:
        return Pipeline(self.rules(), max_body_chars=self.settings.llm.max_body_chars, llm=llm)

    def llm_backend(self) -> LLMBackend:
        s = self.settings
        inner: LLMBackend
        if s.llm.backend == "groq":
            key = self.secrets.get(SecretKeys.groq_api_key(self.user_id)) or ""
            g = s.groq
            inner = GroqBackend(
                self.session, key, model=g.model, reasoning_effort=g.reasoning_effort,
                min_interval_seconds=g.min_interval_seconds, timeout_seconds=g.timeout_seconds,
            )
        else:
            o = s.ollama
            inner = OllamaBackend(self.session, base_url=o.base_url, model=o.model, timeout_seconds=o.timeout_seconds)
        return RateLimitedBackend(
            inner, per_minute=s.llm.max_llm_calls_per_minute, per_run=s.llm.max_llm_calls_per_run
        )

    def backend_description(self) -> str:
        s = self.settings
        if s.llm.backend == "groq":
            return f"groq ({s.groq.model}) - CLOUD: receives redacted text of SAFE mail only"
        return f"ollama ({s.ollama.model}) - local: nothing leaves this machine"

    def repository(self) -> Repository:
        return SQLCipherRepository.open(self.home / DB_RELATIVE_PATH, self.secrets, self.user_id)

    def dashboard_url(self) -> str:
        return f"http://127.0.0.1:{self.settings.dashboard.port}"

    def notifier(self):
        from mailwarden.delivery.desktop_notify import DesktopNotifier

        n = self.settings.notifications
        if not n.enabled or n.backend == "none":
            return None
        return DesktopNotifier(backend=n.backend, dashboard_base_url=self.dashboard_url(),
                               click_wait_seconds=n.click_wait_seconds)

    def digest_sink(self):
        from mailwarden.delivery.digest_file import MarkdownDigestSink

        folder = self.settings.digest.markdown_dir.strip()
        return MarkdownDigestSink(Path(folder).expanduser()) if folder else None

    def dashboard_app(self):
        from mailwarden.delivery.dashboard.app import DashboardDeps, create_app

        # Open once to create the DB/key if needed, then reuse the key for per-request connections.
        self.repository().close()
        key = self.secrets.get(SecretKeys.db_key(self.user_id)) or ""
        path = self.home / DB_RELATIVE_PATH

        def rules_summary() -> dict[str, dict[str, list[str]]]:
            rules = self.rules()
            out: dict[str, dict[str, list[str]]] = {}
            for table, kind in ((rules.domains, "domains"), (rules.addresses, "senders")):
                for entry, tier in sorted(table.items()):
                    out.setdefault(tier.value, {"domains": [], "senders": []})[kind].append(entry)
            return out

        deps = DashboardDeps(
            user_id=self.user_id, port=self.settings.dashboard.port, secrets=self.secrets,
            repo_factory=lambda: SQLCipherRepository(path, key), accounts=self.accounts,
            rules_summary=rules_summary, backend_description=self.backend_description(),
            outbound_hosts=sorted(self.session.allowed), digest_times=self.settings.digest.times,
            job_keywords=self.settings.job_alerts.target_keywords,
            job_locations=self.settings.job_alerts.target_locations,
        )
        return create_app(deps)

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
