"""mailwarden command line."""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path

from mailwarden import __version__
from mailwarden.app import App, build_app
from mailwarden.config import ConfigError, home_dir, init_home
from mailwarden.core.models import SLUG_PATTERN, Account, ProviderKind
from mailwarden.providers.base import ProviderError
from mailwarden.providers.google_oauth import OAuthClient, revoke, run_loopback_flow
from mailwarden.security.fs import InsecurePermissions
from mailwarden.security.log_filter import install_logging, scrub
from mailwarden.security.net import EgressBlocked, RequestException
from mailwarden.security.secrets import InsecureKeyringError, SecretKeys

log = logging.getLogger("mailwarden")


class UsageError(RuntimeError):
    pass


def _mask(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}" if domain else "***"


def cmd_init(args: argparse.Namespace) -> int:
    home = home_dir()
    created = init_home(home)
    print(f"mailwarden home: {home}")
    for p in created:
        print(f"  created {p.name} (mode 600)")
    if not created:
        print("  config already present; nothing changed")
    return 0


def cmd_add_account(args: argparse.Namespace) -> int:
    app = build_app()
    if args.provider != ProviderKind.GMAIL:
        raise UsageError("only --provider gmail is available (Outlook arrives in phase 5)")
    if not re.match(SLUG_PATTERN, args.name):
        raise UsageError("account name must be lowercase letters, digits, '-' or '_' (max 32)")
    if app.accounts.get(app.user_id, args.name):
        raise UsageError(f"account {args.name!r} already exists")

    if args.client_secrets:
        client = OAuthClient.from_client_json(Path(args.client_secrets).read_text("utf-8"))
        app.secrets.set(SecretKeys.oauth_client(app.user_id, ProviderKind.GMAIL), client.to_secret())
        print("Stored the OAuth client in the OS keyring.")
        print(f"You can now delete {args.client_secrets}; mailwarden will not read it again.")
    client = app.google_client()

    grant = run_loopback_flow(client, app.session)
    token_key = SecretKeys.oauth_refresh(app.user_id, args.name)
    app.secrets.set(token_key, grant.refresh_token)
    try:
        draft = Account(user_id=app.user_id, name=args.name, provider=ProviderKind.GMAIL, address="")
        address = app.providers[ProviderKind.GMAIL].profile_address(draft)  # type: ignore[attr-defined]
        app.accounts.add(draft.model_copy(update={"address": address}))
    except Exception:
        app.secrets.delete(token_key)
        revoke(app.session, grant.refresh_token)
        raise
    print(f"Added gmail account {args.name!r} ({_mask(address)}); granted scope: gmail.readonly only.")
    return 0


def cmd_accounts(args: argparse.Namespace) -> int:
    app = build_app()
    accounts = app.accounts.list(app.user_id)
    if not accounts:
        print("No accounts. Add one with: mailwarden add-account --provider gmail --name <name>")
    for a in accounts:
        print(f"{a.name}\t{a.provider}\t{_mask(a.address)}")
    return 0


def cmd_forget_account(args: argparse.Namespace) -> int:
    app = build_app()
    account = app.accounts.get(app.user_id, args.name)
    if account is None:
        raise UsageError(f"no account named {args.name!r}")
    token_key = SecretKeys.oauth_refresh(app.user_id, account.name)
    refresh = app.secrets.get(token_key)
    if refresh and account.provider == ProviderKind.GMAIL:
        revoke(app.session, refresh)
    app.secrets.delete(token_key)
    app.accounts.remove(app.user_id, account.name)
    # Stored message metadata is deleted here once the encrypted DB exists (phase 3).
    print(f"Revoked and deleted the token for {account.name!r} and removed the account.")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    app = build_app()
    s = app.settings
    print(f"home:            {app.home} (permissions ok)")
    print(f"keyring backend: {app.secrets.backend_name}")
    print(f"llm backend:     {s.llm.backend}" + (f" (local, model {s.ollama.model})" if s.llm.backend == "ollama" else " (CLOUD: redacted SAFE text only)"))
    print(f"outbound hosts:  {', '.join(sorted(app.session.allowed))}")
    failures = 0
    for account in app.accounts.list(app.user_id):
        provider = app.provider_for(account)
        try:
            scopes = provider.verify_access(account)
            line = f"account {account.name}: ok, scopes = {', '.join(sorted(scopes))}"
            if args.sync:
                result = provider.list_new(account, None)
                line += f"; {len(result.message_ids)} messages in the last {s.gmail.full_sync_days} days"
            print(line)
        except ProviderError as e:
            failures += 1
            print(f"account {account.name}: FAILED: {e}")
    return 1 if failures else 0


def _not_yet(phase: int):
    def run(args: argparse.Namespace) -> int:
        raise UsageError(f"`{args.command}` is implemented in phase {phase}")

    return run


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mailwarden", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the config dir and default config").set_defaults(func=cmd_init)

    a = sub.add_parser("add-account", help="authorise a mailbox (read-only)")
    a.add_argument("--provider", choices=[k.value for k in ProviderKind], required=True)
    a.add_argument("--name", required=True, help="short label, e.g. personal")
    a.add_argument("--client-secrets", help="Desktop-app OAuth client JSON (first time only)")
    a.set_defaults(func=cmd_add_account)

    sub.add_parser("accounts", help="list accounts").set_defaults(func=cmd_accounts)

    f = sub.add_parser("forget-account", help="revoke and delete an account's token and data")
    f.add_argument("name")
    f.set_defaults(func=cmd_forget_account)

    d = sub.add_parser("doctor", help="check keyring, permissions, allowlist and grants")
    d.add_argument("--sync", action="store_true", help="also count recent messages (no content shown)")
    d.set_defaults(func=cmd_doctor)

    sub.add_parser("run").set_defaults(func=_not_yet(3))
    sub.add_parser("digest").set_defaults(func=_not_yet(4))
    sub.add_parser("dashboard").set_defaults(func=_not_yet(4))
    dr = sub.add_parser("dry-run")
    dr.add_argument("--last", type=int, default=50)
    dr.add_argument("--with-llm", action="store_true")
    dr.set_defaults(func=_not_yet(2))
    pr = sub.add_parser("promote")
    pr.add_argument("sender")
    pr.add_argument("tier")
    pr.set_defaults(func=_not_yet(2))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    install_logging(logging.DEBUG if args.verbose else logging.INFO)
    try:
        return args.func(args)
    except (UsageError, ConfigError, InsecurePermissions, InsecureKeyringError, EgressBlocked, ProviderError, ValueError) as e:
        print(f"mailwarden: {scrub(str(e))}", file=sys.stderr)
        return 2
    except RequestException as e:
        print(f"mailwarden: network error: {type(e).__name__}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception:
        # Tracebacks go through the scrubbing log filter, never raw to stderr.
        log.exception("unexpected error")
        return 1


if __name__ == "__main__":
    sys.exit(main())
