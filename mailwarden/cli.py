"""mailwarden command line."""

from __future__ import annotations

import argparse
import getpass
import logging
import re
import sys
from pathlib import Path

from mailwarden import __version__
from mailwarden.app import App, build_app
from mailwarden.config import RULES_FILE, ConfigError, home_dir, init_home
from mailwarden.core.classify.base import BackendError
from mailwarden.core.models import SLUG_PATTERN, Account, ProviderKind, Tier
from mailwarden.core.runner import Runner
from mailwarden.storage.sqlite_store import StoreError
from mailwarden.core.sender_rules import RulesError, SenderRules, normalise_entry, set_entry_tier
from mailwarden.dryrun import run_dry_run
from mailwarden.security.fs import check_private, write_private
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
    created = init_home(home, reset_rules=args.reset_rules)
    print(f"mailwarden home: {home}")
    if args.reset_rules:
        print(f"  previous rules (if any) saved as {RULES_FILE}.bak")
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
    repo = app.repository()
    try:
        repo.delete_account_data(app.user_id, account.name)
    finally:
        repo.close()
    app.accounts.remove(app.user_id, account.name)
    print(f"Revoked the token for {account.name!r}, deleted it from the keyring, and deleted its stored data.")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    app = build_app()
    s = app.settings
    print(f"home:            {app.home} (permissions ok)")
    print(f"keyring backend: {app.secrets.backend_name}")
    print(f"llm backend:     {app.backend_description()}")
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
    if args.llm:
        failures += _doctor_llm(app)
    return 1 if failures else 0


_SYNTHETIC_EMAIL = (
    "From domain: example-careers.com\nSubject: Interview invitation: Backend Engineer at Example Corp\n\n"
    "Hi, thanks for applying. We would like to invite you to a 45 minute technical interview. "
    "Please book a slot by Oct 10 using [LINK:calendly.com]."
)


def _doctor_llm(app: App) -> int:
    """Check the backend with a hard-coded synthetic email. No real mail is read or sent."""
    try:
        backend = app.llm_backend()
        backend.check()
        result = backend.classify(_SYNTHETIC_EMAIL)
    except BackendError as e:
        print(f"llm check:       FAILED: {e}")
        return 1
    print(f"llm check:       ok (synthetic email -> {result.category}/{result.stage}, action_required={result.action_required})")
    return 0


def cmd_dry_run(args: argparse.Namespace) -> int:
    if not 1 <= args.last <= 500:
        raise UsageError("--last must be between 1 and 500")
    app = build_app()
    accounts = app.accounts.list(app.user_id)
    if args.account:
        accounts = [a for a in accounts if a.name == args.account]
        if not accounts:
            raise UsageError(f"no account named {args.account!r}")
    if not accounts:
        raise UsageError("no accounts; run add-account first")
    llm = None
    if args.with_llm:
        llm = app.llm_backend()
        llm.check()
        log.info("LLM backend: %s", app.backend_description())
    run_dry_run(accounts, app.provider_for, app.pipeline(llm), last=args.last, out=sys.stdout, summary_only=args.summary)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    app = build_app()
    accounts = app.accounts.list(app.user_id)
    if not accounts:
        raise UsageError("no accounts; run add-account first")
    llm = app.llm_backend()
    llm.check()  # fail fast: missing key, bad model, server down
    log.info("LLM backend: %s", app.backend_description())
    repo = app.repository()
    try:
        stats = Runner(
            user_id=app.user_id,
            repo=repo,
            rules=app.rules(),
            llm=llm,
            provider_for=app.provider_for,
            max_body_chars=app.settings.llm.max_body_chars,
            max_per_run=app.settings.gmail.max_messages_per_run,
        ).run(accounts)
    finally:
        repo.close()
    print(
        f"processed {stats.new} new: {stats.classified} classified by LLM, {stats.rule_classified} by rule, "
        f"{stats.unclassified} unclassified, {stats.sensitive} sensitive (not processed; {stats.held_jobs} of "
        f"them job mail surfaced), {stats.ignored} ignored; {stats.job} job emails; "
        f"{len(stats.alerts)} would notify; {stats.pending} pending for next run"
    )
    if stats.accounts_failed:
        print(f"accounts failed: {', '.join(stats.accounts_failed)}", file=sys.stderr)
        return 1
    return 0


def cmd_set_groq_key(args: argparse.Namespace) -> int:
    app = build_app()
    key = getpass.getpass("Groq API key (input hidden): ").strip()
    if not key.startswith("gsk_") or len(key) < 20:
        raise UsageError("that does not look like a Groq API key (expected gsk_...)")
    app.secrets.set(SecretKeys.groq_api_key(app.user_id), key)
    print("Stored the Groq API key in the OS keyring.")
    if not app.settings.groq.enabled or app.settings.llm.backend != "groq":
        print("Note: config.toml does not select Groq yet; set [llm] backend = \"groq\" and [groq] enabled = true.")
    return 0


def cmd_promote(args: argparse.Namespace) -> int:
    tier = Tier(args.tier)
    entry = normalise_entry(args.sender)
    path = home_dir() / RULES_FILE
    check_private(path)
    text = path.read_text("utf-8")
    current = SenderRules.from_yaml(text).tier_of_entry(entry)
    if current == tier:
        print(f"{entry} is already {tier}")
        return 0
    if current == Tier.SENSITIVE and not args.yes:
        answer = input(
            f"{entry} is SENSITIVE. Moving it to {tier} lets its mail reach the LLM when the "
            "content gate passes it. Type 'yes' to continue: "
        )
        if answer.strip().lower() != "yes":
            print("unchanged")
            return 1
    write_private(path, set_entry_tier(text, entry, tier))
    print(f"{entry}: {current} -> {tier}")
    return 0


def _not_yet(phase: int):
    def run(args: argparse.Namespace) -> int:
        raise UsageError(f"`{args.command}` is implemented in phase {phase}")

    return run


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mailwarden", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    i = sub.add_parser("init", help="create the config dir and default config")
    i.add_argument("--reset-rules", action="store_true", help="replace sender_rules.yaml with the shipped seed (backup kept)")
    i.set_defaults(func=cmd_init)

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
    d.add_argument("--llm", action="store_true", help="also test the LLM backend with a synthetic (fake) email")
    d.set_defaults(func=cmd_doctor)

    sub.add_parser("run", help="one sync + classify pass").set_defaults(func=cmd_run)
    sub.add_parser("set-groq-key", help="store the Groq API key in the OS keyring (hidden input)").set_defaults(
        func=cmd_set_groq_key
    )
    sub.add_parser("digest").set_defaults(func=_not_yet(4))
    sub.add_parser("dashboard").set_defaults(func=_not_yet(4))
    dr = sub.add_parser("dry-run", help="show tiers, gate decisions and redacted LLM text; sends/stores nothing")
    dr.add_argument("--last", type=int, default=50, help="messages per account (default 50)")
    dr.add_argument("--account", help="only this account")
    dr.add_argument("--summary", action="store_true", help="print only the summary, no message text")
    dr.add_argument("--with-llm", action="store_true", help="also classify SAFE mail with the configured backend")
    dr.set_defaults(func=cmd_dry_run)
    pr = sub.add_parser("promote", help="move a sender address or domain to a tier")
    pr.add_argument("sender", help="address (a@b.com) or domain (b.com)")
    pr.add_argument("tier", choices=["priority", "sensitive", "ignore", "job_alert", "default"])
    pr.add_argument("--yes", action="store_true", help="skip confirmation when demoting a SENSITIVE sender")
    pr.set_defaults(func=cmd_promote)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    install_logging(logging.DEBUG if args.verbose else logging.INFO)
    try:
        return args.func(args)
    except (UsageError, ConfigError, RulesError, StoreError, BackendError, InsecurePermissions, InsecureKeyringError, EgressBlocked, ProviderError, ValueError) as e:
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
