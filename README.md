# mailwarden

Privacy-first, local-first email triage. mailwarden reads your mailboxes
**read-only**, makes sure job-application mail is never missed, summarises the
rest into a digest, and shows everything on a local dashboard.

- Classification runs on a **local** model (Ollama) by default. It is free, and
  nothing leaves your machine.
- OTPs, bank/UPI/card mail, password resets, login alerts and ID/KYC/tax mail
  are caught by a local gate and **never** reach any LLM.
- OAuth tokens and keys live only in your OS keyring.

> Status: phase 2 of 5 (safety core). See `SECURITY.md`.

## Requirements

- Python 3.11+ (3.13 recommended) and [uv](https://docs.astral.sh/uv/)
- macOS, Linux or Windows with a working OS keyring
  (macOS Keychain, Secret Service / KWallet, Windows Credential Manager)
- [Ollama](https://ollama.com) (from phase 3)

## Install

```sh
make install          # creates .venv from hash-pinned requirements-dev.lock
.venv/bin/mailwarden init
```

`init` creates the mailwarden home directory (mode 700) containing
`config.toml` and `sender_rules.yaml` (mode 600). The location is
`~/Library/Application Support/mailwarden` on macOS, `~/.config/mailwarden` on
Linux, `%LOCALAPPDATA%\mailwarden` on Windows. Override with `MAILWARDEN_HOME`.

## Create your own Google OAuth client (one time, free)

mailwarden ships no shared client ID. Each user creates their own:

1. Open <https://console.cloud.google.com/>, create a project (e.g. `mailwarden`).
2. **APIs & Services → Library**, enable the **Gmail API**.
3. **APIs & Services → OAuth consent screen** (Google Auth Platform):
   - User type: **External**.
   - App name and support email: anything, your own address.
   - **Data access / Scopes**: add only
     `https://www.googleapis.com/auth/gmail.readonly`.
   - **Audience / Test users**: add every Gmail address you will connect.
4. **Credentials → Create credentials → OAuth client ID**, type **Desktop app**.
   Download the JSON.

Then:

```sh
.venv/bin/mailwarden add-account --provider gmail --name personal \
    --client-secrets ~/Downloads/client_secret_XXXX.json
```

The client is copied into the keyring, so delete the JSON file afterwards.
Later accounts don't need `--client-secrets`.

Your browser opens Google's consent page. Google will warn that the app is
unverified, which is expected for a personal client: choose *Continue*.
mailwarden requests **only** `gmail.readonly`. If a token ever comes back with
any broader scope, mailwarden revokes it and refuses to run.

**Token lifetime note.** While the consent screen's publishing status is
*Testing*, Google expires refresh tokens after 7 days, so you would need to
re-run `add-account` weekly. To avoid that, set the publishing status to
*In production* without submitting for verification. For personal use (fewer
than 100 users) Google allows this; you keep seeing the "unverified app"
warning at sign-in, and tokens no longer expire weekly.

## Commands

| Command | What it does |
| --- | --- |
| `mailwarden init [--reset-rules]` | Create config dir and default config; `--reset-rules` restores the seeded `sender_rules.yaml` (old file kept as `.bak`) |
| `mailwarden add-account --provider gmail --name <n>` | OAuth sign-in, token stored in keyring |
| `mailwarden accounts` | List accounts (addresses masked) |
| `mailwarden doctor [--sync]` | Check keyring, permissions, allowlist, granted scopes; `--sync` counts recent messages without showing content |
| `mailwarden dry-run [--last N] [--account n] [--summary]` | Show, per message, the tier, gate decision and the exact redacted text that *would* go to the LLM. Sends, stores and notifies nothing |
| `mailwarden promote <address-or-domain> <tier>` | Move a sender to `priority`, `sensitive`, `ignore` or `default` |
| `mailwarden forget-account <n>` | Revoke token at Google, delete it from keyring |

`run`, `digest` and `dashboard` arrive in later phases.

## Tuning sender rules

`sender_rules.yaml` (in the mailwarden home) has three tiers:

- **priority**: job mail (ATS and assessment platforms are pre-seeded).
- **sensitive**: banks, UPI/payment apps, cards, brokers, tax/government,
  account-security senders. Never sent to any LLM.
- **ignore**: senders you never want processed; only counted.

Domains match their subdomains too; an exact address beats a domain rule.
Workflow:

```sh
mailwarden dry-run --last 100 --summary     # overview: what was held back and why
mailwarden dry-run --last 30                # per-message detail incl. redacted LLM text
mailwarden promote talent@somefintech.com priority   # a recruiter at a sensitive domain
mailwarden promote offers.somestore.com ignore
```

Independently of sender tiers, the **sensitivity gate** inspects the sender name,
subject and body locally and holds back anything that looks like an OTP,
verification code, password reset, login alert, bank/UPI/card transaction,
statement, KYC, PAN, Aadhaar or tax mail. Promoting a sender never bypasses this
content check.

## Development

```sh
make test     # pytest
make lock     # regenerate hash-pinned lockfiles after changing pyproject.toml
```
