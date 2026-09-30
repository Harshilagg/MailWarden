# mailwarden

Privacy-first, local-first email triage. mailwarden reads your mailboxes
**read-only**, makes sure job-application mail is never missed, summarises the
rest into a digest, and shows everything on a local dashboard.

- Classification uses **Groq's free tier** (`openai/gpt-oss-20b`), which only ever
  receives redacted text of non-sensitive mail. A fully local Ollama backend is
  available as an alternative.
- OTPs, bank/UPI/card mail, password resets, login alerts and ID/KYC/tax mail
  are caught by a local gate and **never** reach any LLM.
- OAuth tokens and keys live only in your OS keyring.

> Status: phase 3 of 5 (classification and storage). See `SECURITY.md`.

## Requirements

- Python 3.11+ (3.13 recommended) and [uv](https://docs.astral.sh/uv/)
- macOS, Linux or Windows with a working OS keyring
  (macOS Keychain, Secret Service / KWallet, Windows Credential Manager)
- A free [Groq](https://console.groq.com) API key (or, alternatively, a local [Ollama](https://ollama.com))

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

## Groq API key (free)

1. Sign up at <https://console.groq.com>. Don't add a billing method, so the org
   stays on the free tier and can't be charged.
2. **Settings → Data Controls**: enable **Zero Data Retention**.
3. **API Keys → Create API key**, then:

```sh
.venv/bin/mailwarden set-groq-key      # hidden prompt; stored in the OS keyring
.venv/bin/mailwarden doctor --llm      # checks the key with a synthetic email
```

Free-tier limits for `openai/gpt-oss-20b` are 30 requests/min and 1,000/day.
mailwarden spaces requests about 2.5 s apart and waits on rate limits.
Anything it can't finish is kept as *pending* and retried on the next run.

To stay fully local instead, install Ollama, `ollama pull qwen2.5:3b`, and set
`[llm] backend = "ollama"`.

## Commands

| Command | What it does |
| --- | --- |
| `mailwarden init [--reset-rules]` | Create config dir and default config; `--reset-rules` restores the seeded `sender_rules.yaml` (old file kept as `.bak`) |
| `mailwarden add-account --provider gmail --name <n>` | OAuth sign-in, token stored in keyring |
| `mailwarden accounts` | List accounts (addresses masked) |
| `mailwarden doctor [--sync] [--llm]` | Check keyring, permissions, allowlist, granted scopes; `--sync` counts recent messages without showing content; `--llm` tests the backend with a synthetic email |
| `mailwarden set-groq-key` | Store the Groq API key in the keyring (hidden input) |
| `mailwarden run` | One sync + classify pass; stores metadata and classifications in the encrypted DB |
| `mailwarden dry-run [--last N] [--account n] [--summary] [--with-llm]` | Show, per message, the tier, gate decision and the exact redacted text that *would* go to the LLM. Stores and notifies nothing; sends nothing unless `--with-llm` is given, in which case it also prints each classification and whether a notification would fire |
| `mailwarden promote <address-or-domain> <tier>` | Move a sender to `priority`, `sensitive`, `ignore` or `default` |
| `mailwarden forget-account <n>` | Revoke token at Google, delete it from the keyring, delete the account's stored data |

`digest`, `dashboard` and notifications arrive in phase 4.

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
