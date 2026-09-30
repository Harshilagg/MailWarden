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

> Status: phase 4 of 5 (delivery). See `SECURITY.md`.

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

Free-tier limits are 8,000 tokens/min and 1,000 requests/day, about 6 emails per
minute. mailwarden paces itself with a local token bucket
(`[llm] max_llm_calls_per_minute = 6`) and caps each run
(`max_llm_calls_per_run = 150`). Anything it can't finish is kept as *pending*
and retried on the next run. The model is set by `[groq] model`. The first
run only backfills `[gmail] full_sync_days` (7) days.

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
| `mailwarden promote <address-or-domain> <tier>` | Move a sender to `priority`, `sensitive`, `ignore`, `job_alert` or `default` |
| `mailwarden forget-account <n>` | Revoke token at Google, delete it from the keyring, delete the account's stored data |

| `mailwarden dashboard [--open]` | Start the local dashboard on `127.0.0.1:8765` and print a one-time sign-in link |
| `mailwarden open [--print-only]` | Open a fresh one-time sign-in link to the running dashboard |
| `mailwarden digest` | Build the digest now (shown on the dashboard; optional Markdown copy) |
| `mailwarden schedule [--platform macos\|linux\|windows]` | Generate launchd / systemd / Task Scheduler files to review and install |

Add `--quiet` before any command for warnings-only output (used by scheduled jobs).

## Dashboard

```sh
.venv/bin/mailwarden dashboard --open
```

- **Urgent**: job mail that needs you, soonest deadline first, including held-back
  job mail ("Amex · assessment · needs your attention"). Each item has
  **Open in Gmail** and **Done**.
- **Applications**: a board of companies by stage, with each application's history.
- **Digest**: the latest digest, grouped by category, with one-line summaries.
- **Sensitive**: counts by sender only.
- **Settings**: the classifier, allowed outbound hosts, accounts and sender tiers (read-only).

The dashboard only listens on 127.0.0.1 and has no external assets or JavaScript.
Signing in uses a one-time link (valid 10 minutes). After that a cookie keeps you
signed in for 90 days. If you're signed out, run `mailwarden open`.

## Notifications

Job mail that needs action (an assessment, interview or offer, or an action for a
company you're tracking or a priority sender) triggers a desktop notification
showing only the company, stage and deadline. Clicking it opens the entry on the dashboard.

- **macOS**: `brew install terminal-notifier` (free). Without it, mailwarden
  falls back to `osascript`, which shows the notification but clicking it does
  nothing. The `desktop-notifier` library can't be used with Homebrew's
  unsigned Python.
- **Linux / Windows**: uses `desktop-notifier`.
- Configure under `[notifications]` in `config.toml`, or set `enabled = false`.

## Digest

The scheduled digest runs at `[digest] times` (default 08:00 and 18:00) and covers
the mail since the previous digest. To also write a Markdown copy, set
`[digest] markdown_dir`. It's plaintext, created mode 600.

## Scheduling

```sh
.venv/bin/mailwarden schedule          # writes files to <home>/schedule/<platform>/ and prints install commands
```

- **macOS**: launchd agents that sync every 10 minutes, build the digest at your
  digest times, and keep the dashboard running. They use `StartCalendarInterval`,
  so a run missed while the laptop sleeps happens on wake (cron would skip it).
- **Linux**: systemd user timers with `Persistent=true`.
- **Windows**: Task Scheduler XML with "run as soon as possible after a missed start".

Logs go to `<home>/logs/` (mode 600).

## Tuning sender rules

`sender_rules.yaml` (in the mailwarden home) has three tiers:

- **priority**: job mail (ATS and assessment platforms are pre-seeded).
- **sensitive**: banks, UPI/payment apps, cards, brokers, tax/government,
  account-security senders. Never sent to any LLM.
- **ignore**: senders you never want processed; only counted.
- **job_alert**: job-board alerts and matches (LinkedIn job alerts, Indeed,
  Naukri, foundit, Internshala). Labelled by rule, never notify, digest only.

A recruiting subdomain of a sensitive company (e.g. `recruitment.americanexpress.com`)
counts as priority. Job mail that the gate holds back is still surfaced, but only
as "Company · stage · needs your attention", with no subject or content, and it
never goes to the LLM.

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
