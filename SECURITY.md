# Security

mailwarden is designed with two goals:

- The parts of your email that matter most (OTPs, banking, ID documents, account
  security) never leave your machine.
- Nothing it stores or logs is useful to someone who steals your disk.

## Threat model in brief

| Threat | Defence |
| --- | --- |
| A cloud LLM seeing sensitive mail | A local, fail-closed sensitivity gate. Sensitive mail never reaches any LLM, and everything else is redacted first |
| Malicious email content (prompt injection, crafted HTML, ReDoS) | Email text is treated as data: nonce-delimited prompts, strict output schemas, no tools, linear-time parsing |
| Disk theft or other local users | Secrets only in the OS keyring, an SQLCipher-encrypted database with no bodies or subjects, owner-only file modes |
| Unexpected network traffic | One host allowlist enforced in code, with TLS always verified and proxies ignored. No telemetry |
| Web pages and other local processes reaching the dashboard | Bound to 127.0.0.1, with a Host check, cookie auth, CSRF tokens and a strict CSP with no scripts |
| Too much access at Google | Exactly `gmail.readonly`. Broader grants are revoked and refused |

Out of scope: malware running as your user, which can read the keyring just as
mailwarden does, and the security of Google's and Groq's own services.

## What leaves the machine

Every outbound request uses one of two HTTP sessions in
`mailwarden/security/net.py`.

The **main session** may contact only the hosts in the table below. A request to any
other host fails before a connection is opened. TLS verification cannot be turned
off, and proxy environment variables are ignored. `tests/test_security_doc.py` fails
if this table and the code disagree.

<!-- allowlist:start -->
| Host | When | What is sent |
| --- | --- | --- |
| `accounts.google.com` | `add-account` (in your browser) | OAuth consent; scope `gmail.readonly` only |
| `oauth2.googleapis.com` | always | Refresh token → short-lived access token; token revocation on `forget-account` |
| `gmail.googleapis.com` | always | Read-only API calls (profile, history, message list, message get). No attachment downloads, no writes |
| `127.0.0.1` | `[llm] backend = "ollama"` | Local Ollama: the same requests as Groq below. Stays on this machine |
| `graph.microsoft.com` | `[outlook] enabled = true` | Reserved for read-only Outlook (`Mail.Read`). The Outlook provider is not implemented yet |
| `login.microsoftonline.com` | `[outlook] enabled = true` | Reserved for Microsoft OAuth. Not implemented yet |
| `boards-api.greenhouse.io` | `[job_alerts] jd_auto_fetch = true` (default) | GET of one public job posting, for candidate jobs hosted on Greenhouse. No cookies, no tracking links |
| `api.lever.co` | `[job_alerts] jd_auto_fetch = true` (default) | GET of one public job posting (Lever) |
| `api.eu.lever.co` | `[job_alerts] jd_auto_fetch = true` (default) | GET of one public job posting (Lever, EU) |
| `api.ashbyhq.com` | `[job_alerts] jd_auto_fetch = true` (default) | GET of a company's public job board (Ashby) |
| `api.groq.com` | `[groq] enabled = true` | Redacted text of SAFE mail for classification and job-list extraction, and job text plus a profile summary for fit scores (see below). Never SENSITIVE mail. Also `GET /models` to validate the key |
<!-- allowlist:end -->

The **job-page session** is separate, and only the opt-in fetch buttons use it (see
[Job descriptions](#job-descriptions)). It has its own short list of job sites and
stricter rules.

No telemetry, analytics or update checks exist.

### What the LLM receives

The same three kinds of request go to Groq, or to Ollama when that is the backend:

1. **Email classification.** One request per SAFE email that isn't labelled by rule.
   It contains the redacted text that `mailwarden dry-run` shows under "would send to
   LLM": the sender's domain, a redacted subject, and up to `llm.max_body_chars`
   redacted body characters.
2. **Job-list extraction.** Used only when local parsing finds no jobs in a SAFE
   job-alert email. It contains the redacted email plus numbered link texts with
   **domains only** (see [Job alerts](#job-alerts)).
3. **Fit scoring.** One request per candidate job. It contains the job and a summary
   of `profile.yaml` (see [Fit scores](#fit-scores)).

### About Groq (the default backend)

Groq's documentation (checked 2026-09-30) says it does not retain inference data by
default, but may log inputs and outputs for up to 30 days for reliability or abuse
investigation. **Turn on Zero Data Retention** (Groq console → Settings → Data
Controls) to disable that logging.

Keep the Groq organisation on the free tier with no billing method, so usage cannot
incur charges. Calls are paced locally by these settings:

- `llm.max_llm_calls_per_minute` (default 6)
- `llm.max_llm_tokens_per_minute` (default 7000), enforced with a token bucket
- `llm.max_llm_calls_per_run` (default 150), a cap per run

Work that doesn't fit stays pending for the next run. The API key is stored only in
the OS keyring (`mailwarden set-groq-key`, hidden input).

`mailwarden doctor --llm` sends one hard-coded synthetic email (no real mail) to
check that the backend works.

### Prompt-injection defences

Email text, job text and job pages are untrusted.

- The system prompt tells the model that the text is data, and that any instructions
  in it must be ignored.
- The text is wrapped in delimiters carrying a random per-request nonce, so it cannot
  forge the closing tag.
- Output is pinned with strict structured outputs (a JSON schema), then validated
  again locally by a strict pydantic model that rejects extra keys.
- Invalid output is retried once. After that, the message is stored as
  "unclassified", or the job is left unscored.
- Redaction placeholders that the model echoes back ([LINK:...], [NUM], ...) are
  removed from stored text.
- Fit scores are clamped to the local caps, and project names must match your real
  projects.

The code never acts on model output beyond storing these fields. There are no tools,
no link fetches and no follow-up requests.

## The sensitivity gate

Before any LLM is involved, every message goes through a purely local gate
(`mailwarden/core/sensitivity_gate.py`). It marks mail SENSITIVE if either of these
is true:

- The sender is in the SENSITIVE tier.
- The sender name, subject or body match patterns for any of these: OTPs and
  verification codes, 2FA, "do not share", password resets, login and new-device
  alerts, transactions, debits and credits, statements, UPI, IFSC, account and card
  numbers, KYC, PAN, Aadhaar, and tax and government IDs.

Text is normalised first to defeat obfuscation: NFKC normalisation, zero-width and
bidi characters removed, and Cyrillic and Greek look-alikes folded.

Some rules are tuned so that generic job-portal footers don't hold job mail:

- `do_not_share` fires only when share, forward or disclose is within about 6 words
  of OTP, code, password, PIN or CVV.
- An Aadhaar number must pass the Verhoeff checksum and have "Aadhaar" within about
  50 characters.
- A PAN (`[A-Z]{5}[0-9]{4}[A-Z]`) must have the word PAN nearby.

**Hard and soft rules.** HARD rules always hold, whatever else is true. They cover:

- OTP, verification code, passcode, and a code next to a number
- transactions, debited/credited, account numbers, card endings
- an Aadhaar number (Verhoeff-valid, with the word nearby) and a PAN (strict format,
  with the word nearby)
- IFSC codes, seed phrases, and Hindi OTP/banking terms
- every error or uncertainty
- security alerts from account-security senders, and the government and
  account-security sender tiers

SOFT rules cover mentions rather than secrets:

- "password", and "do not share/forward" footers
- statements, UPI/IFSC words, KYC/PAN/Aadhaar words, banking terms, tax/ID words
- a bank-brand display name, and the bank/payments sender tier
- security-alert wording from any sender that isn't an account-security sender

A hold made **only** of SOFT rules is waived when the mail carries a strong
recruiting marker. A marker is either of these:

- an ATS relay (SmartRecruiters, Greenhouse, Lever, Ashby, Workday,
  jobs2web/SuccessFactors, iCIMS), as the sender domain or in the footer
- a recruiting phrase ("application received", "thank you for applying", "hiring
  team", ...)

For a bank/payments sender, the marker must be an ATS relay or a phrase in the
**subject**, because bank marketing footers often mention careers. Waived mail is
then redacted and classified like any other SAFE mail.

**Recruiting overrides (sender rules only).** A recruiting subdomain (`careers.`,
`recruitment.`, `talent.`, `jobs.` ...) of a SENSITIVE company domain is treated as
PRIORITY. A recruiting display name on such a domain only removes the sender-based
hold. Account-security senders and exact-address rules are never overridden, and
content rules always apply. Display names are easy to forge, so a forged "Careers"
name can get past the sender tier but not past the content rules.

**Held-back job mail.** Mail from a PRIORITY or recruiting sender that is held as
SENSITIVE still never reaches an LLM. Instead, local deterministic rules extract a
company (from the sender name or domain) and a stage (from subject keywords). Only
these values are stored:

- the company and the stage
- a friendly reason (e.g. "Contains a verification code")
- the sender display name, the time and the account

The subject itself is never stored or shown. This metadata can update the
applications table and trigger a notification such as "Amex · assessment · needs
your attention".

**The gate fails closed.** Each of these counts as SENSITIVE: a gate error, a
sender-rules error, a redaction error, an unparseable body and an unparseable sender.

SENSITIVE mail is never passed to any LLM, and its body and subject are never stored
or displayed. The only code path that calls an LLM for mail
(`Pipeline.classify_safe`) refuses anything not marked SAFE.
`tests/test_zero_llm_sensitive.py` asserts zero LLM calls and zero network calls for
a set of realistic Indian bank, UPI, OTP, login-alert, KYC and tax emails. It runs on
every test run, and a skip is reported as a failure.

`mailwarden regate` re-checks stored mail with the current rules. It uses no LLM.
With `--apply`, it reprocesses only the messages whose decision changed.

## Redaction

Some SAFE mail is classified by local rules with no LLM call:

- social notifications (Instagram, Facebook, WhatsApp, X)
- job-board alert senders (the `job_alert` tier)
- non-PRIORITY mail carrying `List-Unsubscribe` or `Precedence: bulk`

All other SAFE mail is redacted before classification, in this order:

1. Newsletter and legal footers are dropped (unsubscribe, privacy policy, "you are
   receiving this" and similar), as is LinkedIn's "This email was intended for ..."
   line.
2. These are removed: email addresses, phone numbers, every run of 4 or more digits,
   URLs (reduced to `[LINK:domain]`), and anything resembling a token, key, password
   or ID number.
3. The text is cut to the subject plus the first `llm.max_body_chars` (default 1500)
   characters of the body.

Names, employers and colleges are deliberately not redacted, because classification
needs them. The sender's domain is kept; the sender's address and name are not.
`mailwarden dry-run` prints this exact text.

## Robustness against crafted mail

The pattern-matching code is written to run in linear time:

- Patterns are anchored at token boundaries.
- Redaction only processes the slice of text that could be sent.
- The HTML converter uses a counter instead of rescanning.

HTML nested more than 2,000 levels deep is treated as unparseable, which holds the
message (fail closed). `tests/test_redos.py` checks every text-processing function
against 100,000-character hostile inputs on every test run.

## Job alerts

Job-alert emails (SAFE only) are split into individual jobs locally, by parsing
"View job" blocks and job links. If that finds nothing, the LLM gets the redacted
email plus a numbered list of link texts and **domains only**
(`[L3] Backend Intern (internshala.com)`). The model answers with link numbers, which
are mapped back to the real URLs locally. Real URLs often carry tracking tokens, and
they never leave the machine.

Jobs are stored in the encrypted database. The dashboard only renders `http(s)`
links. At most one "N new jobs scored 7+" notification is sent per day.

### Your profile

`profile build` reads your CV (PDF) and project notes (Markdown) from
`<home>/profile/` locally, with no network access, and writes `<home>/profile.yaml`.
It refuses to write the file if the result would contain an email address, a phone
number, a link or your name. The CV and project files are never sent anywhere. Only
the summary described under [Fit scores](#fit-scores) is.

### Job descriptions

Job descriptions (JDs) make fit scores meaningful. They come from three places, and
none of them uses anything from your mailbox beyond the job's own link.

1. **Automatic (`[job_alerts] jd_auto_fetch = true`, the default).** This covers only
   candidate jobs (those passing the prefilter) whose link is on **Greenhouse, Lever
   or Ashby**. The job's public posting is read from those companies' job-board APIs,
   which are the fixed hosts in the table above. There are no cookies and no tracking
   links. At most `max_jd_fetches_per_run` are fetched per run, paced, and results
   are cached for 7 days.
2. **Buttons (`[job_alerts] jd_button_fetch = true`, off by default).** "Fetch job
   description" and "Fetch JDs for top 10" on the Job alerts page run only when you
   click them. They use the separate job-page session, which may contact only these
   sites and their subdomains:
   <!-- jd-fetch-sites:start -->
   `greenhouse.io`, `lever.co`, `ashbyhq.com`, `myworkdayjobs.com`, `myworkdaysite.com`, `smartrecruiters.com`, `successfactors.com`, `successfactors.eu`, `sapsf.com`, `sapsf.eu`, `jobs2web.com`
   <!-- jd-fetch-sites:end -->
   The rules for this session are:
   - Every hop, redirects included, must be on that list.
   - Requests use HTTPS on the default port only, and never go to IP addresses.
   - Hosts must resolve to public addresses, and the address actually connected to is
     checked too.
   - Requests are GET only, with no cookies or credentials.
   - Tracking parameters (`utm_*`, `trk`, `gh_src` ...) are removed.
   - Responses are capped at 2 MB.
3. **Paste.** For LinkedIn, Naukri, Indeed, Internshala, click-tracker links and any
   other site, the card explains why the JD can't be fetched and offers a "Paste JD"
   box. Pasted text (at most 120 KB) is stored and scored like a fetched JD.

Unsubscribe, preference and feedback links are never followed. JD text is untrusted:
it is cleaned (links removed, hidden page text dropped), stored in the encrypted
database, and wrapped as data in the scoring prompt.

### Fit scores

`mailwarden run` and `mailwarden jobs score` send one request per candidate job to
the configured LLM, at most `max_scores_per_run` per run. Each request contains:

- the job: title, company, location, listing details, and the JD if available, with
  links removed
- a profile summary from `profile.yaml`: weighted skills, seniority, experience,
  education, experience summary, highlights, target roles, and each project's name,
  skills and one-line description

It never contains contact details. Scores only order jobs; nothing is hidden.

## OAuth scopes

- Gmail: exactly `https://www.googleapis.com/auth/gmail.readonly`. Every token
  response is checked. A broader or missing scope stops the program, and a broader
  grant at sign-in is revoked immediately. `include_granted_scopes` is never sent.
- The OAuth flow uses PKCE and a random `state`, with the redirect bound to
  `127.0.0.1` on a random port.

## What is stored locally

All paths are inside the mailwarden home (mode 700) unless noted otherwise.

| Item | Where |
| --- | --- |
| OAuth refresh tokens, OAuth client, account list | OS keyring (service `mailwarden`) |
| Database key (random 256-bit), Groq API key, dashboard token, hashed one-time sign-in codes | OS keyring |
| Settings and sender rules (non-secret) | `config.toml` and `sender_rules.yaml` (mode 600), with `.bak` copies after `init --reset-rules` |
| Message metadata and classifications | SQLCipher-encrypted database `data/mailwarden.db` (mode 600). No bodies and no subjects. SENSITIVE rows keep only the sender display name, received time, account and message id |
| Applications (company, role, stage, history, company domains) | The encrypted database |
| Jobs: postings, links, sources and "also on" sightings, JDs, fit scores, dismissals, calibration labels, recall-audit answers | The encrypted database |
| Database backups made before migrations | `data/mailwarden.db.<tag>.bak` (mode 600, still encrypted) |
| Your CV and project notes | `profile/` (you copy them there and `chmod 600` them) |
| Profile summary | `profile.yaml` and `profile.yaml.bak` (plaintext, with no contact details) |
| Matching policy | `config/matching.yaml` (mode 600; plaintext preferences, no personal details) |
| Logs | `logs/` (mode 600, scrubbed as described under [Logging](#logging)) |
| Single-window hand-off socket and the run lock | `app.sock` (mode 600) and `jobs.lock` |
| Background-job definitions | `schedule/` |
| Optional digest copy | `[digest] markdown_dir`, off by default (see [Digest files](#digest-files)) |

Access tokens are held only in memory. Email bodies and subjects exist only in memory
while a message is processed, and are cleared right after. `forget-account` revokes
the token and deletes that account's rows, followed by `VACUUM` with `secure_delete`
on.

mailwarden refuses to start if config files are group- or world-accessible, or if the
keyring backend is not a real OS keyring.

## Local dashboard

- It listens on `127.0.0.1` only. Any other `dashboard.host` is refused by the config,
  and again when the server starts.
- The `Host` header must be `127.0.0.1:<port>` or `localhost:<port>`, which blocks
  DNS rebinding.
- Only a few paths are public: the sign-in page, the stylesheet, the logo images, the
  favicon and the bundled font files. Every other page needs a cookie holding a random
  per-install token from the OS keyring. The cookie is HttpOnly, SameSite=Strict and
  lasts 90 days.
- The cookie is set via a one-time sign-in link that expires in 10 minutes. Only the
  SHA-256 hash of the link code is stored, in the keyring.
- Every state-changing request is a POST that must carry a CSRF token: Done, Dismiss,
  Sign out, Fetch job description, Fetch JDs for top 10, and Paste JD. If the request
  has an `Origin` header, it must be the dashboard's own. Request bodies are size
  limited.
- Every response carries a Content-Security-Policy that allows no scripts at all:
  `default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self';
  form-action 'self'; frame-ancestors 'none'; base-uri 'none'`.
- Every response also carries `X-Frame-Options: DENY`, `nosniff`,
  `Cache-Control: no-store`, `Referrer-Policy: same-origin`, and COOP/CORP headers.
- All pages are server-rendered with auto-escaping, and no assets load from other
  hosts. The API docs routes are disabled. Access logs are off, so sign-in links are
  never logged.
- Sensitive mail appears only as counts by sender name. Held-back job mail shows the
  company, the stage and a friendly reason, never the subject.
- Your browser follows "Open in Gmail" and job links. mailwarden itself makes no
  request to them.

## Desktop window (macOS)

`mailwarden app` shows the dashboard in a native WebKit window (pywebview).

- The window loads only `http://127.0.0.1:<port>`.
- It exposes no JavaScript bridge to Python, and developer tools and downloads are
  off.
- It runs in private mode, so no cookies or site data are written to disk. Each launch
  signs in with a fresh one-time code.
- Links that open in a new tab go to the default browser.
- The dashboard's security headers and CSP apply unchanged.

The app registers the `mailwarden://` link type, so notification clicks reach the
single open window. Such a link, from a notification or from any web page, can only
navigate the window to a dashboard path such as `/apply`, `/jobs?match=1` or
`/i/<account>/<id>`. Paths are checked against a strict pattern (letters, digits,
`/`, `_`, `-` and a simple query string, at most 200 characters). Navigation is a
plain GET, so state changes still need a CSRF-protected click.

Later launches hand over to the open window through a Unix socket in the mailwarden
home (mode 600, owner-only). The app bundle runs an ad-hoc-signed copy of the Python
interpreter, so macOS identifies the window and its Keychain access as the mailwarden
app ("mailwarden-python").

## Notifications

Notifications are local. They show only the company, stage and deadline, "needs your
attention" for held-back job mail, or a count ("N new jobs scored 7+"). They never
show a summary, a subject or link text.

- **macOS, with the app installed:** a helper inside the app bundle posts the
  notification as mailwarden (NSUserNotificationCenter). The notification carries
  only a validated dashboard path, which the app opens when you click it.
- **macOS, without the app:** `terminal-notifier` or `osascript`. Text is passed as a
  program argument and never inserted into a script. A click opens a
  `http://127.0.0.1:<port>/...` dashboard URL.
- **Linux and Windows:** `desktop-notifier`.

## Digest files

The digest is stored in the encrypted database. The optional Markdown copy
(`[digest] markdown_dir`, off by default) is **plaintext**: one-line summaries and
sensitive-sender counts, with no links or subjects. Files are mode 600 in a mode-700
folder. Leave it off if disk access is part of your threat model.

## Scheduled jobs

All generated jobs (launchd, systemd and Task Scheduler) run as your user with no
extra privileges. The launchd and systemd jobs run with `umask 077`, so their log
files are private, and the systemd units also set `NoNewPrivileges`. A lock file stops
two syncs from running at once.

## Logging

Logs never include bodies, subjects, tokens or keys. A scrubbing filter on the log
handler also masks the following, including inside tracebacks:

- email addresses
- runs of 4 or more digits
- bearer and OAuth tokens, and JWTs
- `key=value` secrets
- long high-entropy strings

## Supply chain

Dependencies are pinned with hashes in `requirements.lock` and
`requirements-dev.lock`, and `make install` installs them with hash checking.
`make audit` runs `pip-audit` on the lockfile and `bandit` on the code.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository.
