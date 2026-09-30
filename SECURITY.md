# Security

mailwarden is designed so that the parts of your email that matter most
(OTPs, banking, ID documents, account security) never leave your machine, and
so that nothing it stores or logs is useful to someone who steals your disk.

## What leaves the machine

Every outbound request goes through one allowlisted HTTP session
(`mailwarden/security/net.py`). Requests to any other host raise before a
connection is opened. TLS verification cannot be turned off, and proxy
environment variables are ignored. `tests/test_security_doc.py` fails if this
table and the code disagree.

<!-- allowlist:start -->
| Host | When | What is sent |
| --- | --- | --- |
| `accounts.google.com` | `add-account` (in your browser) | OAuth consent; scope `gmail.readonly` only |
| `oauth2.googleapis.com` | always | Refresh token → short-lived access token; token revocation on `forget-account` |
| `gmail.googleapis.com` | always | Read-only API calls (profile, history, message list, message get). No attachment downloads, no writes |
| `127.0.0.1` | `[llm] backend = "ollama"` | Local Ollama: redacted text of SAFE mail. Stays on this machine |
| `graph.microsoft.com` | `[outlook] enabled = true` | Read-only Graph calls, `Mail.Read` (phase 5) |
| `login.microsoftonline.com` | `[outlook] enabled = true` | Microsoft OAuth (phase 5) |
| `boards-api.greenhouse.io` | `[job_alerts] jd_auto_fetch = true` (default) | GET of one public job posting, for candidate jobs hosted on Greenhouse. No cookies, no tracking links |
| `api.lever.co` | `[job_alerts] jd_auto_fetch = true` (default) | GET of one public job posting (Lever) |
| `api.eu.lever.co` | `[job_alerts] jd_auto_fetch = true` (default) | GET of one public job posting (Lever, EU) |
| `api.ashbyhq.com` | `[job_alerts] jd_auto_fetch = true` (default) | GET of a company's public job board (Ashby) |
| `api.groq.com` | `[groq] enabled = true` | One request per SAFE email: redacted text of that email plus a fixed prompt. Never SENSITIVE mail. Also `GET /models` to validate the key |
<!-- allowlist:end -->

No telemetry, analytics or update checks exist.

### About Groq (the default classifier)

With `llm.backend = "groq"`, the redacted text of each SAFE email goes to
Groq. That text is what `mailwarden dry-run` shows under "would send to LLM":
the sender's domain, a redacted subject, and up to `llm.max_body_chars`
redacted body characters. Groq's documentation (checked 2026-09-30) says it
does not retain inference data by default, but may log inputs and outputs for
up to 30 days for reliability or abuse investigation. **Turn on Zero Data
Retention** (Groq console → Settings → Data Controls) to disable that logging.
Keep the Groq organisation on the free tier with no billing method, so usage
cannot incur charges. Calls are paced locally by a token bucket
(`llm.max_llm_calls_per_minute`, default 6) and capped per run
(`llm.max_llm_calls_per_run`, default 150). The rest stays pending for the next
run. The API key is stored only in the OS keyring
(`mailwarden set-groq-key`, hidden input).

`mailwarden doctor --llm` sends one hard-coded synthetic email (no real mail) to
check that the backend works.

### Prompt-injection defences

Email text is untrusted. The system prompt tells the model that the email is
data and any instructions in it must be ignored. The email is wrapped in
delimiters carrying a random per-request nonce, so it cannot forge the closing
tag. Output is pinned with strict structured outputs (JSON schema), then
re-validated locally by a strict pydantic model that rejects extra keys. Invalid
output is retried once, then the message is stored as "unclassified".
Redaction placeholders the model echoes back ([LINK:...], [NUM], ...) are
removed from stored text. The code
never acts on model output beyond storing these fields: there are no tools,
link fetches or follow-up requests.

## The sensitivity gate

Before any LLM is involved, every message goes through a purely local gate
(`mailwarden/core/sensitivity_gate.py`). It marks mail SENSITIVE if the sender
is in the SENSITIVE tier, or if the sender name, subject or body match patterns
for OTPs and verification codes, 2FA, "do not share", password resets, login
and new-device alerts, transactions, debits and credits, statements, UPI, IFSC,
account and card numbers, KYC, PAN, Aadhaar, tax and government IDs. Text is
normalised first (NFKC, zero-width and bidi characters removed, Cyrillic and
Greek look-alikes folded) to defeat obfuscation.

Tuned rules (so generic job-portal footers don't hold job mail):
`do_not_share` fires only when share, forward or disclose is within about
6 words of OTP, code, password, PIN or CVV. An Aadhaar number must pass the
Verhoeff checksum and have "Aadhaar" within about 50 characters. A PAN
(`[A-Z]{5}[0-9]{4}[A-Z]`) must have the word PAN nearby. The keyword rules
(Aadhaar, KYC, OTP, ...) are unchanged.

**Hard and soft rules.** HARD rules always hold, whatever else is true:
OTP / verification code / passcode / code-near-number, transaction,
debited/credited, account number, card ending, Aadhaar number (Verhoeff-valid,
with the word nearby), PAN (strict format with the word nearby), IFSC codes,
seed phrases, Hindi OTP/banking terms, every error or uncertainty, security
alerts from account-security senders, and the government or account-security
sender tier. SOFT rules are mentions rather than secrets: "password", "do not
share/forward" footers, statements, UPI/IFSC words, KYC/PAN/Aadhaar words,
banking terms, tax/ID words, a bank-brand display name, the bank/payments
sender tier, and security-alert wording from any sender that isn't an
account-security sender. A hold made **only** of SOFT rules is waived when the
mail carries strong recruiting markers: an ATS relay (SmartRecruiters,
Greenhouse, Lever, Ashby, Workday, jobs2web/SuccessFactors, iCIMS, as sender
domain or footer) or a recruiting phrase ("application received", "thank you
for applying", "hiring team", ...). For a bank/payments sender the marker must
be an ATS relay or a phrase in the **subject**, because bank marketing footers
often mention careers. Waived mail is then redacted and classified like any
other SAFE mail.

**Recruiting overrides (sender rules only).** A recruiting subdomain
(`careers.`, `recruitment.`, `talent.`, `jobs.` ...) of a SENSITIVE company
domain is treated as PRIORITY. A recruiting display name on such a domain only
removes the sender-based hold. Account-security senders and exact-address
rules are never overridden, and content rules always apply. Display names are
easy to forge, so a forged "Careers" name can get past the sender tier but not
the content rules.

**Held-back job mail.** When mail from a PRIORITY or recruiting sender is held
as SENSITIVE, it still never reaches an LLM. Locally, deterministic rules
extract a company (from the sender name or domain) and a stage (from subject
keywords). Only those two values, a friendly reason (e.g. "Contains a
verification code"), the sender display name, the time and the account are
stored. The subject itself is never stored or shown. This metadata can update
the applications table and trigger a notification such as
"Amex · assessment · needs your attention".

It fails closed. A gate error, a sender-rules error, a redaction error, an
unparseable body or an unparseable sender all count as SENSITIVE.

SENSITIVE mail is never passed to any LLM, and its body and subject are never
stored or displayed. The only code path that calls an LLM
(`Pipeline.classify_safe`) refuses anything not marked SAFE.
`tests/test_zero_llm_sensitive.py` asserts zero LLM calls and zero network
calls for a set of realistic Indian bank, UPI, OTP, login-alert, KYC and tax
emails. It runs on every test run, and a skip is reported as a failure.

## Job alerts

Job-alert emails (SAFE only) are split into individual jobs locally, by
parsing "View job" blocks and job links. If that finds nothing, the LLM gets
the redacted email plus a numbered list of link texts and **domains only**
(`[L3] Backend Intern (internshala.com)`). It answers with link numbers, which
are mapped back to the real URLs locally, so real URLs (which often carry
tracking tokens) never leave the machine. Jobs are stored in the encrypted
database. The dashboard only renders `http(s)` links. At most one "N new jobs
match your filters" notification is sent per day.

## Robustness against crafted mail

The pattern-matching code is written to run in linear time: patterns are
anchored at token boundaries, redaction only processes the slice of text that
could be sent, and the HTML converter uses a counter instead of rescanning.
HTML nested more than 2,000 levels deep is treated as unparseable, which
holds the message (fail closed). `tests/test_redos.py` checks every
text-processing function against 100,000-character hostile inputs on every
test run.

## Redaction

Some SAFE mail is classified by local rules with no LLM call: social
notifications (Instagram, Facebook, WhatsApp, X), job-board alert senders
(the `job_alert` tier) and non-PRIORITY mail carrying `List-Unsubscribe` or
`Precedence: bulk`.

SAFE mail is redacted before classification. Newsletter and legal footers
(unsubscribe, privacy policy, "you are receiving this" and similar), and
LinkedIn's "This email was intended for ..." line, are dropped first. Then email addresses, phone numbers,
every run of 4 or more digits, URLs (reduced to `[LINK:domain]`), and anything
resembling a token, key, password or ID number are removed. The text is then
Names, employers and colleges are deliberately not redacted, because they're
needed for classification. The text is then cut to the subject plus the first `llm.max_body_chars` (default 1500)
characters of the body. The sender's domain is kept; the sender's address
and name are not. `mailwarden dry-run` prints this exact text.

### Job descriptions

Job descriptions (JDs) make fit scores meaningful. They come from three places, and
none of them uses anything from your mailbox beyond the job's own link:

1. **Automatic (`[job_alerts] jd_auto_fetch = true`, default).** Only for candidate jobs
   (those passing the prefilter) whose link is on **Greenhouse, Lever or Ashby**. The
   job's public posting is read from those companies' job-board APIs (the fixed hosts
   in the table above), with no cookies and no tracking links, at most
   `max_jd_fetches_per_run` per run, paced, and cached for 7 days.
2. **Buttons (`[job_alerts] jd_button_fetch = true`, off by default).** "Fetch job
   description" and "Fetch JDs for top 10" on the Job alerts page, only when you click
   them. They use a separate, isolated session that may contact only these sites and
   their subdomains:
   <!-- jd-fetch-sites:start -->
   `greenhouse.io`, `lever.co`, `ashbyhq.com`, `myworkdayjobs.com`, `myworkdaysite.com`, `smartrecruiters.com`, `successfactors.com`, `successfactors.eu`, `sapsf.com`, `sapsf.eu`, `jobs2web.com`
   <!-- jd-fetch-sites:end -->
   Every hop, redirects included, must be on that list. Requests are HTTPS on the
   default port only, never to IP addresses, and only to hosts that resolve to public
   addresses; the address actually connected to is checked too. They're GET only, with
   no cookies or credentials. Tracking parameters (`utm_*`, `trk`, `gh_src` ...) are
   removed, and responses are capped at 2 MB.
3. **Paste.** For LinkedIn, Naukri, Indeed, Internshala, click-tracker links and any
   other site, the card explains why it can't be fetched and offers a "Paste JD" box.
   Pasted text is stored and scored like a fetched JD.

Unsubscribe, preference and feedback links are never followed. JD text is untrusted: it
is cleaned (links removed, hidden page text dropped), stored in the encrypted database,
and wrapped as data in the scoring prompt.

### Fit scores

`mailwarden run` (and `mailwarden jobs score`) sends one request per candidate job to
the configured LLM, at most `max_scores_per_run` per run. Each request contains the job
(title, company, location, listing details, and the JD if available) and a profile summary
from `profile.yaml`: weighted skills, experience, education, experience summary,
highlights, target roles and project one-liners. It never contains contact details:
`profile build` refuses to write them. Scores only order jobs; nothing is hidden.

## OAuth scopes

- Gmail: exactly `https://www.googleapis.com/auth/gmail.readonly`. Every token
  response is checked; a broader or missing scope stops the program, and a
  broader grant at sign-in is revoked immediately. `include_granted_scopes`
  is never sent.
- The OAuth flow uses PKCE and a random `state`, with the redirect bound to
  `127.0.0.1` on a random port.

## What is stored locally

| Item | Where |
| --- | --- |
| OAuth refresh tokens, OAuth client, account list | OS keyring (service `mailwarden`) |
| Database key (random 256-bit), Groq API key, dashboard token (phase 4) | OS keyring |
| Settings (non-secret) | `config.toml`, mode 600, in a mode-700 directory |
| Message metadata and classifications | SQLCipher-encrypted DB at `data/mailwarden.db` (mode 600). No bodies, no subjects. SENSITIVE rows keep only sender display name, received time, account and message id |
| Applications (company, role, stage, history, company domains) | Same encrypted DB |

Access tokens are held only in memory. Email bodies and subjects exist only in memory while a message is processed, and are cleared right after. `forget-account` revokes the token and deletes that account's rows (followed by `VACUUM`, with `secure_delete` on). mailwarden refuses to start if config
files are group/world accessible, or if the keyring backend is not a real OS
keyring.

## Local dashboard

- Listens on `127.0.0.1` only. Any other `dashboard.host` is refused by config
  and again when the server starts.
- The `Host` header must be `127.0.0.1:<port>` or `localhost:<port>`, which blocks
  DNS rebinding.
- Every page except the sign-in page and the stylesheet needs a cookie holding a
  random per-install token from the OS keyring. The cookie is HttpOnly,
  SameSite=Strict and lasts 90 days.
- The cookie is set via a one-time sign-in link that expires in 10 minutes. Only
  the link code's SHA-256 hash is stored, in the keyring.
- Every state-changing request (Done, Sign out) is a POST that must carry a CSRF
  token. If the request has an `Origin` header, it must be the dashboard's own.
- Every response carries `Content-Security-Policy: default-src 'none'; style-src
  'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri
  'none'` (no scripts at all), plus `X-Frame-Options: DENY`, `nosniff`,
  `Cache-Control: no-store`, `Referrer-Policy: same-origin` and COOP/CORP.
- All pages are server-rendered with auto-escaping, and no assets load from
  other hosts. The API docs routes are disabled, and access logs are off, so
  sign-in links are never logged.
- Sensitive mail appears only as counts by sender name. Held-back job mail shows
  company, stage and a friendly reason, never the subject.
- "Open in Gmail" is a link your browser follows. mailwarden itself makes no
  request to `mail.google.com`.

## Desktop window (macOS)

`mailwarden app` shows the dashboard in a native WebKit window (pywebview). The
window loads only `http://127.0.0.1:<port>`. It exposes no JavaScript bridge to
Python, developer tools and downloads are off, and it runs in private mode, so
no cookies or site data are written to disk; each launch signs in with a fresh
one-time code. Links that open in a new tab go to the default browser. The
dashboard's security headers and CSP apply unchanged.

The app registers the `mailwarden://` link type so notification clicks reach the
single open window. Such a link (from a notification or any web page) can only
navigate the window to a validated, read-only dashboard path (`/`, `/jobs?match=1`,
`/i/<account>/<id>` ...); state changes still need a CSRF-protected click. Later
launches hand over to the open window through a Unix socket in the mailwarden home
(mode 600, owner-only). The app bundle runs an ad-hoc-signed copy of the Python
interpreter stub so macOS identifies the window as the mailwarden app.

## Notifications

Notifications are local. They show only company, stage and deadline, or
"needs your attention" for held-back job mail, and never a summary, subject or
link text. On macOS they're sent via `terminal-notifier` or `osascript`; text
is passed as a program argument, never inserted into a script. Clicking one
opens a `http://127.0.0.1:<port>/i/<account>/<message-id>` dashboard URL.

## Digest files

The digest is stored in the encrypted database. The optional Markdown copy
(`[digest] markdown_dir`, off by default) is **plaintext**: one-line summaries
and sensitive-sender counts, no links or subjects. Files are mode 600 in a
mode-700 folder. Leave it off if disk access is part of your threat model.

## Scheduled jobs

The generated launchd, systemd and Task Scheduler jobs run with `umask 077`, so
their log files are private. They run as your user with no extra privileges.

## Logging

Logs never include bodies, subjects, tokens or keys. A scrubbing filter on
the log handler also masks email addresses, digit runs of 4 or more, bearer and
OAuth tokens, JWTs, `key=value` secrets and long high-entropy strings,
including inside tracebacks.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository.
