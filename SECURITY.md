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

## Logging

Logs never include bodies, subjects, tokens or keys. A scrubbing filter on
the log handler also masks email addresses, digit runs of 4 or more, bearer and
OAuth tokens, JWTs, `key=value` secrets and long high-entropy strings,
including inside tracebacks.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository.
