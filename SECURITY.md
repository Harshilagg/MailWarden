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
| `127.0.0.1` | always (from phase 3) | Local Ollama: redacted text of SAFE mail. Stays on this machine |
| `graph.microsoft.com` | `[outlook] enabled = true` | Read-only Graph calls, `Mail.Read` (phase 5) |
| `login.microsoftonline.com` | `[outlook] enabled = true` | Microsoft OAuth (phase 5) |
| `api.groq.com` | `[groq] enabled = true` | Redacted text of SAFE mail only, never SENSITIVE mail (phase 5) |
<!-- allowlist:end -->

No telemetry, analytics or update checks exist.

## The sensitivity gate

Before any LLM is involved, every message goes through a purely local gate
(`mailwarden/core/sensitivity_gate.py`). It marks mail SENSITIVE if the sender
is in the SENSITIVE tier, or if the sender name, subject or body match patterns
for OTPs and verification codes, 2FA, "do not share", password resets, login
and new-device alerts, transactions, debits and credits, statements, UPI, IFSC,
account and card numbers, KYC, PAN, Aadhaar, tax and government IDs. Text is
normalised first (NFKC, zero-width and bidi characters removed, Cyrillic and
Greek look-alikes folded) to defeat obfuscation.

It fails closed. A gate error, a sender-rules error, a redaction error, an
unparseable body or an unparseable sender all count as SENSITIVE.

SENSITIVE mail is never passed to any LLM, and its body and subject are never
stored or displayed. The only code path that calls an LLM
(`Pipeline.classify`) refuses anything not marked SAFE.
`tests/test_zero_llm_sensitive.py` asserts zero LLM calls and zero network
calls for a set of realistic Indian bank, UPI, OTP, login-alert, KYC and tax
emails. It runs on every test run, and a skip is reported as a failure.

## Redaction

SAFE mail is redacted before classification: email addresses, phone numbers,
every run of 4 or more digits, URLs (reduced to `[LINK:domain]`), and anything
resembling a token, key, password or ID number are removed. The text is then
cut to the subject plus the first `llm.max_body_chars` (default 1500)
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
| DB key, dashboard token, optional Groq key | OS keyring (later phases) |
| Settings (non-secret) | `config.toml`, mode 600, in a mode-700 directory |
| Message metadata and classifications | SQLCipher-encrypted DB (phase 3). No bodies, no subjects |

Access tokens are held only in memory. mailwarden refuses to start if config
files are group/world accessible, or if the keyring backend is not a real OS
keyring.

## Logging

Logs never include bodies, subjects, tokens or keys. A scrubbing filter on
the log handler also masks email addresses, digit runs of 4 or more, bearer and
OAuth tokens, JWTs, `key=value` secrets and long high-entropy strings,
including inside tracebacks.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository.
