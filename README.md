# mailwarden

Privacy-first, local-first email triage for job seekers. mailwarden reads your Gmail
**read-only**. It makes sure mail about your job applications is never missed, ranks
the jobs in your job-alert emails against your own profile, summarises everything
else into a digest, and shows it all on a local dashboard.

- **Sensitive mail never reaches an AI.** A local gate catches OTPs, bank/UPI/card
  mail, password resets, login alerts and ID/KYC/tax mail before any model sees
  anything.
- **Free to run.** Classification uses Groq's free tier (`openai/gpt-oss-20b`), which
  receives only redacted text of non-sensitive mail. Alternatively, a fully local
  Ollama backend keeps everything on your machine.
- **Nothing useful on disk.** OAuth tokens and keys live only in your OS keyring. The
  database is SQLCipher-encrypted and stores no email bodies or subjects.
- **Local only.** The dashboard listens on 127.0.0.1 and loads no external assets and
  no JavaScript.

[SECURITY.md](SECURITY.md) lists exactly what leaves your machine, to which host, and
what is stored.

## How it works

```
Gmail (read-only) → sender rules → sensitivity gate → redaction → classify (LLM or rule)
                  → encrypted store → Urgent · Applications · Job alerts · Digest · notifications
```

1. **Sender rules** put senders in tiers: `priority` (job mail), `sensitive` (banks,
   payments, government, account security), `ignore` and `job_alert` (job boards).
2. The **sensitivity gate** checks every message locally. Sensitive mail is held back:
   only the sender name, the time and a friendly reason are kept. Held-back *job* mail
   still shows up as "Company · stage · needs your attention".
3. **Redaction** removes addresses, phone numbers, digit runs, links and secrets from
   the rest. Social notifications, job-board alerts and bulk mail are labelled by rule,
   with no LLM call.
4. The **classifier** labels each remaining email (job, personal, newsletter ...). It
   also extracts the company, role, stage and deadline. Job mail updates your
   Applications.
5. **Job alerts** are split into individual jobs and de-duplicated across sites. Each
   job is filtered and scored against your profile, and the best ones appear in
   **Apply today**.

## Requirements

- Python 3.11+ (3.13 recommended) and [uv](https://docs.astral.sh/uv/)
- macOS, Linux or Windows with a working OS keyring: macOS Keychain, Secret Service or
  KWallet on Linux, or Windows Credential Manager
- A Google account and a free Google Cloud project for your own OAuth client
- A free [Groq](https://console.groq.com) API key, or a local
  [Ollama](https://ollama.com)

The desktop app window and the app's own notifications are macOS-only. Everything
else also runs on Linux and Windows, but has mainly been tested on macOS.

## Setup

### 1. Install

```sh
make install                # .venv from hash-pinned requirements-dev.lock
.venv/bin/mailwarden init   # prints the mailwarden home folder
```

`init` creates the private mailwarden home (mode 700) with `config.toml` and
`sender_rules.yaml` (mode 600). The home is:

- macOS: `~/Library/Application Support/mailwarden`
- Linux: `~/.config/mailwarden`
- Windows: `%LOCALAPPDATA%\mailwarden\mailwarden`

Set `MAILWARDEN_HOME` to use another folder. mailwarden refuses to start if these
files are readable by other users.

### 2. Create your own Google OAuth client (one time, free)

mailwarden ships no shared client ID, so each user creates their own.

1. In <https://console.cloud.google.com/>, create a project (e.g. `mailwarden`).
2. **APIs & Services → Library**: enable the **Gmail API**.
3. **OAuth consent screen** (Google Auth Platform):
   - User type: **External**. App name: anything. Support email: your own address.
   - **Data access / Scopes**: add only `https://www.googleapis.com/auth/gmail.readonly`.
   - **Audience → Test users**: add every Gmail address you will connect.
4. **Credentials → Create credentials → OAuth client ID**, type **Desktop app**.
   Download the JSON.

```sh
.venv/bin/mailwarden add-account --provider gmail --name personal \
    --client-secrets ~/Downloads/client_secret_XXXX.json
```

The client is copied into the keyring, so delete the JSON file afterwards. Later
accounts don't need `--client-secrets`. Google warns that the app is unverified. This
is expected for a personal client, so choose **Continue**. mailwarden requests only
`gmail.readonly`. A token with any broader scope is revoked and refused.

**Seven-day sign-ins.** While the consent screen is in *Testing*, Google expires
refresh tokens after 7 days. To avoid re-running `add-account` every week, set the
publishing status to *In production* without submitting for verification. That is
allowed for personal use (fewer than 100 users). You will still see the "unverified
app" warning when you sign in.

### 3. Set up the classifier

**Groq (default, free):**

1. Sign up at <https://console.groq.com>. Don't add a billing method: the account then
   stays on the free tier and can't be charged.
2. In **Settings → Data Controls**, turn on **Zero Data Retention**.
3. In **API Keys**, choose **Create API key**, then run:

```sh
.venv/bin/mailwarden set-groq-key      # hidden prompt; stored in the OS keyring
.venv/bin/mailwarden doctor --llm      # tests the key with a built-in fake email
```

**Ollama (fully local alternative):**

1. Install Ollama.
2. Run `ollama pull qwen2.5:3b`.
3. Set `[llm] backend = "ollama"` in `config.toml`.

Nothing then leaves your machine for classification or scoring.

### 4. Check, preview, run

```sh
.venv/bin/mailwarden doctor --sync             # keyring, permissions, scopes, message count
.venv/bin/mailwarden init --reset-rules        # only if your sender_rules.yaml predates job_alert
.venv/bin/mailwarden dry-run --last 50 --summary
.venv/bin/mailwarden run                       # first real sync (backfills the last 7 days)
```

For each message, `dry-run` shows the tier, the gate decision and the exact redacted
text that *would* go to the LLM. It stores nothing and notifies no one. It sends
nothing either, unless you add `--with-llm`.

### 5. Run it in the background

```sh
.venv/bin/mailwarden schedule     # writes files to <home>/schedule/<platform>/ and prints install commands
```

- **macOS:** launchd agents sync every 10 minutes, build the digest at your digest
  times and keep the dashboard running. They use `StartCalendarInterval`, so a run
  missed while the laptop sleeps happens on wake (cron would skip it).
- **Linux:** systemd user timers with `Persistent=true`.
- **Windows:** Task Scheduler XML with "run as soon as possible after a missed start".

Logs go to `<home>/logs/` (mode 600). Each sync also fetches the job descriptions it
can fetch automatically, and scores new jobs.

### 6. Open the dashboard

```sh
.venv/bin/mailwarden launcher   # macOS: creates ~/Applications/mailwarden.app
```

Drag `mailwarden.app` to the Dock, or press ⌘Space and type "mailwarden". The app
opens the dashboard in its own window (macOS WebKit, not a browser) and signs you in
each time.

On the first launch, macOS asks whether "mailwarden-python" may use your Keychain.
Enter your Mac login password and choose **Always Allow**.

Without the app, you have two options:

- `mailwarden dashboard --open` runs the dashboard in the foreground.
- `mailwarden open` works when the background agent is running. It opens a one-time
  sign-in link in your browser.

## Daily use

Open the app and go through these views:

1. **Urgent:** job mail that needs you, soonest deadline first. It includes held-back
   job mail, which you open in Gmail because mailwarden deliberately didn't read it.
   Click **Done** when an item is handled. Nothing leaves Urgent until you do.
2. **Apply today:** your best-matching new jobs, with the project to lead with and the
   skills you're missing.
3. **Digest:** everything else since the last digest, by category, one line each.
4. **Applications:** where each application stands.

Reload (⌘R) to see new items. The background sync runs every 10 minutes.

## The dashboard

| View | What it shows |
| --- | --- |
| **Urgent** | Job items that need action, by deadline. Held-back job mail shows the company, the stage and a friendly reason ("Contains a verification code"), never the subject. Items are pinned: only **Done** removes them, even if they are reclassified later. Every item has an **Open in Gmail** link. |
| **Applications** | Companies by stage (applied, assessment, interview, offer, rejection), with each application's history. |
| **Job alerts** | Every job from your job-alert emails (see the next table). |
| **Apply today** | A daily shortlist: the top jobs first seen in the last few days, by rank, with no single role family taking over. Jobs you dismissed, filtered out, already applied to, or that have expired are skipped. |
| **Digest** | The latest digest. Newsletters and job alerts are collapsed, and sensitive mail appears only as counts by sender. |
| **Sensitive** | Counts by sender only. |
| **Settings** | Read-only: the classifier, the allowed outbound hosts, accounts and sender tiers. |

The **Job alerts** view has these controls:

| Control | What it does |
| --- | --- |
| Tabs | **Candidates** (current jobs that pass the prefilter), **All**, **Filtered** (with the reason), and **Expired** (stale or closed postings, with the reason) |
| Sort | **Best match** or **Newest** |
| Chips | Filter by source type and by source |
| Each card | Fit score (*preliminary* or *full*), why, the project to lead with, missing skills, job-description status |
| Card buttons | **Open**, **Fetch job description** (where allowed), **Paste JD**, **Dismiss** |

Every account you add appears on the same dashboard. Sign-in uses a one-time link
that is valid for 10 minutes. A cookie then keeps you signed in for 90 days.

## Job matching

### Your profile

Jobs are scored against a profile that is built **locally** from your own files. The
files live in the private mailwarden home, never in the repo:

```sh
.venv/bin/mailwarden profile init                # creates <home>/profile/ and profile/projects/
# put your CV (PDF) in <home>/profile/ and one Markdown file per project in profile/projects/
chmod 600 <home>/profile/*.pdf <home>/profile/projects/*.md
.venv/bin/mailwarden profile build --dry-run     # preview the diff
.venv/bin/mailwarden profile build               # write <home>/profile.yaml (previous kept as .bak)
```

`profile.yaml` holds weighted skills, years of experience, seniority, target and
avoid roles, locations and your projects. Only the project files count as project
evidence. The Projects section of your CV is ignored.

You can edit the file by hand. A rebuild replaces only the generated blocks
(`skills`, `experience_years`, `projects`). Every other line stays exactly as you
wrote it, comments included. These sections are yours to edit:

- `skill_overrides: {skill: weight}` replaces automatic weights, and adds skills the
  parser missed. Scores use the automatic weights with these overrides applied.
- `extra_project_skills: {project name: [skills]}` adds skills to that project on
  every rebuild. `build` warns if a name matches no project file.
- `education`, `experience_summary` and `highlights` are free text given to the
  scorer.
- `target_roles` entries may list alternatives separated by `/`, e.g.
  `sde / sde-1 / sde i`. They highlight matching titles on the Job alerts page.
- Filtering (roles to avoid, locations, experience) lives in `matching.yaml`, not here.
  `mailwarden matching check` tells you if old `avoid_roles` / `locations` entries are
  still in `profile.yaml`.

`profile.yaml` is given to the LLM for scoring, so it must never contain contact
details. `build` refuses to write the file if it would include an email address, a
phone number, a link or your name.

### Matching policy

`<home>/config/matching.yaml` is the single place for matching rules: experience
levels, hard exclusions, soft penalties, stack families with an evidence project each,
skills to ignore when picking a project, and the scoring rubric given to the model.
`profile.yaml` keeps who you are (skills, projects, education, highlights).

```sh
.venv/bin/mailwarden matching init    # create it from the template (never overwrites)
.venv/bin/mailwarden matching check   # validate it and list likely mistakes
```

Parsing is strict, so a misspelt key is an error rather than a silently ignored rule.
`check` warns about evidence projects that aren't in `profile.yaml`, keywords that
appear in two families, and exclusions that would always filter a family.

### Prefilter

Before scoring, a local prefilter (driven by `matching.yaml`) filters only jobs you
can't or won't do. **The stack never filters**; stacks in `soft_penalties` only lower
the rank (−1 by default).

- **Hard exclusions:** `role_types` matched as whole words in the title, and
  `conditions` ("unpaid", "service bond" ...) anywhere in the title, details or job
  description. Two role types have a built-in meaning:
  - `internship` also catches "Intern" titles, Internshala internship links,
    listings that say "internship", and stipends ("Unpaid", up to ₹40,000 a month);
  - `non-engineering` catches titles with no engineering word and no stack keyword.
- **Experience:** each job is `verified_fresher`, `stretch`, `too_senior` or
  `unknown`. Too senior is filtered. The level comes from, in order:
  1. your quick check;
  2. years in the title or listing details ("(0-2 yrs)", "Experience: 1-4 yrs");
  3. required years in the job description, not "preferred" ones or a company's
     history;
  4. a senior word in the title ("Senior", "Lead", "SDE II", "L5" ...);
  5. a fresher word ("SDE 1", "fresher", "2026 batch" ...);
  6. a fresher-only source (Naukri Campus).

  Ranges use the minimum: a minimum of up to `pass_max_min_years` (1) is fresher, up
  to `stretch_min_years` (2) is a stretch, and above that is too senior.
- **Location:** a known place outside `location.allowed` is filtered, unless the job
  is remote and `remote_ok` is true. `Delhi NCR` covers Delhi, Gurugram, Noida,
  Ghaziabad and Faridabad, and PIN codes are recognised. Jobs with no location, only
  "India", or only a state containing one of your cities pass.

**Needs a quick check.** Most alerts (all of LinkedIn's) don't say what experience a
job wants. With `unknown_policy: needs_check`, such jobs pass the filter but never go
into Apply today until verified. They wait in **Needs a quick check**, under Apply
today and as a tab on Job alerts, ranked by fit. Open the posting, read the experience
line, and click **Fresher OK** (eligible for Apply today) or **Too senior** (filtered).
**Undo check** reverses either.

Filtered jobs are never deleted. They stay under **Filtered** and **All**, with the
reason. `mailwarden jobs prefilter` prints the counts per reason and per experience
level.

### Expired jobs

A job expires when no job-alert email has shown it for `expire_after_days` (default 14)
days, or when its posting is closed: a Greenhouse, Lever or Ashby fetch finds it removed,
or its description says it is no longer accepting applications. Job alerts don't carry
posting dates, so "last seen in an alert" is the main signal; a job that keeps being
advertised stays current. Expired jobs move to the **Expired** tab. They are never
deleted, and they are no longer fetched, scored or offered in Apply today.

### Fit scores

The LLM gives each candidate a score from 0 to 10. With it come the matched and
missing skills, the project to lead with, and one sentence explaining the score.

- A **preliminary** score comes from the alert alone and is capped at 7.
- A **full** score uses the job description. A missing must-have skill caps it at 6,
  and experience above your level caps it at 4. If the description demands a CS/IT
  degree and your education isn't one, "CS degree required" is added to the missing
  skills.

Scores are cached, and only redone when the job or your profile changes. At most
`max_scores_per_run` jobs are scored per sync. Scores only order jobs; nothing is
hidden.

### Job descriptions

- **Automatic:** fetched for candidates hosted on Greenhouse, Lever or Ashby, through
  their public job-board APIs, and cached for 7 days.
- **Buttons (opt-in):** set `[job_alerts] jd_button_fetch = true` to get **Fetch job
  description** and **Fetch JDs for top 10**. These work only for Greenhouse, Lever,
  Ashby, Workday, SmartRecruiters and SuccessFactors/jobs2web.
- **Paste:** for LinkedIn, Naukri, Indeed, Internshala, click-tracking links and other
  sites, the card says why the description can't be fetched. Open the job, copy the
  description, and use **Paste JD → Save and score**.

### Apply today and ranking

A job's rank is its fit score, adjusted as follows:

| Condition | Adjustment |
| --- | --- |
| Seen in the last 3 days | +0.5 |
| First seen more than 3 weeks ago | -1 |
| Company on `[job_alerts] watchlist` | +1 |

At equal rank, full scores come before preliminary ones. **Apply today** is a daily
shortlist:

- It shows the top `apply_today_count` jobs (default 8) first seen in the last
  `apply_today_days` days (default 3).
- No role family (Go, Java, Python, full stack/web, AI/ML, mobile, DevOps/cloud, data,
  .NET/PHP) takes more than `max_family_share` of it (default 25%), unless there
  aren't enough other jobs. Generic titles such as "Software Engineer" or "SDE 1" are
  never capped. Each card shows its family.
- It takes only jobs with a verified experience level (fresher, or at most
  `max_stretch_in_apply_today` stretch jobs).
- It skips jobs you dismissed, jobs filtered out, expired jobs, and jobs whose company
  and role are already in your Applications.

You get one notification a day: "N new jobs scored 7+".

### Sources and duplicates

Each job records its source type and its source:

- Source types: job boards, company careers, startup platforms, communities, and
  company alerts sent via hiring systems.
- Sources: LinkedIn, Naukri, Naukri Campus, Internshala, Cutshort, "Bayer (jobs2web)"
  and so on.

The same job from several sources (same company, title and city) is shown as one
card, which lists the other sources under "also on". mailwarden also tidies what
alerts say:

- A title like "SAP EAM - Bangalore, IN" becomes the title "SAP EAM" with the
  location Bangalore.
- Relay names become real companies (Amex Careers → American Express,
  EYJobAlerts → EY).

### Calibration

```sh
.venv/bin/mailwarden jobs calibrate           # label 20 jobs good/bad, then see agreement
.venv/bin/mailwarden jobs calibrate --report  # re-check after profile changes and rescoring
```

The report shows:

- how many jobs you called good scored 7+
- how many jobs you called bad scored below 5
- the biggest disagreements, with the model's reason

Use it to adjust `profile.yaml`. Your labels stay in the encrypted database.

### Recall audit (weekly)

Calibration checks the scores; the recall audit checks what the ranking **hides**:

```sh
.venv/bin/mailwarden jobs audit           # 15 jobs from outside Apply today: would you apply?
.venv/bin/mailwarden jobs audit --report  # missed-good counts, reasons and suggested changes
```

The audit shows jobs that are *not* in Apply today, one at a time: about 6 filtered,
6 ranked lower, and 3 left out for other reasons (expired, outside the Apply today
window, not scored yet). Each shows the title, company, score and score type, and the
filter reason if any. Answer `y` (I'd apply), `n`, `s` (skip) or `q`. Jobs you've
audited are never shown again.

For every `y`, it shows exactly why the job was left out: the prefilter rule, expiry,
the window, the role-family limit, its rank against the cutoff (including ties), the
title-only score, a score cap, or low skill weights. Each reason comes with the change
that would have surfaced the job, such as "profile.yaml: add 'Pune' to locations" or
"config: raise [job_alerts] apply_today_days (now 3)".

The report shows audited and missed-good counts for the last 7 days and all time, the
reasons grouped by how many missed jobs they explain, and the suggested changes. It
changes nothing by itself. Answers are stored in the encrypted database, and Apply
today reminds you when a week has passed since the last audit.

## Sender rules and the sensitivity gate

`sender_rules.yaml` in the mailwarden home has four tiers. A domain rule also matches
its subdomains, and an exact address beats a domain rule.

- **priority:** job mail. Application-tracking and assessment platforms are
  pre-seeded. Priority mail still goes through the gate.
- **sensitive:** banks, UPI and payment apps, cards, brokers, tax and government, and
  account-security senders. This mail is never sent to any LLM.
- **ignore:** senders you never want processed. They are only counted.
- **job_alert:** job-board alerts (LinkedIn job alerts, Indeed, Naukri, foundit,
  Internshala). They are labelled by rule and never notify. Their jobs are extracted
  for Job alerts.

Independently of tiers, the gate inspects the sender name, subject and body. It holds
back anything that looks like an OTP or verification code, a password reset, a login
alert, a bank, UPI or card transaction, a statement, or KYC, PAN, Aadhaar or tax mail.
Promoting a sender never bypasses these content checks. Two exceptions keep job mail
visible:

- A recruiting subdomain of a sensitive company (e.g.
  `recruitment.americanexpress.com`) counts as priority.
- Job mail that was held back only because of footer wording ("do not share",
  "password") is released when it clearly comes from a hiring system.

SECURITY.md has the exact rules. To tune them:

```sh
.venv/bin/mailwarden dry-run --last 100 --summary          # what was held back, and why
.venv/bin/mailwarden promote talent@somefintech.com priority
.venv/bin/mailwarden promote offers.somestore.com ignore
.venv/bin/mailwarden regate --days 7                       # re-check stored mail with today's rules
.venv/bin/mailwarden regate --days 7 --apply               # reprocess what changed
```

## Notifications

Job mail that needs action triggers a notification: an assessment, interview or
offer, or an action for a company you're tracking or a priority sender. The
notification shows only the company, the stage and the deadline. For held-back job
mail it says "needs your attention". Clicking it opens that entry.

- **macOS:** after `mailwarden launcher`, the mailwarden app posts notifications
  itself, with its name and logo, and a click opens the entry in the app window.
  Without the app, mailwarden uses `terminal-notifier` if it is installed, otherwise
  `osascript`. macOS attributes `osascript` notifications to Script Editor, so a
  click opens Script Editor. `mailwarden notify-test` sends a test notification.
- **Linux and Windows:** notifications use `desktop-notifier`. Clicks are handled only
  while the sending process is alive (`[notifications] click_wait_seconds`).

There is at most one digest notification per day.

## Configuration

`config.toml` in the mailwarden home holds non-secret settings only. Secrets are in
the keyring. These are the settings you're most likely to change:

| Setting | Default | Meaning |
| --- | --- | --- |
| `[llm] backend` | `groq` | `groq` or `ollama` |
| `[llm] max_body_chars` | 1500 | Body characters sent per email, after redaction |
| `[llm] max_llm_calls_per_minute` | 6 | Local pacing for Groq's free tier |
| `[llm] max_llm_tokens_per_minute` | 7000 | Local pacing; Groq's free tier allows 8,000 tokens a minute |
| `[llm] max_llm_calls_per_run` | 150 | Cap per sync; unfinished work stays pending |
| `[groq] model` | `openai/gpt-oss-20b` | Any Groq model with strict structured outputs |
| `[gmail] full_sync_days` | 7 | Days fetched on the first run |
| `[dashboard] port` | 8765 | Local dashboard port (the host is always 127.0.0.1) |
| `[notifications] enabled` | true | Desktop notifications |
| `[digest] times` | 08:00, 18:00 | When the digest is built |
| `[digest] markdown_dir` | off | Optional plaintext Markdown copy of the digest |
| `[job_alerts] watchlist` | `[]` | Companies whose jobs get +1 rank |
| `[job_alerts] apply_today_count` | 8 | Jobs in Apply today |
| `[job_alerts] apply_today_days` | 3 | Apply today picks from jobs first seen in this many days (0 = any age) |
| `[job_alerts] max_family_share` | 0.25 | Largest share of Apply today from one role family (0 = no cap) |
| `[job_alerts] expire_after_days` | 14 | Days without an alert before a job expires (0 = only closed postings expire) |
| `[job_alerts] jd_auto_fetch` | true | Automatic fetches from Greenhouse, Lever and Ashby APIs |
| `[job_alerts] jd_button_fetch` | false | Fetch buttons on the Job alerts page |
| `[job_alerts] max_scores_per_run` | 40 | Jobs scored per sync |
| `[job_alerts] max_jd_fetches_per_run` | 30 | Job descriptions fetched per sync |
| `[job_alerts] daily_notification` | true | "N new jobs scored 7+", once a day |

## Commands

| Command | What it does |
| --- | --- |
| `mailwarden init [--reset-rules]` | Create the home folder and default config. `--reset-rules` restores the seeded `sender_rules.yaml` and keeps the old file as `.bak` |
| `mailwarden add-account --provider gmail --name <n> [--client-secrets FILE]` | Google sign-in; the token is stored in the keyring |
| `mailwarden accounts` | List accounts (addresses masked) |
| `mailwarden forget-account <n>` | Revoke the token at Google, delete it, and delete the account's stored data |
| `mailwarden set-groq-key` | Store the Groq API key in the keyring (hidden input) |
| `mailwarden doctor [--sync] [--llm]` | Check the keyring, permissions, allowlist, scopes and notifications. `--sync` counts recent messages; `--llm` tests the classifier with a fake email |
| `mailwarden dry-run [--last N] [--account n] [--summary] [--with-llm]` | Preview tiers, gate decisions and redacted LLM text; stores nothing |
| `mailwarden run` | One sync: classify mail, extract and score jobs, notify |
| `mailwarden digest` | Build the digest now, and send the daily jobs notification |
| `mailwarden regate [--days 7] [--apply] [--message ID]` | Re-check stored mail with the current rules (no LLM). `--apply` reprocesses what changed |
| `mailwarden promote <address-or-domain> <tier>` | Move a sender to `priority`, `sensitive`, `ignore`, `job_alert` or `default` |
| `mailwarden matching init` / `matching check` | Create the matching policy from the template / validate it |
| `mailwarden profile init` | Create the profile folder |
| `mailwarden profile build [--dry-run]` | Build `profile.yaml` from your CV and projects |
| `mailwarden jobs prefilter [--show summary\|filtered\|kept\|all]` | Show which jobs the prefilter keeps or filters, and why |
| `mailwarden jobs fetch [--limit N]` | Fetch job descriptions from the Greenhouse, Lever and Ashby APIs now |
| `mailwarden jobs score [--limit N]` | Score jobs now |
| `mailwarden jobs calibrate [--count 20] [--report]` | Label jobs good or bad, and see how well the scores agree |
| `mailwarden jobs audit [--count 15] [--report]` | Weekly recall audit: would you apply to jobs Apply today left out, and why were they left out |
| `mailwarden dashboard [--open]` | Run the dashboard in the foreground and print a one-time sign-in link |
| `mailwarden open [--print-only]` | Open a one-time sign-in link to the running dashboard |
| `mailwarden app [--path /jobs]` | Open the dashboard in its own window (macOS) |
| `mailwarden launcher [--browser]` | Create `~/Applications/mailwarden.app` (macOS). `--browser` makes it open your browser instead |
| `mailwarden notify-test` | Send a test notification |
| `mailwarden schedule [--platform macos\|linux\|windows]` | Generate background-job files and print install commands |

Put `--quiet` before any command for warnings-only output (scheduled jobs use it), or
`-v` for debug logs.

## Troubleshooting

- **Keychain asks for your password for "mailwarden-python" (macOS).** The app runs
  its own copy of Python, so macOS asks once for each stored secret. Enter your Mac
  login password and choose **Always Allow**.
- **The window stays white on launch.** The app is waiting for a Keychain prompt to be
  answered.
- **Clicking a notification opens Script Editor.** The app isn't installed. Run
  `mailwarden launcher`. `mailwarden doctor` shows which notifier is in use.
- **"Google rejected the stored grant".** The refresh token expired (the consent
  screen is in *Testing*) or was revoked. Run `add-account` again, and see
  "Seven-day sign-ins" above.
- **Scoring is slow or stops at a rate limit.** Groq's free tier allows about three
  scorings a minute. Unfinished jobs are picked up on the next sync.

## Development

```sh
make test     # pytest, including the mandatory zero-LLM-calls test for sensitive mail
make lock     # regenerate the hash-pinned lockfiles after changing pyproject.toml
make audit    # pip-audit on the lockfile, plus bandit on the code
```

`scripts/make_icon.sh` rebuilds the app icon from `mailwarden/assets/logo-source.png`.
