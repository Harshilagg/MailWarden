"""When a job alert has gone stale. Local rules only (no LLM, no network).

A job is expired when any of these is true:
1. its hiring system says the posting is gone (JD fetch got 404/410, or the job is no
   longer on the company's Ashby board): jd_status "closed";
2. its job description says it is closed ("no longer accepting applications" ...);
3. no job-alert email has shown it for ``after_days`` days (the last sighting counts,
   so a job that keeps being advertised stays fresh).

Alerts carry no posting date or deadline, so (3) is the main signal. Expired jobs are
never deleted: they move to the Expired tab, and are no longer fetched, scored or
offered in "Apply today".
"""

from __future__ import annotations

import datetime as dt
import re

from mailwarden.core.models import StoredJob

_CLOSED_TEXT = re.compile(
    r"\bno\s+longer\s+(?:accepting|available|open|active)\b|"
    r"\b(?:position|role|job|vacancy|requisition)\s+(?:has\s+been\s+|is\s+)?(?:filled|closed)\b|"
    r"\b(?:job|posting|listing)\s+(?:has\s+)?expired\b|"
    r"\bapplications?\s+(?:are\s+|is\s+)?(?:now\s+)?closed\b",
    re.IGNORECASE,
)


def last_seen(job: StoredJob) -> dt.datetime:
    return max(job.received_at, job.last_seen_at) if job.last_seen_at else job.received_at


def expired_reason(job: StoredJob, *, now: dt.datetime, after_days: int) -> str | None:
    """Why the job is expired, or None while it is current. ``after_days`` 0 = never by age."""
    if job.jd_status == "closed":
        return job.jd_reason or "the posting was removed"
    if job.jd_status == "ok" and job.jd_text and _CLOSED_TEXT.search(job.jd_text[:20_000]):
        return "the job description says it is closed"
    if after_days > 0:
        age = now - last_seen(job)
        if age > dt.timedelta(days=after_days):
            return f"not in any alert for {age.days} days"
    return None
