"""Human-friendly formatting for the dashboard, digest and notifications."""

from __future__ import annotations

import datetime as dt


def short_date(d: dt.date, today: dt.date | None = None) -> str:
    """'Tue, 5 Oct'; the year is added when it differs from this year."""
    today = today or dt.date.today()
    text = f"{d:%a}, {d.day} {d:%b}"
    return text if d.year == today.year else f"{text} {d.year}"


def relative_time(when: dt.datetime, now: dt.datetime | None = None) -> str:
    """'just now', '5 minutes ago', '2 hours ago', 'yesterday', else a short date."""
    now = now or dt.datetime.now(dt.UTC)
    seconds = (now - when).total_seconds()
    if seconds < 0:
        return short_date(when.astimezone().date(), now.astimezone().date())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        m = int(seconds // 60)
        return f"{m} minute{'s' if m != 1 else ''} ago"
    if seconds < 86400:
        h = int(seconds // 3600)
        return f"{h} hour{'s' if h != 1 else ''} ago"
    if when.astimezone().date() == (now.astimezone() - dt.timedelta(days=1)).date():
        return "yesterday"
    return short_date(when.astimezone().date(), now.astimezone().date())
