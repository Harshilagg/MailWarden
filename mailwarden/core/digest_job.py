"""Build, store and (optionally) export a digest."""

from __future__ import annotations

import datetime as dt

from mailwarden.core.job_alerts import matches_filters
from mailwarden.core.overview import Digest, build_digest, digest_markdown
from mailwarden.delivery.base import DigestSink, Notifier
from mailwarden.storage.base import Repository

DEFAULT_WINDOW = dt.timedelta(days=1)
MAX_WINDOW = dt.timedelta(days=3)


def run_digest(repo: Repository, user_id: str, *, now: dt.datetime, sink: DigestSink | None = None) -> Digest:
    """Digest of mail since the previous digest (at most 3 days back; 24h the first time)."""
    last = repo.latest_digest(user_id)
    start = last[0] if last else now - DEFAULT_WINDOW
    start = max(start, now - MAX_WINDOW)
    digest = build_digest(repo.list_email_meta(user_id, since=start), now=now, period_start=start)
    repo.save_digest(user_id, now, start, digest.to_json())
    if sink is not None:
        sink.write(user_id, digest_markdown(digest), now)
    return digest


NOTICE_DATE_KEY = "jobs_notice_date"
NOTICE_AT_KEY = "jobs_notice_at"


def maybe_notify_new_jobs(
    repo: Repository,
    user_id: str,
    *,
    now: dt.datetime,
    keywords: list[str],
    locations: list[str],
    notifier: Notifier | None,
) -> int:
    """At most once per local day: '<N> new jobs match your filters'. Returns N (0 if not sent)."""
    today = now.astimezone().date().isoformat()
    if repo.get_state(user_id, NOTICE_DATE_KEY) == today:
        return 0
    last = repo.get_state(user_id, NOTICE_AT_KEY)
    since = dt.datetime.fromisoformat(last) if last else now - DEFAULT_WINDOW
    n = sum(1 for j in repo.list_jobs(user_id, since=since) if matches_filters(j.title, j.location, keywords, locations))
    if n == 0:
        return 0
    if notifier is not None:
        notifier.notify_text(f"{n} new job{'s match' if n != 1 else ' matches'} your filters", "/jobs?match=1")
    repo.set_state(user_id, NOTICE_DATE_KEY, today)
    repo.set_state(user_id, NOTICE_AT_KEY, now.isoformat())
    return n
