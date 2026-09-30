"""Build, store and (optionally) export a digest."""

from __future__ import annotations

import datetime as dt

from mailwarden.core.overview import Digest, build_digest, digest_markdown
from mailwarden.delivery.base import DigestSink
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
