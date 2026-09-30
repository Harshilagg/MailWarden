"""Ranking and "Apply today". Ranks only ORDER jobs; nothing is hidden from "All".

rank = fit score
       + 0.5 if seen in the last 3 days (fresh)
       - 1.0 if first seen more than 21 days ago
       + 1.0 if the company is on [job_alerts] watchlist

"Apply today" = the top N candidates by rank (full scores ahead of preliminary at equal
rank), skipping jobs that are dismissed, filtered by the prefilter, not scored yet, or
whose company + role is already in your Applications.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from mailwarden.core.applications import company_key, role_key
from mailwarden.core.models import Application, StoredJob
from mailwarden.core.prefilter import prefilter

FRESH = dt.timedelta(days=3)
STALE = dt.timedelta(days=21)
FRESH_BONUS = 0.5
STALE_PENALTY = 1.0
WATCHLIST_BONUS = 1.0
NOTIFY_THRESHOLD = 7.0


@dataclass(frozen=True)
class RankInfo:
    rank: float | None
    parts: tuple[str, ...] = ()
    applied: bool = False
    watchlist: bool = False


@dataclass
class AppliedIndex:
    """company key -> role keys of your applications ('' = role unknown)."""

    roles: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def from_applications(cls, apps: list[Application]) -> AppliedIndex:
        index: dict[str, set[str]] = {}
        for app in apps:
            ck = company_key(app.company)
            if ck:
                index.setdefault(ck, set()).add(role_key(app.role))
        return cls(index)

    def contains(self, company: str | None, title: str) -> bool:
        ck = company_key(company or "")
        roles = self.roles.get(ck) if ck else None
        if not roles:
            return False
        if "" in roles:
            return True  # you applied to this company and the role wasn't recorded
        rk = role_key(title)
        return any(r == rk or r in rk or rk in r for r in roles if r)


def on_watchlist(company: str | None, watchlist: list[str]) -> bool:
    ck = company_key(company or "")
    if not ck:
        return False
    for entry in watchlist:
        wk = company_key(entry)
        if wk and (ck == wk or ck.startswith(wk + " ") or wk.startswith(ck + " ")):
            return True
    return False


def rank_job(job: StoredJob, *, now: dt.datetime, watchlist: list[str], applied: AppliedIndex) -> RankInfo:
    is_applied = applied.contains(job.company, job.title)
    watched = on_watchlist(job.company, watchlist)
    if job.score is None:
        return RankInfo(None, (), is_applied, watched)
    rank = job.score
    parts = [f"score {job.score:.1f} ({job.score_level})"]
    age = now - job.received_at
    if age < FRESH:
        rank += FRESH_BONUS
        parts.append(f"fresh +{FRESH_BONUS:g}")
    elif age > STALE:
        rank -= STALE_PENALTY
        parts.append(f"older than 3 weeks -{STALE_PENALTY:g}")
    if watched:
        rank += WATCHLIST_BONUS
        parts.append(f"watchlist +{WATCHLIST_BONUS:g}")
    return RankInfo(round(rank, 2), tuple(parts), is_applied, watched)


def sort_key(job: StoredJob, info: RankInfo) -> tuple:
    """Best first: rank, then full before preliminary, then score, then newest."""
    return (info.rank is None, -(info.rank or 0.0), job.score_level != "full", -(job.score or 0.0),
            -job.received_at.timestamp())


def apply_today(jobs: list[StoredJob], profile: dict | None, *, n: int, now: dt.datetime, watchlist: list[str],
                applied: AppliedIndex) -> list[tuple[StoredJob, RankInfo]]:
    picks = []
    for job in jobs:
        if job.dismissed or job.score is None:
            continue
        if profile is not None and prefilter(job.title, job.location, profile, jd_text=job.jd_text).excluded:
            continue
        info = rank_job(job, now=now, watchlist=watchlist, applied=applied)
        if info.applied:
            continue
        picks.append((job, info))
    picks.sort(key=lambda p: sort_key(*p))
    return picks[:n]


def new_strong_jobs(jobs: list[StoredJob], profile: dict | None, *, since: dt.datetime,
                    applied: AppliedIndex, threshold: float = NOTIFY_THRESHOLD) -> int:
    """Jobs first seen since ``since`` that scored ``threshold``+ (candidates you haven't applied to)."""
    count = 0
    for job in jobs:
        if job.dismissed or job.score is None or job.score < threshold or job.received_at < since:
            continue
        if profile is not None and prefilter(job.title, job.location, profile, jd_text=job.jd_text).excluded:
            continue
        if applied.contains(job.company, job.title):
            continue
        count += 1
    return count
