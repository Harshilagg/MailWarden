"""Ranking and "Apply today". Ranks only ORDER jobs; nothing is hidden from "All".

rank = fit score
       + 0.5 if seen in the last 3 days (fresh)
       - 1.0 if first seen more than 21 days ago
       + 1.0 if the company is on [job_alerts] watchlist

"Apply today" = a daily shortlist: the top N candidates by rank (full scores ahead of
preliminary at equal rank), skipping jobs that are dismissed, filtered by the prefilter,
expired, not scored yet, or whose company + role is already in your Applications.
Optionally only jobs first seen in the last ``new_within_days`` days, and at most
``max_family_share`` of the list from one role family (Go, Java, full stack/web ...), so
one stack can't take every slot. Generic titles (Software Engineer, SDE) have no family.
"""

from __future__ import annotations

import datetime as dt
import math
import re
from dataclasses import dataclass, field

from mailwarden.core.applications import company_key, role_key
from mailwarden.core.expiry import expired_reason
from mailwarden.core.models import Application, StoredJob
from mailwarden.core.experience import STRETCH
from mailwarden.core.policy import MatchingPolicy
from mailwarden.core.prefilter import penalty, prefilter_job

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


def rank_job(job: StoredJob, *, now: dt.datetime, watchlist: list[str], applied: AppliedIndex,
             policy: MatchingPolicy | None = None) -> RankInfo:
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
    if policy is not None and (stacks := penalty(job, policy)) and policy.soft_penalties.rank_penalty:
        rank -= policy.soft_penalties.rank_penalty
        parts.append(f"{', '.join(stacks)} stack -{policy.soft_penalties.rank_penalty:g}")
    return RankInfo(round(rank, 2), tuple(parts), is_applied, watched)


def sort_key(job: StoredJob, info: RankInfo) -> tuple:
    """Best first: rank, then full before preliminary, then score, then newest."""
    return (info.rank is None, -(info.rank or 0.0), job.score_level != "full", -(job.score or 0.0),
            -job.received_at.timestamp())


# Role families, checked in order (first match wins). Titles matching none are generic.
_FAMILIES: tuple[tuple[str, re.Pattern[str]], ...] = tuple((name, re.compile(rx, re.IGNORECASE)) for name, rx in (
    ("Go", r"\bgolang\b|\bgo\s?-?lang\b|\bgo\s+(?:developer|engineer|backend)\b|\(\s*go\s*\)"),
    ("AI/ML", r"\b(?:ai|ml|llm|genai|gen\s+ai|agentic|nlp)\b|machine\s+learning|artificial\s+intelligence|"
              r"data\s+scien"),
    ("Mobile", r"\b(?:android|ios|flutter|mobile|kotlin|swift)\b|react\s+native"),
    ("Full stack/web", r"\bfull[\s-]?stack\b|\b(?:mern|mean|react(?:\.?js)?|node(?:\.?js)?|next\.?js|angular|vue|"
                       r"javascript|typescript)\b|\bweb\s+develop|\bfront[\s-]?end\b"),
    ("Java", r"\bjava\b|\bspring\b"),
    ("Python", r"\b(?:python|django|flask|fastapi)\b"),
    ("DevOps/cloud", r"\b(?:devops|sre|cloud|platform|infrastructure|kubernetes|k8s)\b|site\s+reliability"),
    ("Data", r"\bdata\s+engineer|\b(?:etl|spark|big\s+data)\b"),
    (".NET/PHP", r"\.net\b|\bc#|\bphp\b"),
))


def role_family(title: str) -> str | None:
    for name, rx in _FAMILIES:
        if rx.search(title[:300]):
            return name
    return None


def apply_ready(job: StoredJob, policy: MatchingPolicy | None) -> bool:
    """Passes the filter and, under unknown_policy needs_check, has a verified experience level."""
    if policy is None:
        return True
    verdict = prefilter_job(job, policy)
    if verdict.excluded:
        return False
    return not verdict.needs_check or policy.experience.unknown_policy == "allow"


def apply_today(jobs: list[StoredJob], policy: MatchingPolicy | None, *, n: int, now: dt.datetime,
                watchlist: list[str], applied: AppliedIndex, expire_after_days: int = 0, new_within_days: int = 0,
                max_family_share: float = 0.0) -> list[tuple[StoredJob, RankInfo]]:
    picks = []
    for job in _current(jobs, now=now, expire_after_days=expire_after_days, new_within_days=new_within_days):
        if job.score is None or not apply_ready(job, policy):
            continue
        info = rank_job(job, now=now, watchlist=watchlist, applied=applied, policy=policy)
        if info.applied:
            continue
        picks.append((job, info))
    picks.sort(key=lambda p: sort_key(*p))
    max_stretch = policy.experience.max_stretch_in_apply_today if policy is not None else None
    cap = max(2, math.ceil(n * max_family_share)) if max_family_share > 0 else n
    chosen: list[tuple[StoredJob, RankInfo]] = []
    held: list[tuple[StoredJob, RankInfo]] = []
    per_family: dict[str, int] = {}
    stretch = 0
    for pick in picks:
        if len(chosen) == n:
            break
        stretchy = max_stretch is not None and is_stretch(pick[0], policy)
        if stretchy and stretch >= max_stretch:
            continue  # a hard limit
        family = role_family(pick[0].title)
        if family is not None and per_family.get(family, 0) >= cap:
            held.append(pick)  # used only if there aren't enough other jobs
            continue
        if family is not None:
            per_family[family] = per_family.get(family, 0) + 1
        stretch += stretchy
        chosen.append(pick)
    for pick in held:  # backfill, still within the stretch limit
        if len(chosen) == n:
            break
        stretchy = max_stretch is not None and is_stretch(pick[0], policy)
        if stretchy and stretch >= max_stretch:
            continue
        stretch += stretchy
        chosen.append(pick)
    chosen.sort(key=lambda p: sort_key(*p))
    return chosen


def is_stretch(job: StoredJob, policy: MatchingPolicy | None) -> bool:
    if policy is None:
        return False
    exp = prefilter_job(job, policy).experience
    return exp is not None and exp.status == STRETCH


def _current(jobs: list[StoredJob], *, now: dt.datetime, expire_after_days: int, new_within_days: int):
    for job in jobs:
        if job.dismissed:
            continue
        if new_within_days > 0 and now - job.received_at > dt.timedelta(days=new_within_days):
            continue
        if expired_reason(job, now=now, after_days=expire_after_days):
            continue
        yield job


def quick_check_queue(jobs: list[StoredJob], policy: MatchingPolicy | None, *, now: dt.datetime,
                      watchlist: list[str], applied: AppliedIndex, expire_after_days: int = 0,
                      new_within_days: int = 0) -> list[tuple[StoredJob, RankInfo]]:
    """Current jobs that pass the filter but whose experience level is unknown, best first.
    A quick check ("Fresher OK" / "Too senior") moves them into or out of Apply today."""
    if policy is None or policy.experience.unknown_policy == "allow":
        return []
    out = []
    for job in _current(jobs, now=now, expire_after_days=expire_after_days, new_within_days=new_within_days):
        if not prefilter_job(job, policy).needs_check:
            continue
        info = rank_job(job, now=now, watchlist=watchlist, applied=applied, policy=policy)
        if not info.applied:
            out.append((job, info))
    out.sort(key=lambda p: sort_key(*p))
    return out


def new_strong_jobs(jobs: list[StoredJob], policy: MatchingPolicy | None, *, since: dt.datetime,
                    applied: AppliedIndex, threshold: float = NOTIFY_THRESHOLD, now: dt.datetime | None = None,
                    expire_after_days: int = 0) -> int:
    """Jobs first seen since ``since`` that scored ``threshold``+ (current candidates you haven't applied to)."""
    count = 0
    for job in jobs:
        if job.dismissed or job.score is None or job.score < threshold or job.received_at < since:
            continue
        if expired_reason(job, now=now or dt.datetime.now(dt.UTC), after_days=expire_after_days):
            continue
        if not apply_ready(job, policy):
            continue
        if applied.contains(job.company, job.title):
            continue
        count += 1
    return count
