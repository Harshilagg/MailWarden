"""Recall audit: did the ranking miss jobs you'd apply to? Pure logic, no I/O.

``sample`` draws jobs from OUTSIDE the current "Apply today" list: a mix of filtered,
low-ranked and otherwise excluded (expired, outside the window, not scored yet) jobs.
``explain`` replays the Apply today pipeline for one job and says exactly why it was
left out (rule, weight, cap or role-family limit), each with a suggested change.
``summarise`` groups the reasons behind every "would apply" answer for the report.

Suggestions are only text: nothing here changes the profile or the rules.
"""

from __future__ import annotations

import datetime as dt
import math
import random
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from mailwarden.core.expiry import expired_reason
from mailwarden.core.fit import CS_DEGREE, PRELIMINARY_CAP
from mailwarden.core.models import StoredJob
from mailwarden.core.prefilter import prefilter_job
from mailwarden.core.ranking import AppliedIndex, RankInfo, apply_today, rank_job, role_family

LOW_WEIGHT = 0.5  # a matched skill below this weight is suggested for a raise
# Share of a 15-job sample: filtered, low-ranked candidates, and everything else.
_STRATA = (("filtered", 6), ("low_rank", 6), ("other", 3))


@dataclass(frozen=True)
class Finding:
    kind: str  # not_scored | expired | window | filter | applied | family_cap | rank | preliminary | cap | skill
    detail: str  # what happened, in plain words
    suggestion: str | None = None  # the change that would have surfaced it (None: nothing to change)
    key: str = ""  # groups the same cause across jobs in the report

    def to_dict(self) -> dict:
        return {"kind": self.kind, "detail": self.detail, "suggestion": self.suggestion, "key": self.key}

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(str(d.get("kind", "")), str(d.get("detail", "")), d.get("suggestion"), str(d.get("key", "")))


@dataclass
class Context:
    """Everything Apply today used, so a job's exclusion can be replayed exactly."""

    jobs: list[StoredJob]
    profile: dict | None
    effective_skills: dict[str, float]
    now: dt.datetime
    n: int
    watchlist: list[str]
    applied: AppliedIndex
    expire_after_days: int = 0
    window_days: int = 0
    family_share: float = 0.0
    picks: list[tuple[StoredJob, RankInfo]] = field(init=False)
    uncapped_ids: set[int] = field(init=False)

    def __post_init__(self) -> None:
        kw = dict(n=self.n, now=self.now, watchlist=self.watchlist, applied=self.applied,
                  expire_after_days=self.expire_after_days, new_within_days=self.window_days)
        self.picks = apply_today(self.jobs, self.profile, max_family_share=self.family_share, **kw)
        self.uncapped_ids = {j.id for j, _ in apply_today(self.jobs, self.profile, max_family_share=0.0, **kw)}

    @property
    def pick_ids(self) -> set[int]:
        return {j.id for j, _ in self.picks}

    @property
    def cutoff(self) -> float | None:
        """The lowest rank that made Apply today, when the list is full (else rank wasn't the limit)."""
        ranks = [info.rank for _, info in self.picks if info.rank is not None]
        return min(ranks) if len(self.picks) >= self.n and ranks else None

    @property
    def family_cap(self) -> int:
        return max(2, math.ceil(self.n * self.family_share))


# --- sampling --------------------------------------------------------------------------------

def stratum(job: StoredJob, ctx: Context) -> str:
    if ctx.profile is not None and prefilter_job(job, ctx.profile).excluded:
        return "filtered"
    if (job.score is not None and not expired_reason(job, now=ctx.now, after_days=ctx.expire_after_days)
            and not _outside_window(job, ctx)):
        return "low_rank"
    return "other"


def sample(ctx: Context, *, audited: set[int], count: int, rng: random.Random) -> list[StoredJob]:
    """Up to ``count`` jobs outside Apply today, never dismissed or already audited."""
    picked = ctx.pick_ids
    pool = [j for j in ctx.jobs if not j.dismissed and j.id not in picked and j.id not in audited]
    groups: dict[str, list[StoredJob]] = {name: [] for name, _ in _STRATA}
    for job in pool:
        groups[stratum(job, ctx)].append(job)
    for group in groups.values():
        rng.shuffle(group)
    out: list[StoredJob] = []
    for name, share in _STRATA:
        take = round(count * share / 15)
        out += groups[name][:take]
        groups[name] = groups[name][take:]
    rest = [j for g in groups.values() for j in g]
    rng.shuffle(rest)
    out += rest[: max(0, count - len(out))]
    rng.shuffle(out)
    return out[:count]


# --- explaining one job ----------------------------------------------------------------------

def _outside_window(job: StoredJob, ctx: Context) -> bool:
    return ctx.window_days > 0 and ctx.now - job.received_at > dt.timedelta(days=ctx.window_days)


def _filter_finding(reason: str) -> Finding:
    """A prefilter reason, with the profile/rule change that would let the job through."""
    if m := re.match(r"seniority \((.+)\)$", reason):
        word = m.group(1).lower()
        return Finding("filter", f"seniority rule: the title contains '{word}'",
                       f"rule change: stop treating '{word}' in a title as too senior", f"seniority:{word}")
    if m := re.match(r"level above new grad \((.+)\)$", reason):
        return Finding("filter", f"level rule: '{m.group(1)}' in the title is above new grad",
                       "paste the job description: the level rule is waived when it says 0-2 years or fresher",
                       "level")
    if m := re.match(r"needs (\d+)\+ years$", reason):
        n = int(m.group(1))
        return Finding("filter", f"experience rule: asks for {n}+ years (limit is 2)",
                       f"rule change: allow roles asking up to {n} years", f"years:{n}")
    if m := re.match(r"avoid role: (.+?)(?: \((.+)\))?$", reason):
        entry, hint = m.group(1), m.group(2)
        why = f" ({hint})" if hint else ""
        return Finding("filter", f"avoid_roles entry '{entry}' matched{why}",
                       f"profile.yaml: remove or narrow '{entry}' in avoid_roles", f"avoid:{entry}")
    if m := re.match(r"location \((.+)\)$", reason):
        place = m.group(1).split(",")[0].strip()
        return Finding("filter", f"location rule: '{m.group(1)}' is not in your locations",
                       f"profile.yaml: add '{place}' to locations", f"location:{place.lower()}")
    if reason.endswith(" role"):  # security-only / sales / support / non-engineering categories
        category = "security only" if reason.startswith("security-only") else reason[: -len(" role")]
        return Finding("filter", f"avoid_roles category '{category}' matched",
                       f"profile.yaml: remove '{category}' from avoid_roles", f"avoid:{category}")
    return Finding("filter", reason, "review this prefilter rule", f"filter:{reason}")


def _skill_findings(job: StoredJob, skills: dict[str, float]) -> list[Finding]:
    out = []
    weights = {k.lower(): v for k, v in skills.items()}
    for skill in job.matched_skills[:8]:
        w = weights.get(skill.lower())
        if w is not None and w < LOW_WEIGHT:
            out.append(Finding("skill", f"matched '{skill}', but its weight is only {w:.2f}",
                               f"profile.yaml skill_overrides: raise '{skill}' (now {w:.2f}) if it's a real strength",
                               f"raise:{skill.lower()}"))
    for skill in job.missing_skills[:3]:
        if skill == CS_DEGREE:
            out.append(Finding("skill", "the job description asks for a CS/IT degree", None, "cs_degree"))
        elif skill.lower() not in weights:
            out.append(Finding("skill", f"counted as missing: '{skill}'",
                               f"profile.yaml skill_overrides: add '{skill}' if you have it", f"add:{skill.lower()}"))
    return out


def explain(job: StoredJob, ctx: Context) -> list[Finding]:
    """Why ``job`` isn't in Apply today, most decisive reason first."""
    if job.id in ctx.pick_ids:
        return [Finding("picked", "it is in Apply today", None, "picked")]
    if job.dismissed:
        return [Finding("dismissed", "you dismissed it", None, "dismissed")]
    found: list[Finding] = []
    if ctx.profile is not None:  # the prefilter decides first: filtered jobs are never scored
        found += [_filter_finding(r) for r in prefilter_job(job, ctx.profile).reasons]
    reason = expired_reason(job, now=ctx.now, after_days=ctx.expire_after_days)
    if reason:
        if job.jd_status == "closed" or "closed" in reason:
            found.append(Finding("expired", f"expired: {reason}", None, "closed"))
        else:
            found.append(Finding("expired", f"expired: {reason} (limit {ctx.expire_after_days} days)",
                                 f"config: raise [job_alerts] expire_after_days (now {ctx.expire_after_days})",
                                 "expired_age"))
    if _outside_window(job, ctx):
        days = (ctx.now - job.received_at).days
        found.append(Finding("window", f"first seen {days} days ago; Apply today takes the last {ctx.window_days}",
                             f"config: raise [job_alerts] apply_today_days (now {ctx.window_days})", "window"))
    if job.score is None and not found:  # a current candidate the scorer hasn't reached yet
        found.append(Finding("not_scored", "not scored yet (still in the scoring queue)",
                             "config: raise [job_alerts] max_scores_per_run, or wait for the next syncs",
                             "not_scored"))
    info = rank_job(job, now=ctx.now, watchlist=ctx.watchlist, applied=ctx.applied)
    if info.applied:
        found.append(Finding("applied", "its company and role are already in your Applications", None, "applied"))
    if found or info.rank is None:
        return found
    # It was eligible: only the family cap or its rank kept it out.
    if job.id in ctx.uncapped_ids:
        family = role_family(job.title) or "?"
        return [Finding("family_cap", f"role-family limit: '{family}' already had {ctx.family_cap} of {ctx.n} slots",
                        f"config: raise [job_alerts] max_family_share (now {ctx.family_share:g}) or set it to 0",
                        f"family:{family}")]
    cutoff = ctx.cutoff
    parts = " · ".join(info.parts)
    if cutoff is not None and info.rank >= cutoff:
        found.append(Finding("rank", f"rank {info.rank:.1f} ({parts}) tied with the cutoff for the top {ctx.n}, and "
                                     "lost the tie-break: full scores, higher scores, then newer jobs go first",
                             None, "tie"))
    else:
        below = f", below the cutoff of {cutoff:.1f} for the top {ctx.n}" if cutoff is not None else ""
        found.append(Finding("rank", f"rank {info.rank:.1f} ({parts}){below}", None, "rank"))
    if job.score_level == "preliminary":
        cap = (f"; it hit the {PRELIMINARY_CAP:g} cap for title-only scores" if job.score is not None
               and job.score >= PRELIMINARY_CAP else "")
        found.append(Finding("preliminary", f"scored from the alert title only, without the job description{cap}",
                             "paste or fetch the job description for a full score", "preliminary"))
    elif job.score is not None and job.missing_skills and job.score <= 6:
        # (A JD asking 3+ years never gets here: the prefilter's experience rule catches it first.)
        found.append(Finding("cap", f"missing must-have skill(s) cap the score at 6: "
                                    f"{', '.join(job.missing_skills[:3])}", None, "cap:must_have"))
    if any(p.startswith("older than") for p in info.parts):
        found.append(Finding("rank", f"stale: first seen {(ctx.now - job.received_at).days} days ago (-1)", None,
                             "stale"))
    found += _skill_findings(job, ctx.effective_skills)
    return found


# --- the report ------------------------------------------------------------------------------

_KIND_LABELS = {
    "filter": "prefilter rule", "expired": "expired", "window": "outside the Apply today window",
    "not_scored": "not scored yet", "applied": "already applied", "family_cap": "role-family limit",
    "rank": "ranked out of the top (below or tied at the cutoff)", "preliminary": "preliminary score (title only)", "cap": "score cap",
    "skill": "skill weights",
}


@dataclass
class Summary:
    audited: int
    would_apply: int
    causes: list[tuple[str, int]]  # (cause label, jobs)
    suggestions: list[tuple[str, int]]  # (suggestion, jobs)


def summarise(audits: Iterable[tuple[str, list[Finding]]]) -> Summary:
    """``audits``: (answer, findings) per audited job. Counts each cause once per job."""
    audited = would = 0
    causes: dict[str, int] = {}
    suggestions: dict[str, int] = {}
    for answer, findings in audits:
        audited += 1
        if answer != "apply":
            continue
        would += 1
        for label in {_KIND_LABELS.get(f.kind, f.kind) for f in findings if f.kind in _KIND_LABELS}:
            causes[label] = causes.get(label, 0) + 1
        for text in {f.suggestion for f in findings if f.suggestion}:
            suggestions[text] = suggestions.get(text, 0) + 1
    order = lambda kv: (-kv[1], kv[0])  # noqa: E731
    return Summary(audited, would, sorted(causes.items(), key=order), sorted(suggestions.items(), key=order))
