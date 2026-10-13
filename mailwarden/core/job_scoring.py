"""Keep job descriptions and fit scores up to date. Depends only on interfaces.

- fetch_auto_jds: for candidate jobs hosted on Greenhouse/Lever/Ashby, fetch the JD via
  their public job-board APIs (cached 7 days, paced, capped per run).
- score_jobs: preliminary/full fit scores for candidates, only when inputs changed.
- Expired jobs (core.expiry) are neither fetched nor scored, so the LLM budget goes to
  current ones.
- JobActions: what the dashboard buttons do (fetch one JD, fetch top N, paste a JD),
  each followed by rescoring that job.

Scores only order jobs: nothing here hides or deletes a job.
"""

from __future__ import annotations

import datetime as dt
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from mailwarden.core import fit
from mailwarden.core.classify.base import BackendUnavailable, LLMBackend
from mailwarden.core.expiry import expired_reason, reference_time
from mailwarden.core.jd import DEFAULT_DENY, JDResult, acquire, fetch_outcome, from_paste, plan
from mailwarden.core.jd_fetch import PageRefused
from mailwarden.core.models import StoredJob
from mailwarden.core.policy import MatchingPolicy
from mailwarden.core.prefilter import prefilter_job
from mailwarden.storage.base import Repository

log = logging.getLogger(__name__)

JD_CACHE = dt.timedelta(days=7)

GetJson = Callable[[str], tuple[int, object]]
GetPage = Callable[[str], tuple[int, str]]


def is_candidate(job: StoredJob, policy: MatchingPolicy | None) -> bool:
    """Passes the prefilter (unknown experience included: its score ranks the quick-check list)."""
    return policy is None or not prefilter_job(job, policy).excluded


def _jd_fresh(job: StoredJob, now: dt.datetime) -> bool:
    return job.jd_fetched_at is not None and now - job.jd_fetched_at < JD_CACHE


@dataclass
class JDStats:
    tried: int = 0
    fetched: int = 0
    unavailable: int = 0
    reasons: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class PageSources:
    """How job pages are fetched (jd_fetch = "auto" | "button"): the polite page fetcher, public job JSON
    endpoints (Workday, SmartRecruiters) and the do-not-fetch list."""

    get_page: GetPage
    get_json: GetJson
    deny: tuple[str, ...] = DEFAULT_DENY


def fetch_auto_jds(repo: Repository, user_id: str, policy: MatchingPolicy | None, *, get_json: GetJson | None,
                   limit: int, now: dt.datetime, pause: float = 1.5, sleep: Callable[[float], None] = time.sleep,
                   expire_after_days: int = 0, pages: PageSources | None = None) -> JDStats:
    """Fetch JDs for current candidates, newest first: ATS APIs (``get_json``) and, with ``pages``
    (jd_fetch = "auto"), job pages on other sites. At most ``limit`` attempts per run."""
    stats = JDStats()
    board_cache: dict[str, tuple[int, object]] = {}

    def cached_json(url: str) -> tuple[int, object]:
        if url not in board_cache:  # Ashby returns a whole board: fetch it once per run
            if board_cache:
                sleep(pause)
            board_cache[url] = get_json(url)  # type: ignore[misc]
        return board_cache[url]

    jobs = repo.list_jobs(user_id)
    ref = reference_time(jobs, now)
    for job in jobs:  # newest first
        if stats.tried >= limit:
            break
        if job.jd_source == "paste" or job.jd_status in ("ok", "closed") or _jd_fresh(job, now):
            continue
        if not is_candidate(job, policy) or expired_reason(job, now=ref, after_days=expire_after_days):
            continue
        p = plan(job.link, denied=pages.deny if pages else DEFAULT_DENY)
        if p.automatic and get_json is not None:
            fetch_json, fetch_page = cached_json, (lambda url: (0, ""))
        elif pages is not None and p.kind in ("page", "workday", "smartrecruiters"):
            fetch_json, fetch_page = pages.get_json, pages.get_page
        else:
            continue
        stats.tried += 1
        result = _acquire(p, fetch_json, fetch_page)
        _record(repo, user_id, job, result, stats, url=p.url, now=now)
    return stats


def _acquire(p, get_json: GetJson, get_page: GetPage) -> JDResult:
    try:
        return acquire(p, get_json=get_json, get_page=get_page)
    except PageRefused as e:
        return JDResult.unavailable(f"{e}: open it in your browser and paste the JD")
    except Exception as e:  # network error, blocked by a network guard, bad JSON
        why = str(e) if type(e).__name__.endswith("Blocked") else type(e).__name__
        return JDResult.unavailable(f"Couldn't fetch the page ({why[:120]}): paste the JD")


def _record(repo: Repository, user_id: str, job: StoredJob, result: JDResult, stats: JDStats | None = None, *,
            url: str | None = None, now: dt.datetime | None = None) -> None:
    repo.save_jd(user_id, job.id, status=result.status, reason=result.reason, source=result.source, text=result.text)
    if url:
        host = (urlsplit(url).hostname or "?").lower()
        repo.record_fetch(user_id, host, fetch_outcome(result), now or dt.datetime.now(dt.UTC))
    if stats is not None:
        if result.status == "ok":
            stats.fetched += 1
        else:
            stats.unavailable += 1
            key = (result.reason or "unavailable").split(":")[0]
            stats.reasons[key] = stats.reasons.get(key, 0) + 1


DAILY_KEY = "fit_scores_today"


def scores_left_today(repo: Repository, user_id: str, per_day: int, now: dt.datetime) -> int | None:
    """How many fit scores today's budget still allows (None: no daily cap)."""
    if per_day <= 0:
        return None
    import json

    today = now.astimezone().date().isoformat()
    try:
        state = json.loads(repo.get_state(user_id, DAILY_KEY) or "{}")
    except ValueError:
        state = {}
    used = int(state.get("count", 0)) if state.get("date") == today else 0
    return max(0, per_day - used)


def count_scores(repo: Repository, user_id: str, n: int, now: dt.datetime) -> None:
    import json

    today = now.astimezone().date().isoformat()
    try:
        state = json.loads(repo.get_state(user_id, DAILY_KEY) or "{}")
    except ValueError:
        state = {}
    used = int(state.get("count", 0)) if state.get("date") == today else 0
    repo.set_state(user_id, DAILY_KEY, json.dumps({"date": today, "count": used + n}))


@dataclass
class ScoreStats:
    scored: int = 0
    preliminary: int = 0
    full: int = 0
    unchanged: int = 0
    failed: int = 0
    stopped: str | None = None


def score_jobs(repo: Repository, user_id: str, llm: LLMBackend, profile: dict, effective_skills: dict[str, float],
               *, limit: int, only_ids: set[int] | None = None, now: dt.datetime | None = None,
               expire_after_days: int = 0, policy: MatchingPolicy | None = None) -> ScoreStats:
    stats = ScoreStats()
    now = now or dt.datetime.now(dt.UTC)
    profile_p = fit.profile_payload(profile, effective_skills)
    every = repo.list_jobs(user_id)
    ref = reference_time(every, now)
    jobs = [j for j in every if only_ids is None or j.id in only_ids]
    # Unscored first, then those whose inputs changed; newest first within each.
    jobs.sort(key=lambda j: (j.score is not None, -j.received_at.timestamp()))
    for job in jobs:
        if stats.scored >= limit:
            break
        if only_ids is None and (not is_candidate(job, policy)
                                 or expired_reason(job, now=ref, after_days=expire_after_days)):
            continue
        job_p = fit.job_payload(job.title, job.company, job.location, job.details,
                                job.jd_text if job.jd_status == "ok" else None)
        h = fit.input_hash(profile_p, job_p)
        if job.score_hash == h:
            stats.unchanged += 1
            continue
        try:
            result = fit.score_job(llm, profile_p, job_p)
        except BackendUnavailable as e:
            stats.stopped = str(e)
            break
        if result is None:
            stats.failed += 1
            continue
        repo.save_score(user_id, job.id, score=result.score, level=result.level, detail=result.detail(), input_hash=h)
        stats.scored += 1
        if result.level == "full":
            stats.full += 1
        else:
            stats.preliminary += 1
    return stats


class JobActions:
    """Dashboard buttons. Every action is user-initiated (a CSRF-protected POST)."""

    def __init__(self, *, user_id: str, repo_factory: Callable[[], Repository], profile_loader: Callable[[], dict | None],
                 effective_skills: Callable[[dict], dict[str, float]], llm_factory: Callable[[], LLMBackend] | None,
                 auto_json: GetJson | None, pages: PageSources | None, deny: tuple[str, ...] = DEFAULT_DENY,
                 clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC)) -> None:
        self._user_id = user_id
        self._repo_factory = repo_factory
        self._profile_loader = profile_loader
        self._effective = effective_skills
        self._llm_factory = llm_factory
        self._auto_json = auto_json  # None: jd_auto_fetch = false
        self._pages = pages  # None: jd_fetch = "off"
        self.deny = pages.deny if pages else deny
        self._clock = clock

    @property
    def button_fetch_enabled(self) -> bool:
        return self._pages is not None

    def _rescore(self, repo: Repository, job_id: int) -> str:
        profile = self._profile_loader()
        if profile is None or self._llm_factory is None:
            return "Saved. Build your profile to get a fit score."
        try:
            stats = score_jobs(repo, self._user_id, self._llm_factory(), profile, self._effective(profile),
                               limit=1, only_ids={job_id})
        except Exception:
            log.exception("rescoring failed")
            return "Saved. Scoring will run on the next sync."
        if stats.stopped:
            return "Saved. The AI is unavailable right now; scoring will run on the next sync."
        return "Saved and rescored." if stats.scored or stats.unchanged else "Saved. Scoring failed; it will retry."

    def fetch(self, job_id: int) -> str:
        repo = self._repo_factory()
        try:
            job = repo.get_job(self._user_id, job_id)
            if job is None:
                return "Job not found."
            p = plan(job.link, denied=self.deny)
            if p.automatic and self._auto_json:
                get_json, get_page = self._auto_json, (lambda url: (0, ""))
            elif self._pages is not None:
                get_json, get_page = self._pages.get_json, self._pages.get_page
            elif p.kind != "none":
                return 'Fetching is off: set [job_alerts] jd_fetch = "button" (or "auto"), or paste the JD.'
            else:
                get_json, get_page = (lambda url: (0, None)), (lambda url: (0, ""))
            result = _acquire(p, get_json, get_page)
            _record(repo, self._user_id, job, result, url=p.url, now=self._clock())
            if result.status != "ok":
                return result.reason or "Not available."
            return "Job description fetched. " + self._rescore(repo, job_id)
        finally:
            repo.close()

    def fetch_top(self, job_ids: list[int]) -> str:
        done = 0
        for job_id in job_ids:
            self.fetch(job_id)
            done += 1
        return f"Tried {done} job description(s). Jobs that couldn't be fetched show why, with a paste box."

    def paste(self, job_id: int, text: str) -> str:
        repo = self._repo_factory()
        try:
            job = repo.get_job(self._user_id, job_id)
            if job is None:
                return "Job not found."
            result = from_paste(text)
            if result.status != "ok":
                return result.reason or "That doesn't look like a job description."
            _record(repo, self._user_id, job, result)
            return "Job description saved. " + self._rescore(repo, job_id)
        finally:
            repo.close()
