"""Keep job descriptions and fit scores up to date. Depends only on interfaces.

- fetch_auto_jds: for candidate jobs hosted on Greenhouse/Lever/Ashby, fetch the JD via
  their public job-board APIs (cached 7 days, paced, capped per run).
- score_jobs: preliminary/full fit scores for candidates, only when inputs changed.
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

from mailwarden.core import fit
from mailwarden.core.classify.base import BackendUnavailable, LLMBackend
from mailwarden.core.jd import JDResult, acquire, from_paste, plan
from mailwarden.core.models import StoredJob
from mailwarden.core.prefilter import prefilter
from mailwarden.storage.base import Repository

log = logging.getLogger(__name__)

JD_CACHE = dt.timedelta(days=7)

GetJson = Callable[[str], tuple[int, object]]
GetPage = Callable[[str], tuple[int, str]]


def is_candidate(job: StoredJob, profile: dict) -> bool:
    return not prefilter(job.title, job.location, profile, jd_text=job.jd_text).excluded


def _jd_fresh(job: StoredJob, now: dt.datetime) -> bool:
    return job.jd_fetched_at is not None and now - job.jd_fetched_at < JD_CACHE


@dataclass
class JDStats:
    tried: int = 0
    fetched: int = 0
    unavailable: int = 0
    reasons: dict[str, int] = field(default_factory=dict)


def fetch_auto_jds(repo: Repository, user_id: str, profile: dict, *, get_json: GetJson, limit: int,
                   now: dt.datetime, pause: float = 1.5, sleep: Callable[[float], None] = time.sleep) -> JDStats:
    stats = JDStats()
    board_cache: dict[str, tuple[int, object]] = {}

    def cached_json(url: str) -> tuple[int, object]:
        if url not in board_cache:  # Ashby returns a whole board: fetch it once per run
            if board_cache:
                sleep(pause)
            board_cache[url] = get_json(url)
        return board_cache[url]

    for job in repo.list_jobs(user_id):
        if stats.tried >= limit:
            break
        if job.jd_source == "paste" or _jd_fresh(job, now) or not is_candidate(job, profile):
            continue
        p = plan(job.link)
        if not p.automatic:
            continue
        stats.tried += 1
        try:
            result = acquire(p, get_json=cached_json, get_page=lambda url: (0, ""))
        except Exception as e:  # network error, blocked, bad JSON
            result = JDResult.unavailable(f"Couldn't reach {p.kind.title()} ({type(e).__name__}); will retry later")
        _record(repo, user_id, job, result, stats)
    return stats


def _record(repo: Repository, user_id: str, job: StoredJob, result: JDResult, stats: JDStats | None = None) -> None:
    repo.save_jd(user_id, job.id, status=result.status, reason=result.reason, source=result.source, text=result.text)
    if stats is not None:
        if result.status == "ok":
            stats.fetched += 1
        else:
            stats.unavailable += 1
            key = (result.reason or "unavailable").split(":")[0]
            stats.reasons[key] = stats.reasons.get(key, 0) + 1


@dataclass
class ScoreStats:
    scored: int = 0
    preliminary: int = 0
    full: int = 0
    unchanged: int = 0
    failed: int = 0
    stopped: str | None = None


def score_jobs(repo: Repository, user_id: str, llm: LLMBackend, profile: dict, effective_skills: dict[str, float],
               *, limit: int, only_ids: set[int] | None = None) -> ScoreStats:
    stats = ScoreStats()
    profile_p = fit.profile_payload(profile, effective_skills)
    jobs = [j for j in repo.list_jobs(user_id) if only_ids is None or j.id in only_ids]
    # Unscored first, then those whose inputs changed; newest first within each.
    jobs.sort(key=lambda j: (j.score is not None, -j.received_at.timestamp()))
    for job in jobs:
        if stats.scored >= limit:
            break
        if only_ids is None and not is_candidate(job, profile):
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
                 auto_json: GetJson | None, button_json: GetJson | None, button_page: GetPage | None) -> None:
        self._user_id = user_id
        self._repo_factory = repo_factory
        self._profile_loader = profile_loader
        self._effective = effective_skills
        self._llm_factory = llm_factory
        self._auto_json = auto_json  # None: jd_auto_fetch = false
        self._button_json = button_json  # None: jd_button_fetch = false
        self._button_page = button_page

    @property
    def button_fetch_enabled(self) -> bool:
        return self._button_page is not None

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
            p = plan(job.link)
            get_json = self._auto_json if p.automatic and self._auto_json else self._button_json
            if p.kind != "none" and get_json is None:
                return "Fetching is off: set [job_alerts] jd_button_fetch = true, or paste the JD."
            try:
                result = acquire(p, get_json=get_json or (lambda url: (0, None)),
                                 get_page=self._button_page or (lambda url: (0, "")))
            except Exception as e:
                result = JDResult.unavailable(f"Couldn't fetch the job description ({type(e).__name__}): paste it instead")
            _record(repo, self._user_id, job, result)
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
