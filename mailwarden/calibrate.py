"""`mailwarden jobs calibrate`: check the fit scores against your own judgement.

Shows scored jobs one at a time (a mix of high, mid and low scores); you answer
good / bad / skip. Labels are stored in the encrypted database and never sent anywhere.

The report compares your labels with the *current* scores:
- of the jobs you called good, how many scored 7+;
- of the jobs you called bad, how many scored below 5;
- the biggest disagreements, with the model's reason, to guide edits to profile.yaml
  or the rubric. Re-run after changes (once jobs are rescored) to see if it improved.
"""

from __future__ import annotations

import datetime as dt
import json
import random
from collections.abc import Callable
from dataclasses import dataclass
from typing import TextIO

from mailwarden.core.models import StoredJob
from mailwarden.storage.base import Repository

GOOD_AT = 7.0
BAD_BELOW = 5.0
HISTORY_KEY = "calibration_history"
BANDS = (("high", lambda s: s >= GOOD_AT, 7), ("mid", lambda s: BAD_BELOW <= s < GOOD_AT, 7),
         ("low", lambda s: s < BAD_BELOW, 6))


def sample(jobs: list[StoredJob], labelled: set[int], *, count: int, rng: random.Random) -> list[StoredJob]:
    """About 7 high, 7 mid and 6 low (scaled to ``count``); short bands are filled from the others."""
    pool = [j for j in jobs if j.score is not None and not j.dismissed and j.id not in labelled]
    by_band = {name: [j for j in pool if test(j.score)] for name, test, _ in BANDS}
    for band in by_band.values():
        rng.shuffle(band)
    picks: list[StoredJob] = []
    for name, _, share in BANDS:
        take = round(count * share / 20)
        picks += by_band[name][:take]
        by_band[name] = by_band[name][take:]
    leftovers = [j for band in by_band.values() for j in band]
    rng.shuffle(leftovers)
    picks += leftovers[: max(0, count - len(picks))]
    rng.shuffle(picks)
    return picks[:count]


def describe(job: StoredJob, n: int, total: int) -> str:
    lines = [
        f"\n[{n}/{total}]  {job.title}",
        f"  {job.company or 'Company not listed'} · {job.location or 'location not listed'}"
        f" · via {job.source_name or job.sender}",
        f"  score {job.score:.1f} ({job.score_level})",
    ]
    if job.why:
        lines.append(f"  why: {job.why}")
    if job.best_project:
        lines.append(f"  lead with: {job.best_project}")
    if job.missing_skills:
        lines.append(f"  missing: {', '.join(job.missing_skills[:6])}")
    return "\n".join(lines)


def run_session(repo: Repository, user_id: str, *, count: int, ask: Callable[[str], str], out: TextIO,
                rng: random.Random | None = None) -> int:
    """Label up to ``count`` jobs. Returns how many were labelled (good or bad)."""
    jobs = repo.list_jobs(user_id)
    labelled = {job_id for job_id, _, _ in repo.list_labels(user_id)}
    picks = sample(jobs, labelled, count=count, rng=rng or random.Random())
    if not picks:
        print("No unlabelled scored jobs right now: scores fill in on each sync.", file=out)
        return 0
    print("For each job: g = good (you'd apply), b = bad (not for you), s = skip, q = quit.", file=out)
    done = 0
    for n, job in enumerate(picks, 1):
        print(describe(job, n, len(picks)), file=out)
        while True:
            try:
                answer = ask("  good/bad/skip/quit [g/b/s/q]: ").strip().lower()[:1]
            except EOFError:
                answer = "q"
            if answer in ("g", "b", "s", "q"):
                break
        if answer == "q":
            break
        if answer in ("g", "b"):
            repo.save_label(user_id, job.id, "good" if answer == "g" else "bad",
                            score=job.score, level=job.score_level)
            done += 1
    print(f"\nSaved {done} label(s).", file=out)
    return done


@dataclass
class Agreement:
    good: int
    good_hits: int
    bad: int
    bad_hits: int
    disagreements: list[tuple[float, str, StoredJob, float | None]]

    @property
    def good_rate(self) -> float | None:
        return self.good_hits / self.good if self.good else None

    @property
    def bad_rate(self) -> float | None:
        return self.bad_hits / self.bad if self.bad else None


def agreement(repo: Repository, user_id: str) -> Agreement:
    jobs = {j.id: j for j in repo.list_jobs(user_id, include_dismissed=True)}
    good = good_hits = bad = bad_hits = 0
    misses: list[tuple[float, str, StoredJob, float | None]] = []
    for job_id, label, score_then in repo.list_labels(user_id):
        job = jobs.get(job_id)
        if job is None or job.score is None:
            continue
        if label == "good":
            good += 1
            if job.score >= GOOD_AT:
                good_hits += 1
            else:
                misses.append((GOOD_AT - job.score, "good", job, score_then))
        else:
            bad += 1
            if job.score < BAD_BELOW:
                bad_hits += 1
            else:
                misses.append((job.score - BAD_BELOW + 0.5, "bad", job, score_then))
    misses.sort(key=lambda m: -m[0])
    return Agreement(good, good_hits, bad, bad_hits, misses)


def _pct(hits: int, total: int) -> str:
    return f"{hits}/{total} ({round(100 * hits / total)}%)" if total else "no labels yet"


def print_report(repo: Repository, user_id: str, out: TextIO, *, now: dt.datetime, top: int = 8) -> Agreement:
    a = agreement(repo, user_id)
    history = json.loads(repo.get_state(user_id, HISTORY_KEY) or "[]")
    print("\n=== calibration report (labels vs current scores) ===", file=out)
    print(f"jobs you called good that scored {GOOD_AT:g}+:      {_pct(a.good_hits, a.good)}", file=out)
    print(f"jobs you called bad that scored below {BAD_BELOW:g}: {_pct(a.bad_hits, a.bad)}", file=out)
    if history:
        prev = history[-1]
        print(f"previous report ({prev['at'][:16].replace('T', ' ')}): good {_pct(prev['good_hits'], prev['good'])}, "
              f"bad {_pct(prev['bad_hits'], prev['bad'])}", file=out)
    if a.disagreements:
        print(f"\nbiggest disagreements (top {min(top, len(a.disagreements))}):", file=out)
        for _, label, job, then in a.disagreements[:top]:
            change = f" (was {then:.1f} when labelled)" if then is not None and abs(then - job.score) >= 0.5 else ""
            print(f"\n  you said {label.upper()}, scored {job.score:.1f} {job.score_level}{change}", file=out)
            print(f"  {job.title} · {job.company or '?'} · {job.location or '?'}", file=out)
            if job.why:
                print(f"  why: {job.why}", file=out)
            if job.missing_skills:
                print(f"  missing: {', '.join(job.missing_skills[:6])}", file=out)
            if label == "good" and job.score_level == "preliminary":
                print("  note: preliminary scores are capped at 7: paste the JD for a full score", file=out)
    if a.good or a.bad:
        history.append({"at": now.isoformat(), "good": a.good, "good_hits": a.good_hits,
                        "bad": a.bad, "bad_hits": a.bad_hits})
        repo.set_state(user_id, HISTORY_KEY, json.dumps(history[-20:]))
    return a
