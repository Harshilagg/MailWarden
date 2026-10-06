"""`mailwarden jobs audit`: a weekly check that the ranking isn't hiding jobs you'd apply to.

Shows jobs from OUTSIDE the current "Apply today" list one at a time (a mix of filtered,
low-ranked and otherwise excluded jobs); you answer would-apply / no / skip. For every
would-apply it shows exactly why the job was left out (rule, weight, cap or role-family
limit). Answers and explanations are stored in the encrypted database, never sent anywhere.

The report counts audited and missed-good jobs, groups the reasons, and lists the
profile/config/rule change behind each. Nothing is changed automatically.
"""

from __future__ import annotations

import datetime as dt
import random
from collections.abc import Callable
from typing import TextIO

from mailwarden.core.models import StoredJob
from mailwarden.core.prefilter import prefilter_job
from mailwarden.core.recall import Context, Finding, explain, sample, summarise
from mailwarden.storage.base import Repository

LAST_AUDIT_KEY = "recall_audit_at"
AUDIT_EVERY = dt.timedelta(days=7)


def describe(job: StoredJob, ctx: Context, n: int, total: int) -> str:
    score = f"score {job.score:.1f} ({job.score_level})" if job.score is not None else "not scored yet"
    lines = [
        f"\n[{n}/{total}]  {job.title}",
        f"  {job.company or 'Company not listed'} · {job.location or 'location not listed'}"
        f" · via {job.source_name or job.sender}",
        f"  {score}",
    ]
    if ctx.profile is not None and (verdict := prefilter_job(job, ctx.profile)).excluded:
        lines.append(f"  filtered: {'; '.join(verdict.reasons)}")
    return "\n".join(lines)


def format_findings(findings: list[Finding]) -> str:
    lines = ["  Why it wasn't in Apply today:"]
    for f in findings:
        lines.append(f"   - {f.detail}")
        if f.suggestion:
            lines.append(f"     -> {f.suggestion}")
    return "\n".join(lines)


def run_session(repo: Repository, user_id: str, ctx: Context, *, count: int, ask: Callable[[str], str],
                out: TextIO, rng: random.Random | None = None) -> tuple[int, int]:
    """Audit up to ``count`` jobs. Returns (answered, would-apply)."""
    audited = {a.job_id for a in repo.list_audits(user_id)}
    picks = sample(ctx, audited=audited, count=count, rng=rng or random.Random())
    if not picks:
        print("No jobs outside Apply today left to audit.", file=out)
        return 0, 0
    print(f"These {len(picks)} jobs are NOT in today's Apply today ({len(ctx.picks)} jobs): some filtered, some "
          "ranked lower, some excluded for other reasons.\nFor each: y = I'd apply, n = no, s = skip, q = quit.",
          file=out)
    answered = would = 0
    for n, job in enumerate(picks, 1):
        print(describe(job, ctx, n, len(picks)), file=out)
        while True:
            try:
                answer = ask("  would you apply? [y/n/s/q]: ").strip().lower()[:1]
            except EOFError:
                answer = "q"
            if answer in ("y", "n", "s", "q"):
                break
        if answer == "q":
            break
        if answer == "s":
            continue
        findings = explain(job, ctx)
        if answer == "y":
            print(format_findings(findings), file=out)
            would += 1
        repo.save_audit(user_id, job.id, "apply" if answer == "y" else "no", [f.to_dict() for f in findings],
                        score=job.score, level=job.score_level, at=ctx.now)
        answered += 1
    if answered:
        repo.set_state(user_id, LAST_AUDIT_KEY, ctx.now.isoformat())
    print(f"\nSaved {answered} answer(s): {would} you'd apply to.", file=out)
    return answered, would


def _pct(part: int, whole: int) -> str:
    return f"{part}/{whole} ({round(100 * part / whole)}%)" if whole else "0"


def print_report(repo: Repository, user_id: str, out: TextIO, *, now: dt.datetime, top: int = 10) -> None:
    audits = repo.list_audits(user_id)
    print("\n=== recall audit report ===", file=out)
    if not audits:
        print("No audits yet: run `mailwarden jobs audit`.", file=out)
        return
    week = [a for a in audits if now - a.audited_at <= AUDIT_EVERY]
    for label, rows in (("last 7 days", week), ("all time", audits)):
        s = summarise((a.answer, []) for a in rows)
        print(f"{label:>11}: {s.audited} audited, {_pct(s.would_apply, s.audited)} missed-good "
              "(you'd apply, but they weren't in Apply today)", file=out)
    summary = summarise((a.answer, [Finding.from_dict(f) for f in a.findings]) for a in audits)
    if not summary.would_apply:
        print("\nNo missed-good jobs: the ranking hasn't hidden anything you'd apply to.", file=out)
        return
    print("\nWhy the jobs you'd apply to were left out (jobs per reason):", file=out)
    for label, n in summary.causes:
        print(f"  {n:>3}  {label}", file=out)
    if summary.suggestions:
        print("\nSuggested changes (jobs each would have surfaced). Nothing changes until you make it:", file=out)
        for text, n in summary.suggestions:
            print(f"  {n:>3}  {text}", file=out)
    jobs = {j.id: j for j in repo.list_jobs(user_id, include_dismissed=True)}
    missed = [a for a in reversed(audits) if a.answer == "apply"][:top]
    print(f"\nMissed-good jobs (latest {len(missed)}):", file=out)
    for a in missed:
        job = jobs.get(a.job_id)
        title = f"{job.title} · {job.company or '?'}" if job else f"job {a.job_id} (no longer stored)"
        score = f"{a.score:.1f} {a.score_level}" if a.score is not None else "unscored"
        print(f"\n  {title}  [{score}, audited {a.audited_at.date().isoformat()}]", file=out)
        print(format_findings([Finding.from_dict(f) for f in a.findings]), file=out)


def audit_due(repo: Repository, user_id: str, now: dt.datetime) -> int | None:
    """Days since the last audit when one is due (None: not due). -1 = never audited."""
    last = repo.get_state(user_id, LAST_AUDIT_KEY)
    if not last:
        return -1
    age = now - dt.datetime.fromisoformat(last)
    return age.days if age >= AUDIT_EVERY else None
