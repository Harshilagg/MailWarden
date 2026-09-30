import datetime as dt

import pytest

from mailwarden.core.models import Application, Stage, StoredJob
from mailwarden.core.ranking import AppliedIndex, apply_today, new_strong_jobs, on_watchlist, rank_job

NOW = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.UTC)
PROFILE = {"avoid_roles": ["sales"], "locations": ["Bengaluru", "Remote", "Delhi NCR"], "remote_ok": True}


def job(i, title="Backend Engineer", company="Acme", score=7.0, level="full", days=1, location="Bengaluru",
        dismissed=False):
    return StoredJob(id=i, user_id="local", title=title, company=company, location=location, link=None,
                     sender="LinkedIn", account="p", message_id="m", received_at=NOW - dt.timedelta(days=days),
                     dismissed=dismissed, score=score, score_level=level)


def app(company, role=None):
    return Application(user_id="local", company=company, role=role, current_stage=Stage.APPLIED, last_update=NOW)


NONE = AppliedIndex()


def test_rank_parts():
    r = rank_job(job(1, days=1), now=NOW, watchlist=["Acme"], applied=NONE)
    assert r.rank == 8.5 and r.parts == ("score 7.0 (full)", "fresh +0.5", "watchlist +1") and r.watchlist
    assert rank_job(job(1, days=10), now=NOW, watchlist=[], applied=NONE).rank == 7.0
    assert rank_job(job(1, days=30), now=NOW, watchlist=[], applied=NONE).rank == 6.0
    assert rank_job(job(1, score=None), now=NOW, watchlist=[], applied=NONE).rank is None


def test_watchlist_matching():
    assert on_watchlist("Razorpay Software Pvt Ltd", ["razorpay"])
    assert on_watchlist("Amazon Development Centre", ["Amazon"])
    assert not on_watchlist("Amazonia Foods", ["Amazon"])
    assert not on_watchlist(None, ["Amazon"])


def test_applied_index():
    idx = AppliedIndex.from_applications([app("Acme Pvt Ltd", "Backend Engineer"), app("Zeta")])
    assert idx.contains("Acme", "Backend Engineer")
    assert not idx.contains("Acme", "Data Scientist")  # same company, different role: still shown
    assert idx.contains("Zeta", "Anything")  # role unknown: the company counts as applied
    assert not idx.contains("Globex", "Backend Engineer")


def test_apply_today_selection_and_order():
    jobs = [
        job(1, "Backend Engineer", "Acme", 7.0, "preliminary", days=1),
        job(2, "SDE 1", "Zeta", 7.0, "full", days=10),
        job(3, "Senior Backend Engineer", "Old", 9.5),        # prefiltered: seniority
        job(4, "Platform Engineer", "Applied Co", 9.0),        # already applied
        job(5, "Backend Developer", "Dismissed", 9.0, dismissed=True),
        job(6, "Backend Developer", "Unscored", None),
        job(7, "Sales Engineer", "Globex", 9.0),               # avoid role
        job(8, "Go Developer", "Watched", 6.5, days=5),        # watchlist 6.5 + 1
        job(9, "Backend Engineer", "Stale", 7.5, days=40),     # 7.5 - 1
    ]
    applied = AppliedIndex.from_applications([app("Applied Co", "Platform Engineer")])
    picks = apply_today(jobs, PROFILE, n=8, now=NOW, watchlist=["Watched"], applied=applied)
    assert [j.id for j, _ in picks] == [8, 1, 2, 9]
    # rank 7.5 (1, fresh) = 7.5 (8, watchlist); full before preliminary only at equal rank -> 8 is full
    top = apply_today(jobs, PROFILE, n=1, now=NOW, watchlist=["Watched"], applied=applied)
    assert len(top) == 1


def test_full_beats_preliminary_at_equal_rank():
    jobs = [job(1, company="A", score=7.0, level="preliminary", days=10),
            job(2, company="B", score=7.0, level="full", days=10)]
    assert [j.id for j, _ in apply_today(jobs, PROFILE, n=2, now=NOW, watchlist=[], applied=NONE)] == [2, 1]


def test_new_strong_jobs():
    jobs = [job(1, score=7.0, days=0), job(2, score=6.5, days=0), job(3, score=9.0, days=5),
            job(4, "Senior Engineer", score=9.0, days=0), job(5, company="Applied Co", score=8.0, days=0)]
    applied = AppliedIndex.from_applications([app("Applied Co", "Backend Engineer")])
    assert new_strong_jobs(jobs, PROFILE, since=NOW - dt.timedelta(days=1), applied=applied) == 1
