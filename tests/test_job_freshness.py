"""Stale jobs expire (never deleted), Apply today is a varied daily shortlist, stipends mark internships."""

import datetime as dt

import pytest

from mailwarden.core import jd
from mailwarden.core.expiry import expired_reason
from mailwarden.core.job_alerts import dedup_key
from mailwarden.core.job_scoring import fetch_auto_jds, score_jobs
from mailwarden.core.models import JobPost, StoredJob
from mailwarden.core.prefilter import is_stipend, prefilter, prefilter_job
from mailwarden.core.ranking import AppliedIndex, apply_today, new_strong_jobs, role_family
from mailwarden.storage.sqlite_store import SQLCipherRepository
from tests.test_dashboard import PROFILE as DASH_PROFILE
from tests.test_dashboard import client, env  # noqa: F401  (fixture)

NOW = dt.datetime(2026, 10, 5, 12, 0, tzinfo=dt.UTC)
NONE = AppliedIndex()
PROFILE = {"avoid_roles": ["intern / internship"], "locations": ["Bengaluru", "Remote"], "remote_ok": True}


def job(i, title="Backend Engineer", *, score=6.0, days=1, last_seen_days=None, jd_status=None, jd_text=None,
        details=None, level="preliminary"):
    return StoredJob(
        id=i, user_id="local", title=title, company=f"Co{i}", location="Bengaluru", link=None, sender="LinkedIn",
        account="p", message_id="m", received_at=NOW - dt.timedelta(days=days), details=details,
        last_seen_at=NOW - dt.timedelta(days=last_seen_days) if last_seen_days is not None else None,
        jd_status=jd_status, jd_text=jd_text, score=score, score_level=level)


# --- expiry ------------------------------------------------------------------------------

def test_expires_by_last_sighting_not_first():
    assert expired_reason(job(1, days=20), now=NOW, after_days=14) == "not in any alert for 20 days"
    assert expired_reason(job(1, days=20, last_seen_days=2), now=NOW, after_days=14) is None  # still advertised
    assert expired_reason(job(1, days=10), now=NOW, after_days=14) is None
    assert expired_reason(job(1, days=400), now=NOW, after_days=0) is None  # 0 = never by age


def test_closed_postings_expire_whatever_their_age():
    closed = job(1, days=0, jd_status="closed")
    assert expired_reason(closed, now=NOW, after_days=0) == "the posting was removed"
    text = "About the role\nThis position has been filled. Thank you for your interest."
    assert expired_reason(job(2, days=0, jd_status="ok", jd_text=text), now=NOW, after_days=14) == \
        "the job description says it is closed"
    open_text = "We are hiring backend engineers to build open systems. Apply now."
    assert expired_reason(job(3, days=0, jd_status="ok", jd_text=open_text), now=NOW, after_days=14) is None


def test_hiring_systems_report_removed_postings_as_closed():
    gh = jd.plan("https://boards.greenhouse.io/acme/jobs/1")
    for status in (404, 410):
        r = jd.acquire(gh, get_json=lambda u, s=status: (s, None), get_page=None)
        assert r.status == "closed" and f"HTTP {status}" in r.reason
    assert jd.acquire(gh, get_json=lambda u: (500, None), get_page=None).status == "unavailable"  # not proof
    ashby = jd.plan("https://jobs.ashbyhq.com/acme/0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b")
    assert ashby.kind == "ashby"
    board = {"jobs": [{"id": "other", "descriptionPlain": "x" * 500}]}
    r = jd.acquire(ashby, get_json=lambda u: (200, board), get_page=None)
    assert r.status == "closed" and "no longer on the company's job board" in r.reason


@pytest.fixture
def repo(tmp_path, secret_store):
    r = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    yield r
    r.close()


def _save(repo, posts, *, message_id, when):
    repo.save_jobs("local", account="p", message_id=message_id, sender="LinkedIn", received_at=when, posts=posts,
                   keys=[dedup_key(p, "x") for p in posts])


def test_store_tracks_last_sighting_and_lists_every_job(repo):
    post = JobPost(title="Backend Engineer", company="Acme", location="Bengaluru",
                   link="https://boards.greenhouse.io/acme/jobs/1")
    _save(repo, [post], message_id="m1", when=NOW - dt.timedelta(days=20))
    _save(repo, [post], message_id="m2", when=NOW - dt.timedelta(days=2))  # the same job, advertised again
    (stored,) = repo.list_jobs("local")
    assert stored.received_at == NOW - dt.timedelta(days=20)
    assert stored.last_seen_at == NOW - dt.timedelta(days=2)
    assert expired_reason(stored, now=NOW, after_days=14) is None
    many = [JobPost(title=f"Engineer {i}", company=f"C{i}", location="Bengaluru", link=None) for i in range(520)]
    _save(repo, many, message_id="m3", when=NOW)
    assert len(repo.list_jobs("local")) == 521  # no silent cap at 500


class _LLM:
    def __init__(self):
        self.calls = 0

    def score_fit(self, messages):
        self.calls += 1
        return ('{"score": 6, "matched_skills": [], "missing_skills": [], "evidence": [], "best_project": null, '
                '"why": "Fine."}')


def test_expired_jobs_are_not_fetched_or_scored(repo):
    fresh = JobPost(title="Backend Engineer", company="Fresh", location="Bengaluru",
                    link="https://boards.greenhouse.io/fresh/jobs/1")
    stale = JobPost(title="Platform Engineer", company="Stale", location="Bengaluru",
                    link="https://boards.greenhouse.io/stale/jobs/2")
    _save(repo, [fresh], message_id="m1", when=NOW - dt.timedelta(days=1))
    _save(repo, [stale], message_id="m2", when=NOW - dt.timedelta(days=30))
    urls = []
    fetch_auto_jds(repo, "local", PROFILE, get_json=lambda u: (urls.append(u), (404, None))[1], limit=10, now=NOW,
                   sleep=lambda s: None, expire_after_days=14)
    assert urls == ["https://boards-api.greenhouse.io/v1/boards/fresh/jobs/1"]
    by_company = {j.company: j for j in repo.list_jobs("local")}
    assert by_company["Fresh"].jd_status == "closed"  # 404: the posting is gone
    llm = _LLM()
    st = score_jobs(repo, "local", llm, PROFILE, {"go": 0.5}, limit=10, now=NOW, expire_after_days=14)
    assert llm.calls == 0 and st.scored == 0  # one closed, one stale: nothing worth an LLM call


# --- Apply today ---------------------------------------------------------------------------

def test_apply_today_window_and_expiry():
    jobs = [job(1, days=1), job(2, days=5), job(3, days=1, jd_status="closed"), job(4, days=0, score=None)]
    ids = [j.id for j, _ in apply_today(jobs, PROFILE, n=10, now=NOW, watchlist=[], applied=NONE,
                                        expire_after_days=14, new_within_days=3)]
    assert ids == [1]  # 2 is older than the window, 3 is closed, 4 isn't scored yet
    ids = [j.id for j, _ in apply_today(jobs, PROFILE, n=10, now=NOW, watchlist=[], applied=NONE)]
    assert ids == [1, 2]  # no window and no age limit, but a closed posting is always expired


def test_one_role_family_cannot_take_every_slot():
    go = [job(i, "Golang Developer", score=7.0) for i in range(1, 8)]
    other = [job(10, "Full Stack Engineer", score=5.0), job(11, "Java Developer", score=5.0),
             job(12, "Software Engineer", score=4.5), job(13, "SDE 1", score=4.0)]
    picks = apply_today(go + other, PROFILE, n=8, now=NOW, watchlist=[], applied=NONE, max_family_share=0.25)
    titles = [j.title for j, _ in picks]
    assert titles.count("Golang Developer") == 4  # 25% of 8 = 2 ... then backfilled to fill all 8 slots
    assert {"Full Stack Engineer", "Java Developer", "Software Engineer", "SDE 1"} <= set(titles)
    assert len(picks) == 8
    plenty = go + [job(20 + i, "Software Engineer", score=5.0) for i in range(10)]
    picks = apply_today(plenty, PROFILE, n=8, now=NOW, watchlist=[], applied=NONE, max_family_share=0.25)
    assert [j.title for j, _ in picks].count("Golang Developer") == 2  # generic titles fill the rest
    ranks = [info.rank for _, info in picks]
    assert ranks == sorted(ranks, reverse=True)  # still in rank order


def test_role_families():
    assert role_family("Backend Developer ( Go Lang)") == "Go"
    assert role_family("Golang Developer") == "Go"
    assert role_family("Go-to-market Analyst") is None
    assert role_family("Full Stack Developer - Python") == "Full stack/web"
    assert role_family("React Native Developer") == "Mobile"
    assert role_family("Software Engineer - Java, Spring Boot") == "Java"
    assert role_family("Software Engineer") is None and role_family("SDE 1") is None


def test_daily_notice_skips_expired():
    jobs = [job(1, score=8.0, days=0), job(2, score=8.0, days=0, jd_status="closed")]
    assert new_strong_jobs(jobs, PROFILE, since=NOW - dt.timedelta(days=1), applied=NONE, now=NOW,
                           expire_after_days=14) == 1


# --- internships by stipend ------------------------------------------------------------------

@pytest.mark.parametrize("details, stipend", [
    ("Unpaid", True), ("₹ 5,000 /month", True), ("₹ 10,000 - 15,000 /month", True), ("Stipend: 8000", True),
    ("₹ 3,00,000 - 5,00,000 /year", False), ("₹ 60,000 /month", False), ("Remote", False), (None, False),
])
def test_is_stipend(details, stipend):
    assert is_stipend(details) is stipend


def test_stipend_listing_counts_as_internship_only_if_you_avoid_internships():
    j = job(1, "Web Development", details="₹ 10,000 - 15,000 /month")
    verdict = prefilter_job(j, PROFILE)
    assert verdict.excluded and "avoid role: intern / internship (stipend" in verdict.reasons[0]
    assert not prefilter_job(j, {**PROFILE, "avoid_roles": ["sales"]}).excluded
    assert not prefilter("Web Development", "Bengaluru", PROFILE, details="₹ 3,00,000 /year").excluded


def test_internshala_internship_links_and_wording():
    tracked = ("https://et.internshala.com/CL0/https:%2F%2Finternshala.com%2Finternship%2Fdetail%2F"
               "python-development-at-acme123/1/0100")
    job_link = "https://et.internshala.com/CL0/https:%2F%2Finternshala.com%2Fappcast%2Fjob%2Fdetail%2Fx/1/0100"
    v = prefilter("Python Development", "Bengaluru", PROFILE, link=tracked)
    assert v.excluded and "(Internshala internship)" in v.reasons[0]
    assert not prefilter("Python Development", "Bengaluru", PROFILE, link=job_link).excluded
    wording = "6 months, ₹30,000-45,000/month, Job offer starting ₹9LPA post internship"
    v = prefilter("Software Development", "Bengaluru", PROFILE, details=wording)
    assert v.excluded and "(listing says internship)" in v.reasons[0]


# --- dashboard -------------------------------------------------------------------------------

def test_expired_tab_keeps_stale_jobs_visible(env):  # noqa: F811
    env.profile_loader = lambda: DASH_PROFILE
    env.expire_after_days = 14
    env.now = lambda: NOW
    repo = env.repo_factory()
    _save(repo, [JobPost(title="Backend Engineer", company="New", location="Bengaluru", link=None)],
          message_id="n1", when=NOW - dt.timedelta(days=1))
    _save(repo, [JobPost(title="Platform Engineer", company="Old", location="Bengaluru", link=None)],
          message_id="o1", when=NOW - dt.timedelta(days=30))
    repo.close()
    c = client(env)
    cand = c.get("/jobs").text
    assert "Backend Engineer" in cand and "Platform Engineer" not in cand
    assert "Candidates (1)" in cand and "Expired (1)" in cand and "All (2)" in cand
    expired = c.get("/jobs?view=expired").text
    assert "Platform Engineer" in expired and "not in any alert for 30 days" in expired
    assert "Backend Engineer" not in expired
    assert "Platform Engineer" in c.get("/jobs?view=all").text  # never deleted
