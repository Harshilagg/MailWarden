"""Open job-page fetching (robots.txt, pacing, denylist, per-site stats), Applied, and the data fixes."""

import datetime as dt

import pytest

from mailwarden.core import jd
from mailwarden.core.jd_fetch import PageFetcher, PageRefused
from mailwarden.core.job_alerts import _post, dedup_key
from mailwarden.core.job_scoring import JobActions, PageSources, fetch_auto_jds
from mailwarden.core.models import JobPost
from mailwarden.core.ranking import AppliedIndex, apply_today
from mailwarden.core.sources import company_from_link, company_from_source, tidy_requisition_title
from mailwarden.storage.sqlite_store import SQLCipherRepository
from tests.policy_helpers import policy
from tests.test_dashboard import PROFILE as DASH_PROFILE
from tests.test_dashboard import _csrf, client, env  # noqa: F401  (fixture)

NOW = dt.datetime(2026, 10, 13, 9, 0, tzinfo=dt.UTC)
PAGE = ("<html><main><h1>Backend Engineer</h1><h2>Requirements</h2><p>"
        + "You will design and run backend services in Go and Postgres for our payments platform. " * 5
        + "</p></main></html>")
ALLOW = policy(experience={"unknown_policy": "allow"})


# --- robots.txt and pacing -----------------------------------------------------------------------

class Clock:
    def __init__(self):
        self.t, self.slept = 100.0, []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.slept.append(round(s, 2))
        self.t += s


def _fetcher(robots, pages=None, interval=5.0):
    calls, clock = [], Clock()

    def get_robots(url):
        calls.append(url)
        if isinstance(robots, Exception):
            raise robots
        return robots

    def get_page(url):
        calls.append(url)
        return 200, (pages or {}).get(url, PAGE)

    return PageFetcher(get_page, get_robots, min_interval=interval, clock=clock, sleep=clock.sleep), calls, clock


def test_robots_txt_is_read_once_per_site_and_honoured():
    f, calls, clock = _fetcher((200, "User-agent: *\nDisallow: /private/\n"))
    assert f.get_page("https://careers.acme.com/jobs/1")[0] == 200
    with pytest.raises(PageRefused, match="robots.txt"):
        f.get_page("https://careers.acme.com/private/2")
    f.get_page("https://careers.acme.com/jobs/3")
    assert calls == ["https://careers.acme.com/robots.txt", "https://careers.acme.com/jobs/1",
                     "https://careers.acme.com/jobs/3"]
    assert clock.slept == [5.0, 5.0]  # robots -> page 1 -> page 3, 5 s apart


def test_robots_rules_for_our_agent_and_missing_or_broken_files():
    f, _, _ = _fetcher((200, "User-agent: mailwarden\nDisallow: /\n\nUser-agent: *\nAllow: /\n"))
    assert not f.allowed("https://a.example.com/job")
    f, _, _ = _fetcher((404, ""))  # no robots.txt: everything allowed
    assert f.allowed("https://a.example.com/job")
    f, _, _ = _fetcher((503, ""))  # server error: nothing allowed (RFC 9309)
    assert not f.allowed("https://a.example.com/job")
    f, _, _ = _fetcher(ConnectionError("down"))
    assert not f.allowed("https://a.example.com/job")


# --- the auto loop --------------------------------------------------------------------------------

@pytest.fixture
def repo(tmp_path, secret_store):
    r = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    yield r
    r.close()


def _save(repo, posts, when=NOW):
    repo.save_jobs("local", account="p", message_id=f"m{when.timestamp()}", sender="Alerts", received_at=when,
                   posts=posts, keys=[dedup_key(p, "Alerts") for p in posts])


def test_auto_fetches_pages_newest_first_skips_denied_and_logs_per_site(repo):
    _save(repo, [JobPost(title="Backend Engineer", company="Old", location="Bengaluru",
                         link="https://careers.old.com/j/1")], NOW - dt.timedelta(hours=5))
    _save(repo, [JobPost(title="Backend Engineer", company="Acme", location="Bengaluru",
                         link="https://careers.acme.com/j/2?utm_source=email"),
                 JobPost(title="SDE 1", company="Zeta", location="Bengaluru", link="https://www.linkedin.com/jobs/view/3"),
                 JobPost(title="Platform Engineer", company="Menu", location="Bengaluru",
                         link="https://careers.menu.com/j/4")])
    pages = {"https://careers.menu.com/j/4": "<html><nav>Jobs</nav><main><p>Apply now</p></main></html>"}
    f, calls, _ = _fetcher((404, ""), pages)
    st = fetch_auto_jds(repo, "local", ALLOW, get_json=None, limit=2, now=NOW, sleep=lambda s: None,
                        pages=PageSources(get_page=f.get_page, get_json=lambda u: (0, None)))
    assert st.tried == 2  # the per-run cap; the older job waits for the next sync
    assert "https://careers.acme.com/j/2" in calls and not any("linkedin" in c for c in calls)
    jobs = {j.company: j for j in repo.list_jobs("local")}
    assert jobs["Acme"].jd_status == "ok" and jobs["Acme"].jd_source == "fetch:careers.acme.com"
    assert jobs["Menu"].jd_status == "unavailable" and jobs["Menu"].jd_reason == jd.UNREADABLE
    assert jobs["Zeta"].jd_status is None and jobs["Old"].jd_status is None
    stats = sorted(repo.fetch_stats("local", NOW - dt.timedelta(days=1)))
    assert stats == [("careers.acme.com", "ok", 1), ("careers.menu.com", "unreadable", 1)]


def test_button_mode_explains_when_fetching_is_off(repo, tmp_path, secret_store):
    _save(repo, [JobPost(title="Backend Engineer", company="Acme", location="Bengaluru",
                         link="https://careers.acme.com/j/2")])
    key = secret_store.get("local/db-key")
    actions = JobActions(user_id="local", repo_factory=lambda: SQLCipherRepository(tmp_path / "d" / "mw.db", key),
                         profile_loader=lambda: None, effective_skills=lambda p: {}, llm_factory=None,
                         auto_json=None, pages=None)
    (job,) = repo.list_jobs("local")
    assert 'jd_fetch = "button"' in actions.fetch(job.id)
    assert not actions.button_fetch_enabled


# --- Applied ----------------------------------------------------------------------------------------

def test_applied_jobs_leave_apply_today_at_once(repo):
    _save(repo, [JobPost(title=f"Backend Engineer {i}", company=f"C{i}", location="Bengaluru", link=None)
                 for i in ("A", "B")])
    for j in repo.list_jobs("local"):
        repo.save_score("local", j.id, score=6.0, level="preliminary", input_hash="h",
                        detail={"matched_skills": [], "missing_skills": [], "evidence": [], "best_project": None,
                                "why": "x"})
    first = repo.list_jobs("local")[0]
    repo.mark_applied("local", first.id, NOW)
    picks = apply_today(repo.list_jobs("local"), ALLOW, n=5, now=NOW, watchlist=[], applied=AppliedIndex())
    assert first.id not in {j.id for j, _ in picks} and len(picks) == 1
    repo.mark_applied("local", first.id, None)
    assert len(apply_today(repo.list_jobs("local"), ALLOW, n=5, now=NOW, watchlist=[], applied=AppliedIndex())) == 2


def test_applied_button_records_an_application_and_can_be_undone(env):  # noqa: F811
    env.policy_loader = lambda: ALLOW
    env.profile_loader = lambda: DASH_PROFILE
    repo = env.repo_factory()
    repo.save_jobs("local", account="personal", message_id="j", sender="LinkedIn", received_at=env.now(),
                   posts=[JobPost(title="Backend Engineer", company="Zeta", location="Bengaluru", link=None)],
                   keys=["k"])
    (job,) = repo.list_jobs("local")
    repo.save_score("local", job.id, score=6.0, level="preliminary", input_hash="h",
                    detail={"matched_skills": [], "missing_skills": [], "evidence": [], "best_project": None,
                            "why": "x"})
    repo.close()
    c = client(env)
    form = {"content-type": "application/x-www-form-urlencoded"}
    assert c.post(f"/jobs/{job.id}/applied", content="view=apply", headers=form).status_code == 403  # CSRF
    assert "Backend Engineer" in c.get("/apply").text
    r = c.post(f"/jobs/{job.id}/applied", content=f"csrf={_csrf(env)}&view=apply", headers=form)
    assert r.status_code == 303
    picks = c.get("/apply").text.split("Applied today")[0]  # gone from the tiers, listed under Applied today
    assert "Backend Engineer" not in picks
    repo = env.repo_factory()
    assert any(a.company == "Zeta" and a.current_stage.value == "applied" for a in repo.list_applications("local"))
    repo.close()
    assert "Undo applied" in c.get("/jobs/browse?status=all").text
    c.post(f"/jobs/{job.id}/applied", content=f"csrf={_csrf(env)}&value=undo", headers=form)
    assert "Backend Engineer" in c.get("/apply").text


def test_insights_page_shows_success_per_site(env):  # noqa: F811
    repo = env.repo_factory()
    for outcome in ("ok", "ok", "unreadable", "blocked"):
        repo.record_fetch("local", "careers.acme.com", outcome, env.now())
    repo.record_fetch("local", "jobs.example.com", "unreadable", env.now())
    repo.record_fetch("local", "old.example.com", "ok", env.now() - dt.timedelta(days=40))  # outside 30 days
    repo.close()
    html = client(env).get("/insights").text
    assert "careers.acme.com" in html and "50%" in html and "unreadable (1)" in html
    assert "old.example.com" not in html


# --- data fixes --------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw, title, city", [
    ("2026_Java_Eclipse Development_BAN", "Java Eclipse Development", "Bengaluru"),
    ("Junior Software Developer_V4", "Junior Software Developer", None),
    ("Data_Engineer_HYD_R12345", "Data Engineer", "Hyderabad"),
    ("FY26 - SDE 1", "SDE 1", None),
    ("SAP FICO_Sr Lead Consultant - Enterprise Apps", "SAP FICO Sr Lead Consultant - Enterprise Apps", None),
    ("Backend Engineer", "Backend Engineer", None),
    ("C_Sharp_Developer", "C Sharp Developer", None),
])
def test_requisition_titles_become_readable(raw, title, city):
    assert tidy_requisition_title(raw) == (title, city)


def test_parsed_posts_keep_the_raw_title_and_find_the_company():
    p = _post("2026_Java_Eclipse Development_BAN", None, None, "https://my.greenhouse.io/jobs/66degrees/6222445004")
    assert (p.title, p.location, p.company) == ("Java Eclipse Development", "Bengaluru", "66degrees")
    assert p.details == "Original title: 2026_Java_Eclipse Development_BAN"
    assert company_from_link("https://jobs.lever.co/acme-corp/0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b") == "Acme Corp"
    assert company_from_link("https://amex.wd5.myworkdayjobs.com/x/job/y") == "American Express"
    assert company_from_link("https://www.linkedin.com/jobs/view/1") is None
    assert company_from_source("company_careers", "WSP") == "WSP"
    assert company_from_source("ats_feed", "Bayer (jobs2web)") == "Bayer"
    assert company_from_source("job_board", "LinkedIn") is None


def test_stored_jobs_are_tidied_once_on_upgrade(tmp_path, secret_store):
    path = tmp_path / "d" / "mw.db"
    r = SQLCipherRepository.open(path, secret_store, "local")
    raw = JobPost(title="2026_Java_Eclipse Development_BAN", company=None, location=None,
                  link="https://my.greenhouse.io/jobs/66degrees/6222445004")
    r._db.execute(  # a row saved before this version, untouched by the new parser
        "INSERT INTO job_postings (user_id, dedup_key, title, company, location, link, sender, account, message_id, "
        "received_at) VALUES ('local', ?, ?, NULL, NULL, ?, 'MyGreenhouse', 'p', 'm', ?)",
        (dedup_key(raw, "MyGreenhouse"), raw.title, raw.link, NOW.isoformat()))
    r._db.execute("UPDATE meta SET value = '8' WHERE key = 'schema_version'")
    r.close()
    r = SQLCipherRepository.open(path, secret_store, "local")
    (job,) = r.list_jobs("local")
    assert (job.title, job.company, job.location) == ("Java Eclipse Development", "66degrees", "Bengaluru")
    assert "Original title: 2026_Java_Eclipse Development_BAN" in job.details
    assert (tmp_path / "d" / "mw.db.before-v10.bak").exists()
    # A new alert for the same job now finds the stored row instead of making a duplicate.
    again = _post("2026_Java_Eclipse Development_BAN", None, None, raw.link)
    r.save_jobs("local", account="p", message_id="m2", sender="MyGreenhouse", received_at=NOW, posts=[again],
                keys=[dedup_key(again, "MyGreenhouse")])
    assert len(r.list_jobs("local")) == 1
    r.close()


def test_daily_score_budget_leaves_quota_for_email(repo):
    from mailwarden.core.job_scoring import count_scores, scores_left_today

    assert scores_left_today(repo, "local", 0, NOW) is None  # no cap
    assert scores_left_today(repo, "local", 80, NOW) == 80
    count_scores(repo, "local", 50, NOW)
    count_scores(repo, "local", 40, NOW + dt.timedelta(hours=1))
    assert scores_left_today(repo, "local", 80, NOW + dt.timedelta(hours=2)) == 0
    assert scores_left_today(repo, "local", 80, NOW + dt.timedelta(days=1)) == 80  # a new day


@pytest.mark.parametrize("title, company, role", [
    ("McLaren Strategic Solutions - AI/ML Engineer - GenAI (1-3 yrs)", "McLaren Strategic Solutions",
     "AI/ML Engineer - GenAI (1-3 yrs)"),
    ("FirstHive - Data Science Engineer (0-1 yrs)", "FirstHive", "Data Science Engineer (0-1 yrs)"),
    ("Data Scientist - Python/SQL (1-6 yrs)", None, "Data Scientist - Python/SQL (1-6 yrs)"),
    ("Software Engineer – Backend (Remote)", None, "Software Engineer – Backend (Remote)"),
])
def test_company_prefix_in_title(title, company, role):
    from mailwarden.core.sources import split_company_prefix

    assert split_company_prefix(title) == (company, role)


def test_host_names_are_not_companies():
    from mailwarden.core.sources import real_company

    assert [real_company(x) for x in ("Postoffice.hirist.tech", "www.acme.com", "Booking.com", "Acme Inc.")] == \
        [None, None, "Booking.com", "Acme Inc."]
    p = _post("McLaren Strategic Solutions - AI/ML Engineer (1-3 yrs)", "Postoffice.hirist.tech", None,
              "https://postoffice.hirist.tech/CL0/https:%2F%2Fwww.hirist.tech%2Fj%2Fx/1/a")
    assert (p.company, p.title) == ("McLaren Strategic Solutions", "AI/ML Engineer (1-3 yrs)")


def test_auto_stops_trying_sites_that_never_read(repo):
    for _ in range(5):
        repo.record_fetch("local", "www.hirist.tech", "unreadable", NOW - dt.timedelta(days=1))
    repo.record_fetch("local", "careers.acme.com", "unreadable", NOW)
    _save(repo, [JobPost(title="Backend Engineer", company="H", location="Bengaluru", link="https://www.hirist.tech/j/1"),
                 JobPost(title="Platform Engineer", company="A", location="Bengaluru",
                         link="https://careers.acme.com/j/2")])
    f, calls, _ = _fetcher((404, ""))
    st = fetch_auto_jds(repo, "local", ALLOW, get_json=None, limit=10, now=NOW, sleep=lambda s: None,
                        pages=PageSources(get_page=f.get_page, get_json=lambda u: (0, None)))
    assert st.skipped_sites == 1 and not any("hirist" in c for c in calls)
    assert "https://careers.acme.com/j/2" in calls  # one failure isn't enough to give up
