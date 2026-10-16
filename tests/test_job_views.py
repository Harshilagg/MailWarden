"""Job alerts redesign: Today (tiers), Review (triage), Browse (sidebar filters), old links, no inline JS."""

import datetime as dt
import re
from urllib.parse import urlencode

from mailwarden.core.job_alerts import dedup_key
from mailwarden.core.models import Application, JobPost, Stage
from mailwarden.delivery.dashboard import job_pages
from tests.policy_helpers import POLICY, policy
from tests.test_dashboard import NOW, PROFILE, _Actions, _csrf, _jobs, client, env  # noqa: F401  (fixture)

FORM = {"content-type": "application/x-www-form-urlencoded"}
ALLOW = policy(location={"allowed": ["Bengaluru"]}, experience={"unknown_policy": "allow"})


def text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def _score(env, title, score, level="preliminary", **detail):
    repo = env.repo_factory()
    job_id = next(j.id for j in repo.list_jobs("local") if j.title == title)
    repo.save_score("local", job_id, score=score, level=level, input_hash="h",
                    detail={"matched_skills": [], "missing_skills": [], "evidence": [], "best_project": None,
                            "why": "x", **detail})
    repo.close()
    return job_id


def _add(env, titles, **kw):
    repo = env.repo_factory()
    posts = [JobPost(title=t, company=f"Co {i}", location="Bengaluru", link=f"https://careers.co{i}.com/j")
             for i, t in enumerate(titles)]
    repo.save_jobs("local", account="personal", message_id="m-" + titles[0], sender="LinkedIn", received_at=NOW,
                   posts=posts, keys=[dedup_key(p, "x") for p in posts], **kw)
    repo.close()


def _post(c, path, **fields):
    return c.post(path, content=urlencode({"csrf": _csrf(_post.env), **fields}), headers=FORM)


# --- Today ----------------------------------------------------------------------------------------

def test_today_groups_tiers_and_counts_applied(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: ALLOW)
    env.tier_a_count, env.tier_b_count = 1, 1
    _add(env, ["Backend Engineer A", "Backend Engineer B", "Backend Engineer C", "Backend Engineer D"])
    a = _score(env, "Backend Engineer A", 8.0, level="full", why="Strong fit.")
    _score(env, "Backend Engineer B", 6.5)
    _score(env, "Backend Engineer C", 6.0)
    d = _score(env, "Backend Engineer D", 5.0)
    c = client(env)
    _post.env = env
    html = c.get("/jobs").text
    tier_a, rest = html.split('id="tier-b"')
    assert "Backend Engineer A" in tier_a and "tailor your CV + ask for a referral" in tier_a
    assert "Backend Engineer B" in rest and "quick apply" in rest
    assert "More" in rest and "Backend Engineer C" in rest  # beyond Tier B
    assert "Applied 0 of 4" in text(html)
    assert '<span class="badge full"' in html and '<span class="badge prelim"' in html  # solid vs outlined
    r = _post(c, f"/jobs/{d}/applied", view="today")
    assert r.status_code == 303 and r.headers["location"] == f"/jobs#job-{d}"
    page = text(c.get("/jobs").text)
    assert "Applied 1 of 4" in page and "Applied today 1" in page
    assert c.get("/apply").text.count('id="tier-a"') == 1  # notification links still land on Today
    assert "Backend Engineer A" in c.get("/jobs").text and a


def test_short_tier_a_lists_jobs_worth_a_jd(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: ALLOW)
    _add(env, ["Backend Engineer A"])
    _score(env, "Backend Engineer A", 6.5)
    html = client(env).get("/jobs").text
    assert "Tier A needs a full score of 7+" in html and "Backend Engineer A" in html


def test_today_without_profile_or_jobs(env):
    html = client(env).get("/jobs").text
    assert "Build your profile" in html and "How ranking works" in html


# --- Review ---------------------------------------------------------------------------------------

def test_review_shows_one_job_and_moves_on_after_each_action(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: POLICY)
    _add(env, ["Software Engineer A", "Software Engineer B", "Software Engineer C"])
    ids = [_score(env, f"Software Engineer {x}", s) for x, s in (("A", 7.0), ("B", 6.0), ("C", 5.0))]
    c = client(env)
    _post.env = env
    page = c.get("/jobs/review").text
    assert "3 left" in text(page) and "Software Engineer A" in page and "Software Engineer B" not in page
    assert 'data-key="f"' in page and 'data-next="/jobs/review?pos=1"' in page
    r = _post(c, f"/jobs/{ids[0]}/experience", value="fresher", view="review", pos="0")
    assert r.headers["location"] == "/jobs/review?pos=0"
    page = c.get(r.headers["location"]).text
    assert "2 left" in text(page) and "Software Engineer B" in page  # the next job slid into place
    assert "Software Engineer A" in c.get("/jobs").text  # verified: now on Today
    _post(c, f"/jobs/{ids[1]}/closed", view="review", pos="0")
    page = c.get("/jobs/review").text
    assert "1 left" in text(page) and "Software Engineer C" in page
    repo = env.repo_factory()
    assert repo.get_job("local", ids[1]).jd_reason == "you marked it closed"
    repo.close()
    assert "Software Engineer B" in c.get("/jobs/browse?status=expired").text
    _post(c, f"/jobs/{ids[2]}/dismiss", view="review", pos="0")
    assert "Nothing to review" in c.get("/jobs/review").text
    assert c.get("/jobs/review?pos=99").status_code == 200  # out of range is clamped


def test_closed_can_be_reopened(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: ALLOW)
    _add(env, ["Backend Engineer A"])
    job_id = _score(env, "Backend Engineer A", 6.0)
    c = client(env)
    _post.env = env
    _post(c, f"/jobs/{job_id}/closed", view="browse", back="/jobs/browse?status=expired")
    assert "Backend Engineer A" in c.get("/jobs/browse?status=expired").text
    _post(c, f"/jobs/{job_id}/closed", value="reopen", view="browse")
    assert "Backend Engineer A" in c.get("/jobs/browse").text


# --- Browse ---------------------------------------------------------------------------------------

def test_browse_status_filter_and_old_links(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: POLICY)
    _jobs(env)
    c = client(env)
    page = text(c.get("/jobs/browse").text)
    assert "Backend Engineer" in page and "Marketing Intern" not in page
    assert "Candidates 1" in page and "Filtered 1" in page and "All 2" in page
    filtered = c.get("/jobs/browse?status=filtered").text
    assert "Marketing Intern" in filtered and "excluded role: internship" in text(filtered)
    assert "javascript:" not in c.get("/jobs/browse?status=all").text  # unsafe links are never rendered
    for old, new in (("/jobs?view=filtered", "/jobs/browse?status=filtered"), ("/jobs?view=check", "/jobs/review"),
                     ("/jobs?match=1", "/jobs/browse"), ("/jobs?view=candidates", "/jobs/browse")):
        r = c.get(old)
        assert r.status_code == 303 and r.headers["location"] == new, old
    assert c.get("/jobs/browse?status=bogus&exp=nope&sort=x").status_code == 200


def test_browse_sidebar_facets_are_bookmarkable(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: ALLOW)
    repo = env.repo_factory()
    for mid, src, stype, title in [("m1", "LinkedIn", "job_board", "Backend Engineer"),
                                   ("m2", "Naukri", "job_board", "Backend Engineer"),
                                   ("m3", "Cutshort", "startup_platform", "Golang Developer")]:
        post = JobPost(title=title, company="Zeta", location="Bengaluru")
        repo.save_jobs("local", account="personal", message_id=mid, sender=src, received_at=NOW, posts=[post],
                       keys=[dedup_key(post, src)], source_type=stype, source_name=src)
    repo.close()
    c = client(env)
    page = text(c.get("/jobs/browse").text)
    for facet in ("Job boards 1", "Startup platforms 1", "LinkedIn 1", "Naukri 1", "Cutshort 1", "Go 1", "General 1"):
        assert facet in page, facet
    assert "Also on: Naukri" in page
    only = c.get("/jobs/browse?type=startup_platform").text
    assert "Golang Developer" in only and "Backend Engineer" not in only
    naukri = c.get("/jobs/browse?source=Naukri").text  # matches the merged job via "also on"
    assert "Backend Engineer" in naukri and "Golang Developer" not in naukri
    go = c.get("/jobs/browse?family=Go").text
    assert "Golang Developer" in go and "Backend Engineer" not in go
    assert "Cutshort" in text(c.get("/jobs/browse?q=cut").text)


def test_browse_actions_return_to_the_same_filters(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: ALLOW)
    _add(env, ["Backend Engineer A"])
    job_id = _score(env, "Backend Engineer A", 6.0)
    c = client(env)
    _post.env = env
    back = "/jobs/browse?source=Bayer+%28jobs2web%29&sort=newest"
    r = _post(c, f"/jobs/{job_id}/applied", view="browse", back=back)
    assert r.headers["location"] == back + f"#job-{job_id}"
    for evil in ("https://evil.example.com/", "//evil.example.com", "/jobs/browse/../../x", "/settings"):
        r = _post(c, f"/jobs/{job_id}/applied", view="browse", back=evil, value="undo")
        assert r.headers["location"].startswith("/jobs/browse"), evil


def test_jd_buttons_and_long_pastes(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: POLICY)
    env.job_actions = _Actions()
    _jobs(env)
    c = client(env)
    _post.env = env
    repo = env.repo_factory()
    job_id = next(j.id for j in repo.list_jobs("local") if j.title == "Backend Engineer")
    repo.close()
    for path in (f"/jobs/{job_id}/fetch-jd", f"/jobs/{job_id}/paste-jd", "/jobs/fetch-top", f"/jobs/{job_id}/closed",
                 f"/jobs/{job_id}/applied", f"/jobs/{job_id}/experience"):
        assert c.post(path, content="csrf=bad", headers=FORM).status_code == 403, path
    r = _post(c, f"/jobs/{job_id}/paste-jd", jd="Responsibilities " * 2000, view="browse")  # ~34 KB
    assert r.status_code == 303
    assert c.post(f"/jobs/{job_id}/dismiss", content=urlencode({"csrf": _csrf(env), "x": "y" * 5000}),
                  headers=FORM).status_code == 403  # other forms keep the small limit
    html = c.get("/jobs/browse").text
    assert "Paste JD" in html and "Fetch JDs for top 10" in html and "LinkedIn is on the do-not-fetch list" in html


def test_already_applied_and_expanded_details(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: ALLOW)
    _jobs(env)
    _score(env, "Backend Engineer", 6.5, matched_skills=["Go"], missing_skills=["Kafka"],
           best_project="Observable Job Queue", why="Good Go overlap.")
    repo = env.repo_factory()
    repo.upsert_application(Application(user_id="local", company="Zeta", role="Backend Engineer",
                                        current_stage=Stage.APPLIED, last_update=NOW),
                            event_stage=Stage.APPLIED, account="personal", message_id="a1", occurred_at=NOW, domain=None)
    repo.close()
    page = text(client(env).get("/jobs/browse").text)
    assert "Good Go overlap." in page and "Lead with: Observable Job Queue" in page and "Missing: Kafka" in page


# --- JavaScript: one first-party file, never inline -----------------------------------------------

def test_only_the_first_party_script_and_no_inline_code(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: POLICY)
    _jobs(env)
    c = client(env)
    for path in ("/", "/jobs", "/jobs/review", "/jobs/browse", "/apply", "/digest", "/settings", "/insights"):
        html = c.get(path).text
        scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.IGNORECASE | re.DOTALL)
        assert all(s.strip() == "" for s in scripts), path  # no inline code
        assert set(re.findall(r'<script\b[^>]*src="([^"]+)"', html)) <= {"/static/jobs.js"}, path
        assert not re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE), path  # no inline event handlers
        assert "javascript:" not in html, path
    js = c.get("/static/jobs.js")
    assert js.status_code == 200 and js.headers["content-type"].startswith("text/javascript")
    assert "fetch(" not in js.text and "XMLHttpRequest" not in js.text and "eval(" not in js.text
    assert c.get("/static/jobs.css").status_code == 200
    anon = client(env, logged_in=False)
    assert anon.get("/static/jobs.js").status_code == 401  # served only to the signed-in dashboard


def test_tiers_and_filters_are_pure():
    f = job_pages.Filters.parse({"status": "expired", "sort": "newest", "source": "Bayer (jobs2web)", "exp": "bad"})
    assert (f.status, f.sort, f.exp) == ("expired", "newest", "")
    assert f.url(status="candidates", sort="score") == "/jobs/browse?source=Bayer+%28jobs2web%29"
    assert f.url(source="") == "/jobs/browse?status=expired&sort=newest"

    class J:
        def __init__(self, score, level):
            self.score, self.score_level = score, level

    picks = [(J(8.0, "full"), 0), (J(7.5, "preliminary"), 0), (J(9.0, "full"), 0), (J(6.0, "preliminary"), 0)]
    t = job_pages.tiers(picks, a_count=3, b_count=1)
    assert [p[0].score for p in t.a] == [8.0, 9.0] and [p[0].score for p in t.b] == [7.5]
    assert [p[0].score for p in t.more] == [6.0] and [p[0].score for p in t.fill_a] == [7.5]
    assert job_pages.applied_today([], dt.datetime.now(dt.UTC)) == []


def test_browse_pages_50_at_a_time(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: ALLOW)
    _add(env, [f"Backend Engineer {i:03d}" for i in range(120)])
    c = client(env)
    first = c.get("/jobs/browse").text
    assert first.count('class="jrow') == 50 and "showing 1–50" in text(first) and "Page 1 of 3" in text(first)
    assert 'href="/jobs/browse?page=2"' in first
    last = c.get("/jobs/browse?page=3").text
    assert last.count('class="jrow') == 20 and "showing 101–120" in text(last)
    assert c.get("/jobs/browse?page=99").text.count('class="jrow') == 20  # clamped to the last page
    assert 'href="/jobs/browse?sort=newest"' in last  # changing a filter goes back to page 1


def test_weak_matches_never_take_an_apply_today_slot(env):
    env.profile_loader, env.policy_loader = (lambda: PROFILE), (lambda: ALLOW)
    env.apply_today_min_score = 5.0
    _add(env, ["Backend Engineer A", "Research Specialist B"])
    _score(env, "Backend Engineer A", 6.0)
    _score(env, "Research Specialist B", 4.0)
    c = client(env)
    today = c.get("/jobs").text
    assert "Backend Engineer A" in today and "Research Specialist B" not in today
    assert "Research Specialist B" in c.get("/jobs/browse").text  # still findable


def test_audit_names_the_minimum_score():
    from mailwarden.core.models import StoredJob
    from mailwarden.core.ranking import AppliedIndex
    from mailwarden.core.recall import Context, explain

    job = StoredJob(id=1, user_id="local", title="Research Specialist", company="X", location="Bengaluru", link=None,
                    sender="s", account="a", message_id="m", received_at=NOW, score=4.0, score_level="preliminary")
    ctx = Context(jobs=[job], policy=ALLOW, effective_skills={}, now=NOW, n=5, watchlist=[], applied=AppliedIndex(),
                  min_score=5.0)
    (f,) = explain(job, ctx)
    assert f.kind == "min_score" and "apply_today_min_score (now 5)" in f.suggestion
