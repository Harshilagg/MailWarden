import datetime as dt

import pytest
from fastapi.testclient import TestClient

from mailwarden.core.models import (
    Account, Application, Category, Classification, EmailMeta, GateDecision, ProviderKind, Stage, Tier,
)
from mailwarden.delivery.dashboard import auth
from mailwarden.delivery.dashboard.app import DashboardDeps, create_app
from mailwarden.delivery.dashboard.server import UnsafeBind, serve
from mailwarden.core.job_alerts import dedup_key
from mailwarden.core.models import JobPost
from mailwarden.storage.keyring_accounts import KeyringAccountRegistry
from mailwarden.storage.sqlite_store import SQLCipherRepository

PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
NOW = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.UTC)


def cls(**kw):
    base = dict(category=Category.JOB, company="Acme", role="SWE", stage=Stage.INTERVIEW, action_required=True,
                deadline=dt.date(2026, 10, 5), summary="You're invited to an interview with Acme on Mon, 5 Oct.")
    return Classification(**{**base, **kw})


@pytest.fixture
def env(tmp_path, secret_store):
    path = tmp_path / "d" / "mw.db"
    repo = SQLCipherRepository.open(path, secret_store, "local")
    key = secret_store.get("local/db-key")
    registry = KeyringAccountRegistry(secret_store)
    registry.add(Account(user_id="local", name="personal", provider=ProviderKind.GMAIL, address="me@gmail.com"))
    rows = [
        EmailMeta(user_id="local", account="personal", message_id="job1", sender_address="hr@acme.com",
                  sender_name="Acme HR", received_at=NOW - dt.timedelta(hours=2), tier=Tier.DEFAULT,
                  gate=GateDecision.SAFE, classification=cls(), classified_by="llm"),
        EmailMeta(user_id="local", account="personal", message_id="held1", sender_address=None,
                  sender_name="HackerEarth", received_at=NOW - dt.timedelta(hours=1), tier=Tier.PRIORITY,
                  gate=GateDecision.SENSITIVE, held_reason="Contains a verification code", held_job=True,
                  held_company="HackerEarth", held_stage=Stage.ASSESSMENT),
        EmailMeta(user_id="local", account="personal", message_id="bank1", sender_address=None,
                  sender_name="IDFC FIRST Bank", received_at=NOW - dt.timedelta(hours=3), tier=Tier.SENSITIVE,
                  gate=GateDecision.SENSITIVE, held_reason="Banking or payment details"),
        EmailMeta(user_id="local", account="personal", message_id="news1", sender_address="n@x.com",
                  sender_name="<script>alert(1)</script>", received_at=NOW - dt.timedelta(hours=5), tier=Tier.DEFAULT,
                  gate=GateDecision.SAFE, classified_by="rule:bulk_header",
                  classification=cls(category=Category.NEWSLETTER, company=None, role=None, stage=None,
                                     action_required=False, deadline=None, summary="Newsletter from <b>X</b>.")),
    ]
    for r in rows:
        repo.save_email_meta(r)
    repo.upsert_application(
        Application(user_id="local", company="Acme", role="SWE", current_stage=Stage.INTERVIEW, last_update=NOW,
                    source_message_ids=("job1",)),
        event_stage=Stage.INTERVIEW, account="personal", message_id="job1", occurred_at=NOW, domain=None)
    repo.close()
    deps = DashboardDeps(
        user_id="local", port=PORT, secrets=secret_store, repo_factory=lambda: SQLCipherRepository(path, key),
        accounts=registry, rules_summary=lambda: {"priority": {"domains": ["greenhouse.io"], "senders": []}},
        backend_description="groq (openai/gpt-oss-20b)", outbound_hosts=["api.groq.com"], digest_times=["08:00"],
        now=lambda: NOW,
    )
    return deps


def client(deps, logged_in=True):
    c = TestClient(create_app(deps), base_url=BASE, follow_redirects=False)
    if logged_in:
        code = auth.issue_login_code(deps.secrets, "local")
        r = c.get(f"/login?code={code}")
        assert r.status_code == 303
    return c


# --- security controls -------------------------------------------------------------

@pytest.mark.parametrize("host", ["evil.example.com", "127.0.0.1:9999", "attacker.test:8765", "localhost.evil.com:8765", ""])
def test_host_header_rejected(env, host):
    r = client(env).get("/", headers={"host": host})
    assert r.status_code == 400


def test_localhost_host_allowed(env):
    assert client(env).get("/", headers={"host": f"localhost:{PORT}"}).status_code == 200


def test_requires_login(env):
    c = client(env, logged_in=False)
    for path in ("/", "/applications", "/digest", "/sensitive", "/settings", "/i/personal/job1"):
        r = c.get(path)
        assert r.status_code == 401 and "mailwarden open" in r.text


def test_forged_cookie_rejected(env):
    c = client(env, logged_in=False)
    c.cookies.set(auth.COOKIE_NAME, "guess")
    assert c.get("/").status_code == 401


def test_login_code_is_single_use_and_sets_strict_cookie(env):
    c = client(env, logged_in=False)
    code = auth.issue_login_code(env.secrets, "local")
    r = c.get(f"/login?code={code}")
    cookie = r.headers["set-cookie"].lower()
    assert r.status_code == 303 and "httponly" in cookie and "samesite=strict" in cookie
    assert c.get("/").status_code == 200
    fresh = client(env, logged_in=False)
    assert fresh.get(f"/login?code={code}").status_code == 401  # already used


def test_login_code_expires(env):
    now = [1000.0]
    code = auth.issue_login_code(env.secrets, "local", now=lambda: now[0])
    now[0] += auth.LOGIN_TTL_SECONDS + 1
    assert not auth.redeem_login_code(env.secrets, "local", code, now=lambda: now[0])


def test_wrong_code_rejected(env):
    auth.issue_login_code(env.secrets, "local")
    assert client(env, logged_in=False).get("/login?code=nope").status_code == 401


def test_security_headers_on_every_response(env):
    c = client(env)
    for r in (c.get("/"), c.get("/static/style.css"), c.get("/nope"), c.get("/", headers={"host": "evil"})):
        csp = r.headers["content-security-policy"]
        assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp and "script" not in csp
        assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["cache-control"] == "no-store"


def test_no_api_docs(env):
    c = client(env)
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert c.get(path).status_code == 404


def test_no_external_assets_or_scripts(env):
    html = client(env).get("/").text
    assert "<script" not in html.lower()
    for tag in ('src="http', "href=\"http://", "cdn"):
        assert tag not in html.lower()


def _csrf(env):
    return auth.csrf_token(auth.ensure_install_token(env.secrets, "local"))


def test_dismiss_requires_csrf(env):
    c = client(env)
    form = {"content-type": "application/x-www-form-urlencoded"}
    assert c.post("/i/personal/job1/dismiss", content="", headers=form).status_code == 403
    assert c.post("/i/personal/job1/dismiss", content="csrf=bad", headers=form).status_code == 403
    r = c.post("/i/personal/job1/dismiss", content=f"csrf={_csrf(env)}",
               headers={**form, "origin": "https://evil.example"})
    assert r.status_code == 403
    r = c.post("/i/personal/job1/dismiss", content=f"csrf={_csrf(env)}", headers={**form, "origin": BASE})
    assert r.status_code == 303
    assert "interview with Acme" not in c.get("/").text


def test_dismiss_needs_login(env):
    r = client(env, logged_in=False).post("/i/personal/job1/dismiss", content=f"csrf={_csrf(env)}",
                                          headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 401


def test_serve_refuses_non_loopback():
    with pytest.raises(UnsafeBind):
        serve(None, host="0.0.0.0", port=8765)


def test_config_refuses_non_loopback():
    from mailwarden.config import Settings

    with pytest.raises(ValueError):
        Settings.model_validate({"dashboard": {"host": "0.0.0.0"}})


# --- views ---------------------------------------------------------------------------------

def test_urgent_view(env):
    html = client(env).get("/").text
    assert "Acme" in html and "Due Mon, 5 Oct" in html and "invited to an interview" in html
    assert "HackerEarth" in html and "Contains a verification code" in html and "Assessment" in html
    assert "https://mail.google.com/mail/u/me@gmail.com/#all/job1" in html
    assert 'rel="noopener noreferrer"' in html
    assert "2 hours ago" in html
    assert "IDFC" not in html  # non-job sensitive mail is not urgent
    for token in ("[LINK", "[NUM]", "[EMAIL]", "[TOKEN]", "otp", "code_near_number"):
        assert token not in html


def test_applications_view(env):
    html = client(env).get("/applications").text
    assert "Acme" in html and "SWE" in html and "Interview" in html and "History (1)" in html


def test_sensitive_view_counts_only(env):
    html = client(env).get("/sensitive").text
    assert "IDFC FIRST Bank" in html and "HackerEarth" in html
    assert "Banking or payment details" not in html  # counts by sender only


def test_digest_view_live_and_escaped(env):
    html = client(env).get("/digest").text
    assert "Newsletters" in html and "&lt;script&gt;" in html and "<script>alert" not in html
    assert "&lt;b&gt;X&lt;/b&gt;" in html
    assert "2 sensitive emails (not processed)" in html


def test_item_page_for_notification_click(env):
    c = client(env)
    assert "HackerEarth" in c.get("/i/personal/held1").text
    bank = c.get("/i/personal/bank1").text
    assert "Sensitive email" in bank and "Banking or payment details" in bank
    assert c.get("/i/personal/missing").status_code == 404
    assert c.get("/i/personal/..%2F..%2Fetc").status_code == 404


def test_settings_view(env):
    html = client(env).get("/settings").text
    assert "greenhouse.io" in html and "api.groq.com" in html and "m***@gmail.com" in html


def _jobs(env):
    from mailwarden.core.job_alerts import dedup_key
    from mailwarden.core.models import JobPost

    repo = env.repo_factory()
    posts = [
        JobPost(title="Backend Engineer", company="Zeta", location="Bengaluru", link="https://www.linkedin.com/jobs/view/1"),
        JobPost(title="Marketing Intern", company="Acme", location="Mumbai", link="javascript:alert(1)"),
    ]
    repo.save_jobs("local", account="personal", message_id="ja1", sender="LinkedIn Job Alerts", received_at=NOW,
                   posts=posts, keys=[dedup_key(p, "x") for p in posts])
    repo.close()


def test_jobs_page_without_profile_highlights_keywords(env):
    env.job_keywords, env.job_locations = ["backend"], ["Bengaluru"]
    _jobs(env)
    html = client(env).get("/jobs?view=all").text
    assert "Backend Engineer" in html and "Marketing Intern" in html and 'class="job match"' in html
    assert "javascript:" not in html  # unsafe links are never rendered
    assert 'href="https://www.linkedin.com/jobs/view/1"' in html
    assert "Build your profile" in html


PROFILE = {"target_roles": ["backend / platform"], "avoid_roles": ["non-engineering"],
           "locations": ["Bengaluru", "Remote"], "remote_ok": True}


def test_jobs_page_prefilter_tabs_never_hide_jobs(env):
    env.profile_loader = lambda: PROFILE
    _jobs(env)
    c = client(env)
    cand = c.get("/jobs").text
    assert "Backend Engineer" in cand and "Marketing Intern" not in cand
    assert "Candidates (1)" in cand and "All (2)" in cand and "Filtered (1)" in cand
    assert 'class="job match"' in cand  # target role highlighted
    everything = c.get("/jobs?view=all").text
    assert "Backend Engineer" in everything and "Marketing Intern" in everything
    assert "non-engineering role" in everything and "location (Mumbai)" in everything
    filt = c.get("/jobs?view=filtered").text
    assert "Marketing Intern" in filt and "Backend Engineer" not in filt
    assert c.get("/jobs?match=1").text.count("Backend Engineer") == 1  # old notification links still work
    assert c.get("/jobs?view=bogus").status_code == 200


def test_dismiss_job_requires_csrf(env):
    _jobs(env)
    c = client(env)
    repo = env.repo_factory()
    job_id = repo.list_jobs("local")[0].id
    repo.close()
    form = {"content-type": "application/x-www-form-urlencoded"}
    assert c.post(f"/jobs/{job_id}/dismiss", content="csrf=bad", headers=form).status_code == 403
    assert c.post(f"/jobs/{job_id}/dismiss", content=f"csrf={_csrf(env)}", headers=form).status_code == 303
    repo = env.repo_factory()
    assert job_id not in [j.id for j in repo.list_jobs("local")]
    repo.close()


def test_pinned_item_shows_on_urgent_with_note(env):
    repo = env.repo_factory()
    repo.save_email_meta(EmailMeta(
        user_id="local", account="personal", message_id="pin1", sender_address="events@hackerearth.com",
        sender_name="HackerEarth", received_at=NOW - dt.timedelta(days=1), tier=Tier.PRIORITY, gate=GateDecision.SAFE,
        classification=cls(category=Category.NEWSLETTER, company="Booking Holdings", stage=None,
                           action_required=False, deadline=None, summary="A hiring challenge newsletter."),
        urgent_since=NOW - dt.timedelta(days=1)))
    repo.close()
    html = client(env).get("/").text
    assert "Booking Holdings" in html and "It stays until you click Done" in html


def test_logo_and_favicon_served_without_login(env):
    c = client(env, logged_in=False)
    for path in ("/favicon.ico", "/static/logo-64.png", "/static/logo-180.png"):
        r = c.get(path)
        assert r.status_code == 200 and r.headers["content-type"] == "image/png" and r.content[:4] == b"\x89PNG"
        assert "default-src 'none'" in r.headers["content-security-policy"]
    assert c.get("/static/other.png").status_code == 401  # only the known logo files are public


def test_pages_reference_local_logo_only(env):
    html = client(env).get("/").text
    assert 'rel="icon" type="image/png" href="/static/logo-64.png"' in html
    assert 'class="site-title"' in html  # the Mail/warden wordmark header


def test_fonts_served_locally_and_allowed_by_csp(env):
    from urllib.parse import quote

    c = client(env, logged_in=False)
    css = c.get("/static/style.css").text
    assert 'format("opentype")' in css and 'format("otf")' not in css
    for name in ("DunbarLow_Bold.otf", "Tempting - PERSONAL USE ONLY.otf"):
        r = c.get("/static/fonts/" + quote(name))
        assert r.status_code == 200 and r.headers["content-type"] == "font/otf"
        assert r.content[:4] in (b"OTTO", b"\x00\x01\x00\x00")
        assert "font-src 'self'" in r.headers["content-security-policy"]
    for bad in ("..%2Fstyle.css", "..%2F..%2Fapp.py", "missing.otf", "x.exe"):
        assert c.get("/static/fonts/" + bad).status_code in (401, 404)



@pytest.mark.parametrize(
    "next_path, expected",
    [
        ("/jobs", "/jobs"),
        ("/jobs?match=1", "/jobs?match=1"),
        ("/i/personal/job1", "/i/personal/job1"),
        ("//evil.example.com", "/"),
        ("https://evil.example.com", "/"),
        ("/\\evil.example.com", "/"),
        ("/%2F%2Fevil.example.com", "/"),
        ("javascript:alert(1)", "/"),
    ],
)
def test_login_next_only_redirects_to_local_paths(env, next_path, expected):
    from urllib.parse import quote

    c = client(env, logged_in=False)
    code = auth.issue_login_code(env.secrets, "local")
    r = c.get(f"/login?code={code}&next={quote(next_path, safe='')}")
    assert r.status_code == 303 and r.headers["location"] == expected


def test_local_port_open():
    import socket

    from mailwarden.security.net import local_port_open

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        assert local_port_open(port)
    assert not local_port_open(port)


class _Actions:
    button_fetch_enabled = True

    def __init__(self):
        self.calls = []

    def fetch(self, job_id):
        self.calls.append(("fetch", job_id))
        return "ok"

    def paste(self, job_id, text):
        self.calls.append(("paste", job_id, len(text)))
        return "ok"

    def fetch_top(self, ids):
        self.calls.append(("top", ids))
        return "ok"


def test_jd_buttons_require_csrf_and_accept_long_pastes(env):
    env.profile_loader = lambda: PROFILE
    env.job_actions = _Actions()
    _jobs(env)
    c = client(env)
    repo = env.repo_factory()
    job_id = next(j.id for j in repo.list_jobs("local") if j.title == "Backend Engineer")
    repo.close()
    form = {"content-type": "application/x-www-form-urlencoded"}
    for path in (f"/jobs/{job_id}/fetch-jd", f"/jobs/{job_id}/paste-jd", "/jobs/fetch-top"):
        assert c.post(path, content="csrf=bad", headers=form).status_code == 403
    long_jd = "Responsibilities " * 2000  # ~34 KB: allowed for pastes only
    from urllib.parse import urlencode

    r = c.post(f"/jobs/{job_id}/paste-jd", content=urlencode({"csrf": _csrf(env), "jd": long_jd, "view": "all"}),
               headers=form)
    assert r.status_code == 303 and r.headers["location"].startswith("/jobs?view=all&sort=score#job-")
    assert c.post(f"/jobs/{job_id}/fetch-jd", content=f"csrf={_csrf(env)}", headers=form).status_code == 303
    assert c.post(f"/jobs/{job_id}/dismiss", content=urlencode({"csrf": _csrf(env), "x": "y" * 5000}),
                  headers=form).status_code == 403  # other forms keep the small limit
    kinds = [c[0] for c in env.job_actions.calls]
    assert kinds == ["paste", "fetch"]
    html = c.get("/jobs?view=all").text
    assert "Paste JD" in html and "Fetch JDs for top 10" in html and "LinkedIn pages can&#39;t be fetched" in html


def test_scores_show_level_and_details(env):
    env.profile_loader = lambda: PROFILE
    _jobs(env)
    repo = env.repo_factory()
    job_id = next(j.id for j in repo.list_jobs("local") if j.title == "Backend Engineer")
    repo.save_score("local", job_id, score=6.5, level="preliminary", input_hash="h",
                    detail={"matched_skills": ["Go"], "missing_skills": ["Kafka"], "evidence": [],
                            "best_project": "Observable Job Queue", "why": "Good Go overlap."})
    repo.close()
    html = client(env).get("/jobs").text
    assert "6.5 · preliminary" in html and "Good Go overlap." in html
    assert "Lead with: Observable Job Queue" in html and "Missing: Kafka" in html


def test_apply_today_view(env):
    env.profile_loader = lambda: PROFILE
    env.watchlist = ["Zeta"]
    _jobs(env)
    repo = env.repo_factory()
    job_id = next(j.id for j in repo.list_jobs("local") if j.title == "Backend Engineer")
    repo.save_score("local", job_id, score=6.0, level="preliminary", input_hash="h",
                    detail={"matched_skills": [], "missing_skills": ["Kafka"], "evidence": [],
                            "best_project": "Observable Job Queue", "why": "Your Go work fits."})
    repo.close()
    c = client(env)
    html = c.get("/apply").text
    assert "Backend Engineer" in html and "Marketing Intern" not in html  # filtered job not picked
    assert "score 6.0 (preliminary) · fresh +0.5" in html  # received just now
    assert "Lead with: <strong>Observable Job Queue</strong>" in html and "Paste or fetch the job description" in html
    assert "Apply today (1)" in c.get("/jobs").text
    r = c.post(f"/jobs/{job_id}/dismiss", content=f"csrf={_csrf(env)}&view=apply",
               headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 303 and r.headers["location"] == "/apply"
    assert "Backend Engineer" not in c.get("/apply").text
    assert "Backend Engineer" not in c.get("/jobs?view=all").text  # you dismissed it: gone from both views


def test_already_applied_label(env):
    env.profile_loader = lambda: PROFILE
    _jobs(env)
    repo = env.repo_factory()
    repo.upsert_application(Application(user_id="local", company="Zeta", role="Backend Engineer",
                                        current_stage=Stage.APPLIED, last_update=NOW),
                            event_stage=Stage.APPLIED, account="personal", message_id="a1", occurred_at=NOW, domain=None)
    repo.close()
    assert "Already applied" in client(env).get("/jobs?view=all").text


def test_source_chips_and_also_on(env):
    env.profile_loader = lambda: PROFILE
    repo = env.repo_factory()
    for mid, src, stype, title in [("m1", "LinkedIn", "job_board", "Backend Engineer"),
                                   ("m2", "Naukri", "job_board", "Backend Engineer"),
                                   ("m3", "Cutshort", "startup_platform", "Platform Engineer")]:
        post = JobPost(title=title, company="Zeta", location="Bengaluru")
        repo.save_jobs("local", account="personal", message_id=mid, sender=src, received_at=NOW, posts=[post],
                       keys=[dedup_key(post, src)], source_type=stype, source_name=src)
    repo.close()
    c = client(env)
    html = c.get("/jobs?view=all").text
    assert "Job boards (1)" in html and "Startup platforms (1)" in html
    assert "LinkedIn (1)" in html and "Naukri (1)" in html and "Cutshort (1)" in html
    assert "via LinkedIn" in html and "also on: Naukri" in html
    only = c.get("/jobs?view=all&type=startup_platform").text
    assert "Platform Engineer" in only and "Backend Engineer" not in only
    naukri = c.get("/jobs?view=all&source=Naukri").text  # matches the merged job via 'also on'
    assert "Backend Engineer" in naukri and "Platform Engineer" not in naukri
    assert c.get("/jobs?view=all&type=bogus").status_code == 200
