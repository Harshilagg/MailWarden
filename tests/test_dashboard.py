import datetime as dt

import pytest
from fastapi.testclient import TestClient

from mailwarden.core.models import (
    Account, Application, Category, Classification, EmailMeta, GateDecision, ProviderKind, Stage, Tier,
)
from mailwarden.delivery.dashboard import auth
from mailwarden.delivery.dashboard.app import DashboardDeps, create_app
from mailwarden.delivery.dashboard.server import UnsafeBind, serve
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
