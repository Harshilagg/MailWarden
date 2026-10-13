"""A broken sync must be visible and fixable, never a silently empty dashboard."""

import datetime as dt
import types

import pytest

from mailwarden import cli
from mailwarden.core import sync_health
from mailwarden.core.models import Account, ProviderKind, StoredJob
from mailwarden.core.overview import Digest
from mailwarden.core.ranking import AppliedIndex, apply_today
from mailwarden.core.expiry import expired_reason, reference_time
from mailwarden.providers.base import ReauthRequired
from mailwarden.storage.sqlite_store import SQLCipherRepository
from tests.policy_helpers import policy
from tests.test_dashboard import client, env  # noqa: F401  (fixture)
from tests.test_runner import ACCOUNT, FakeLLM, Provider, runner

NOW = dt.datetime(2026, 10, 12, 13, 30, tzinfo=dt.UTC)


@pytest.fixture
def repo(tmp_path, secret_store):
    r = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    yield r
    r.close()


# --- recording ---------------------------------------------------------------------------------

def test_expired_sign_in_shows_at_once_and_notifies_once_a_day(repo):
    assert sync_health.record_failure(repo, "local", "harshil", "invalid_grant", reauth=True, now=NOW)
    assert not sync_health.record_failure(repo, "local", "harshil", "invalid_grant", reauth=True,
                                          now=NOW + dt.timedelta(minutes=10))  # same day: no second notice
    (p,) = sync_health.problems(repo, "local", NOW)
    assert (p.account, p.reauth, p.since) == ("harshil", True, NOW)  # since the FIRST failure
    assert sync_health.record_failure(repo, "local", "harshil", "invalid_grant", reauth=True,
                                      now=NOW + dt.timedelta(days=1))  # next day: remind again
    sync_health.record_ok(repo, "local", "harshil", NOW + dt.timedelta(days=1, hours=1))
    assert sync_health.problems(repo, "local", NOW + dt.timedelta(days=2)) == []


def test_other_failures_wait_30_minutes_and_keep_the_last_good_sync(repo):
    sync_health.record_ok(repo, "local", "a", NOW - dt.timedelta(hours=1))
    sync_health.record_failure(repo, "local", "a", "network down", reauth=False, now=NOW)
    assert sync_health.problems(repo, "local", NOW + dt.timedelta(minutes=10)) == []  # probably a blip
    (p,) = sync_health.problems(repo, "local", NOW + dt.timedelta(minutes=31))
    assert not p.reauth and p.error == "network down" and p.last_ok == NOW - dt.timedelta(hours=1)
    assert sync_health.problems(repo, "local", NOW + dt.timedelta(hours=1), accounts=["other"]) == []
    sync_health.forget(repo, "local", "a")
    assert sync_health.problems(repo, "local", NOW + dt.timedelta(hours=1)) == []


class ExpiredProvider(Provider):
    def list_new(self, account, cursor):
        raise ReauthRequired("Google rejected the stored sign-in (invalid_grant); run `mailwarden reauth <account>`")


class Notices:
    def __init__(self):
        self.sent = []

    def notify_text(self, text, path):
        self.sent.append((text, path))


def test_runner_records_failures_and_successes(repo):
    notices = Notices()
    r = runner(repo, ExpiredProvider({}), FakeLLM())
    r._notifier, r._clock = notices, (lambda: NOW)
    assert r.run([ACCOUNT]).accounts_failed == ["personal"]
    r.run([ACCOUNT])
    assert notices.sent == [("mailwarden can't read personal: sign in again", "/")]  # once, not every 10 minutes
    (p,) = sync_health.problems(repo, "local", NOW)
    assert p.reauth and "reauth" in p.error
    ok = runner(repo, Provider({}), FakeLLM())
    ok._clock = lambda: NOW + dt.timedelta(minutes=20)
    ok.run([ACCOUNT])
    assert sync_health.problems(repo, "local", NOW + dt.timedelta(hours=1)) == []


# --- an outage must not empty the lists --------------------------------------------------------

def _job(i, days, title="SDE 1"):
    return StoredJob(id=i, user_id="local", title=title, company=f"C{i}", location="Bengaluru", link=None,
                     sender="s", account="a", message_id="m", received_at=NOW - dt.timedelta(days=days), score=6.0,
                     score_level="preliminary")


def test_apply_today_and_expiry_survive_a_week_without_mail():
    jobs = [_job(1, 6), _job(2, 7), _job(3, 30)]  # nothing newer arrived for 6 days
    picks = apply_today(jobs, policy(), n=10, now=NOW, watchlist=[], applied=AppliedIndex(), expire_after_days=14,
                        new_within_days=3)
    assert [j.id for j, _ in picks] == [1, 2]  # the last alerts' jobs, not an empty list
    assert reference_time(jobs, NOW) == NOW - dt.timedelta(days=6)
    assert expired_reason(jobs[0], now=reference_time(jobs, NOW), after_days=14) is None
    assert expired_reason(jobs[2], now=reference_time(jobs, NOW), after_days=14)  # 24 days older than the rest
    assert reference_time([], NOW) == NOW


# --- the dashboard -----------------------------------------------------------------------------

def test_banner_says_what_to_run(env):  # noqa: F811
    repo = env.repo_factory()
    sync_health.record_failure(repo, "local", "personal", "invalid_grant", reauth=True,
                               now=env.now() - dt.timedelta(days=5))
    repo.close()
    c = client(env)
    for page in ("/", "/apply", "/jobs", "/digest", "/applications"):
        html = c.get(page).text
        assert "Google's sign-in expired" in html and "mailwarden reauth personal" in html, page


def test_digest_falls_back_to_the_last_one_with_mail(env):  # noqa: F811
    repo = env.repo_factory()
    full = Digest(generated_at=(env.now() - dt.timedelta(days=3)).isoformat(),
                  period_start=(env.now() - dt.timedelta(days=4)).isoformat(), ignored=2,
                  sensitive_by_sender={"HDFC Bank": 1})
    empty = Digest(generated_at=(env.now() - dt.timedelta(hours=2)).isoformat(),
                   period_start=(env.now() - dt.timedelta(hours=12)).isoformat())
    for d in (full, empty):
        repo.save_digest("local", dt.datetime.fromisoformat(d.generated_at), dt.datetime.fromisoformat(d.period_start),
                         d.to_json())
    repo.close()
    html = client(env).get("/digest").text
    assert "HDFC Bank" in html and "This is the last digest that had mail" in html


# --- signing in again keeps the data -----------------------------------------------------------

def _fake_app(monkeypatch, *, signed_in_as):
    secrets = {"tok": "old-token"}
    acct = Account(user_id="local", name="harshil", provider=ProviderKind.GMAIL, address="me@gmail.com")
    revoked, healthy = [], []
    app = types.SimpleNamespace(
        user_id="local", session=object(),
        accounts=types.SimpleNamespace(get=lambda u, n: acct if n == "harshil" else None),
        google_client=lambda: "client",
        secrets=types.SimpleNamespace(get=lambda k: secrets.get("tok"), set=lambda k, v: secrets.__setitem__("tok", v),
                                      delete=lambda k: secrets.pop("tok", None)),
        providers={ProviderKind.GMAIL: types.SimpleNamespace(profile_address=lambda a: signed_in_as)},
        repository=lambda: types.SimpleNamespace(close=lambda: None),
    )
    monkeypatch.setattr(cli, "build_app", lambda: app)
    hints = []

    def flow(client, session, login_hint=None):
        hints.append(login_hint)
        return types.SimpleNamespace(refresh_token="new")

    monkeypatch.setattr(cli, "run_loopback_flow", flow)
    monkeypatch.setattr(cli, "revoke", lambda session, token: revoked.append(token))
    monkeypatch.setattr(sync_health, "record_ok", lambda repo, user, name, now: healthy.append(name))
    app.hints = hints
    return secrets, revoked, healthy


def test_reauth_replaces_the_token_and_clears_the_warning(monkeypatch, capsys):
    secrets, revoked, healthy = _fake_app(monkeypatch, signed_in_as="Me@Gmail.com")
    assert cli.cmd_reauth(types.SimpleNamespace(name="harshil")) == 0
    assert secrets["tok"] == "new" and revoked == ["old-token"] and healthy == ["harshil"]
    assert cli.build_app().hints == ["me@gmail.com"]  # Google preselects the right account
    assert "All its data is kept" in capsys.readouterr().out


def test_reauth_as_the_wrong_google_account_changes_nothing(monkeypatch):
    secrets, revoked, healthy = _fake_app(monkeypatch, signed_in_as="someone.else@gmail.com")
    with pytest.raises(cli.UsageError, match="you signed in as"):
        cli.cmd_reauth(types.SimpleNamespace(name="harshil"))
    assert secrets["tok"] == "old-token" and revoked == ["new"] and healthy == []


def test_add_account_points_existing_accounts_to_reauth(monkeypatch):
    app = types.SimpleNamespace(user_id="local", accounts=types.SimpleNamespace(get=lambda u, n: object()))
    monkeypatch.setattr(cli, "build_app", lambda: app)
    with pytest.raises(cli.UsageError, match="mailwarden reauth harshil"):
        cli.cmd_add_account(types.SimpleNamespace(provider=ProviderKind.GMAIL, name="harshil", client_secrets=None))
