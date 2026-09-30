"""End-to-end: mock provider -> real pipeline -> fake LLM -> real SQLCipher store."""

import datetime as dt
from importlib import resources

import pytest

from mailwarden.core.classify.base import BackendUnavailable, InvalidOutput, LLMBackend
from mailwarden.core.models import Account, Category, Classification, GateDecision, MessageStatus, ProviderKind, Stage
from mailwarden.core.runner import Runner
from mailwarden.core.sender_rules import SenderRules
from mailwarden.providers.base import MailProvider, ProviderError, SyncResult
from mailwarden.storage.sqlite_store import SQLCipherRepository
from tests.fixtures.emails import SENSITIVE, make

RULES = SenderRules.from_yaml(resources.files("mailwarden.templates").joinpath("sender_rules.yaml").read_text())
ACCOUNT = Account(user_id="local", name="personal", provider=ProviderKind.GMAIL, address="me@gmail.com")


class Provider(MailProvider):
    kind = ProviderKind.GMAIL

    def __init__(self, messages, cursor="100"):
        self.messages = messages
        self.cursor = cursor
        self.seen_cursors = []
        self.fail_ids: set[str] = set()

    def verify_access(self, account):
        return frozenset()

    def list_new(self, account, cursor):
        self.seen_cursors.append(cursor)
        return SyncResult(list(self.messages), self.cursor, cursor is None)

    def list_recent(self, account, limit):
        return list(self.messages)[:limit]

    def get_message(self, account, message_id):
        if message_id in self.fail_ids:
            raise ProviderError("boom")
        return self.messages[message_id].model_copy()


class FakeLLM(LLMBackend):
    name, model, remote = "fake", "fake", True

    def __init__(self, result=None, raise_=None):
        self.calls: list[str] = []
        self.result = result
        self.raise_ = raise_

    def classify(self, text):
        self.calls.append(text)
        if self.raise_:
            raise self.raise_
        return self.result


INTERVIEW = Classification(category=Category.JOB, company="Acme", role="SWE", stage=Stage.INTERVIEW,
                           action_required=True, deadline=dt.date(2026, 10, 10), summary="Interview with Acme")


def _messages():
    msgs = {
        "job": make("no-reply@greenhouse.io", "Acme Recruiting", "Interview", "Please pick a slot for your interview.", message_id="job"),
        "friend": make("rahul@gmail.com", "Rahul", "Dinner", "Dinner Friday?", message_id="friend"),
    }
    for i, (_, s, n, subj, body) in enumerate(SENSITIVE[:5]):
        msgs[f"s{i}"] = make(s, n, subj, body, message_id=f"s{i}")
    return msgs


@pytest.fixture
def repo(tmp_path, secret_store):
    r = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    yield r
    r.close()


def runner(repo, provider, llm, max_per_run=100):
    return Runner(user_id="local", repo=repo, rules=RULES, llm=llm, provider_for=lambda a: provider,
                  max_body_chars=1500, max_per_run=max_per_run)


def test_full_run_then_idempotent_rerun(repo):
    provider = Provider(_messages())
    llm = FakeLLM(INTERVIEW)
    stats = runner(repo, provider, llm).run([ACCOUNT])
    assert stats.sensitive == 5 and stats.classified == 2 and len(stats.alerts) == 2
    assert len(llm.calls) == 2  # only the two SAFE messages
    assert all("OTP" not in c and "debited" not in c for c in llm.calls)

    rows = {m.message_id: m for m in repo.list_email_meta("local")}
    for i in range(5):
        s = rows[f"s{i}"]
        assert s.gate is GateDecision.SENSITIVE and s.sender_address is None and s.classification is None
    assert rows["job"].classification == INTERVIEW
    apps = repo.list_applications("local")
    assert len(apps) == 1 and apps[0].current_stage is Stage.INTERVIEW
    assert repo.get_sync_cursor("local", "personal") == "100"

    # Re-run: nothing is processed twice.
    stats2 = runner(repo, provider, llm).run([ACCOUNT])
    assert stats2.new == 0 and len(llm.calls) == 2
    assert provider.seen_cursors == [None, "100"]


def test_backend_down_leaves_mail_pending_then_recovers(repo):
    provider = Provider(_messages())
    down = FakeLLM(raise_=BackendUnavailable("down"))
    stats = runner(repo, provider, down).run([ACCOUNT])
    assert stats.pending == 2 and len(down.calls) == 1  # stops calling after the first failure
    assert set(repo.list_pending("local", "personal", 10)) == {"job", "friend"}
    assert repo.get_sync_cursor("local", "personal") == "100"  # cursor still advances

    up = FakeLLM(INTERVIEW)
    provider.messages_for_history = {}
    stats2 = runner(repo, provider, up).run([ACCOUNT])
    assert stats2.classified == 2 and repo.list_pending("local", "personal", 10) == []


def test_invalid_output_twice_is_unclassified(repo):
    provider = Provider({"friend": make("rahul@gmail.com", "Rahul", "Dinner", "Dinner Friday?", message_id="friend")})
    llm = FakeLLM(raise_=InvalidOutput("bad"))
    stats = runner(repo, provider, llm).run([ACCOUNT])
    assert stats.unclassified == 1 and len(llm.calls) == 2
    assert repo.list_email_meta("local")[0].status is MessageStatus.UNCLASSIFIED


def test_fetch_failure_and_cap_become_pending(repo):
    msgs = _messages()
    provider = Provider(msgs)
    provider.fail_ids = {"job"}
    stats = runner(repo, provider, FakeLLM(INTERVIEW), max_per_run=3).run([ACCOUNT])
    assert stats.pending == len(msgs) - 3 + 1
    assert "job" in repo.list_pending("local", "personal", 50)


def test_company_domain_becomes_priority_next_run(repo):
    msg = make("careers@acme.com", "Acme Careers", "Application received", "Thanks for applying to Acme.", message_id="a1")
    applied = INTERVIEW.model_copy(update={"stage": Stage.APPLIED, "action_required": False})
    runner(repo, Provider({"a1": msg}), FakeLLM(applied)).run([ACCOUNT])
    assert repo.application_domains("local") == {"acme.com"}
    assert RULES.with_priority_domains(repo.application_domains("local")).tier_for("hr@acme.com").value == "priority"


def test_held_job_mail_is_stored_minimally_and_alerts(repo):
    msg = make("support@hackerearth.com", "HackerEarth", "Coding challenge invite", "Your verification code is 771203.",
               message_id="h1")
    llm = FakeLLM(INTERVIEW)
    stats = runner(repo, Provider({"h1": msg}), llm).run([ACCOUNT])
    assert stats.sensitive == 1 and stats.held_jobs == 1 and llm.calls == []
    meta = repo.list_email_meta("local")[0]
    assert meta.gate is GateDecision.SENSITIVE and meta.sender_address is None and meta.classification is None
    assert meta.held_job and meta.held_company == "HackerEarth" and meta.held_stage is Stage.ASSESSMENT
    assert meta.held_reason == "Contains a verification code"
    alert = stats.alerts[0]
    assert alert.held and alert.title() == "HackerEarth · assessment · needs your attention"
    apps = repo.list_applications("local")
    assert len(apps) == 1 and apps[0].company == "HackerEarth" and apps[0].current_stage is Stage.ASSESSMENT
    raw = repo._db.execute("SELECT * FROM messages").fetchone()
    assert "Coding challenge invite" not in str(raw) and "771203" not in str(raw)


def test_rule_classified_mail_is_stored_without_llm(repo):
    msgs = {
        "n1": make("news@substack.com", "Substack", "Weekly", "Hello readers", message_id="n1", is_bulk=True),
        "j1": make("jobalerts-noreply@linkedin.com", "LinkedIn Job Alerts", "Jobs", "New jobs", message_id="j1"),
        "i1": make("no-reply@mail.instagram.com", "Instagram", "DMs", "2 unread", message_id="i1"),
    }
    llm = FakeLLM(INTERVIEW)
    stats = runner(repo, Provider(msgs), llm).run([ACCOUNT])
    assert llm.calls == [] and stats.rule_classified == 3 and stats.alerts == []
    by_id = {m.message_id: m for m in repo.list_email_meta("local")}
    assert by_id["n1"].classification.category is Category.NEWSLETTER and by_id["n1"].classified_by == "rule:bulk_header"
    assert by_id["j1"].classification.category is Category.JOB_ALERT
    assert by_id["i1"].classification.category is Category.NOTIFICATION


def test_action_required_alerts_only_for_known_company_or_priority(repo):
    act = Classification(category=Category.JOB, company="Initech", role=None, stage=Stage.OTHER,
                         action_required=True, deadline=None, summary="Please reply to Initech.")
    msg = make("hr@initech.com", "Initech HR", "Quick question", "Please reply", message_id="a1")
    stats = runner(repo, Provider({"a1": msg}), FakeLLM(act)).run([ACCOUNT])
    assert stats.alerts == []  # unknown company, non-priority sender

    applied = act.model_copy(update={"stage": Stage.APPLIED, "action_required": False})
    runner(repo, Provider({"a2": make("hr@initech.com", "Initech HR", "Applied", "Thanks", message_id="a2")}),
           FakeLLM(applied)).run([ACCOUNT])
    stats = runner(repo, Provider({"a3": make("hr@initech.com", "Initech HR", "Docs", "Send docs", message_id="a3")}),
                   FakeLLM(act)).run([ACCOUNT])
    assert len(stats.alerts) == 1  # company is tracked now


def test_llm_budget_exhausted_leaves_rest_pending(repo):
    from mailwarden.core.classify.ratelimit import RateLimitedBackend

    msgs = {f"f{i}": make(f"p{i}@gmail.com", "Friend", "Hi", "Dinner?", message_id=f"f{i}") for i in range(4)}
    llm = RateLimitedBackend(FakeLLM(INTERVIEW), per_minute=600, per_run=2, sleep=lambda s: None)
    stats = runner(repo, Provider(msgs), llm).run([ACCOUNT])
    assert stats.classified == 2 and stats.pending == 2


def test_runner_notifies_through_notifier(repo):
    sent = []

    class N:
        def notify(self, alert):
            sent.append(alert)

    msg = make("no-reply@greenhouse.io", "Acme Recruiting", "Interview", "Please pick a slot.", message_id="job")
    r = Runner(user_id="local", repo=repo, rules=RULES, llm=FakeLLM(INTERVIEW), provider_for=lambda a: Provider({"job": msg}),
               max_body_chars=1500, max_per_run=10, notifier=N())
    r.run([ACCOUNT])
    assert len(sent) == 1 and sent[0].company == "Acme" and sent[0].account == "personal"
    assert "pick a slot" not in sent[0].title().lower()
