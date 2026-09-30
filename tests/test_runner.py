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
