"""MANDATORY: sensitive mail must never reach any LLM backend or the network.

This module is part of the default run; conftest turns any skip into a failure.
"""

import io
from importlib import resources
from unittest.mock import MagicMock

import pytest

from mailwarden.core.classify.base import LLMBackend
from mailwarden.core.models import Account, GateDecision, ProviderKind, Tier
from mailwarden.core.pipeline import Pipeline
from mailwarden.core.sender_rules import SenderRules
from mailwarden.dryrun import run_dry_run
from mailwarden.providers.base import MailProvider, SyncResult
from mailwarden.security import net
from tests.fixtures.emails import SENSITIVE, make

RULES = SenderRules.from_yaml(
    resources.files("mailwarden.templates").joinpath("sender_rules.yaml").read_text()
)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network call attempted while processing sensitive mail")

    monkeypatch.setattr(net.AllowlistedSession, "send", refuse)


def _llms():
    """One mock per backend kind (local and cloud)."""
    local, cloud = MagicMock(spec=LLMBackend), MagicMock(spec=LLMBackend)
    local.remote, cloud.remote = False, True
    return [local, cloud]


@pytest.mark.parametrize("case", SENSITIVE, ids=[c[0] for c in SENSITIVE])
def test_sensitive_fixture_never_reaches_any_llm(case):
    _, sender, name, subject, body = case
    for llm in _llms():
        pipeline = Pipeline(RULES, max_body_chars=1500, llm=llm)
        triage = pipeline.triage(make(sender, name, subject, body))
        assert triage.gate.decision is GateDecision.SENSITIVE, triage
        assert triage.llm_text is None
        assert pipeline.classify_safe(triage) is None
        assert llm.mock_calls == []


@pytest.mark.parametrize("case", SENSITIVE, ids=[c[0] for c in SENSITIVE])
def test_content_alone_is_enough(case):
    """Defence in depth: even with no sender rules at all, content (or name) catches it."""
    _, sender, name, subject, body = case
    triage = Pipeline(SenderRules(), max_body_chars=1500).triage(make(sender, name, subject, body))
    assert triage.gate.decision is GateDecision.SENSITIVE


def test_gate_error_fails_closed(monkeypatch):
    from mailwarden.core import sensitivity_gate

    def boom(text):
        raise RuntimeError("regex engine exploded")

    monkeypatch.setattr(sensitivity_gate, "scan_text", boom)
    llm = MagicMock(spec=LLMBackend)
    p = Pipeline(RULES, max_body_chars=1500, llm=llm)
    t = p.triage(make("friend@gmail.com", "Friend", "hi", "hello"))
    assert t.gate.decision is GateDecision.SENSITIVE and t.gate.reasons == ("gate_error",)
    assert p.classify_safe(t) is None and llm.mock_calls == []


def test_rules_error_fails_closed():
    rules = MagicMock(spec=SenderRules)
    rules.match.side_effect = RuntimeError("bad rules")
    llm = MagicMock(spec=LLMBackend)
    p = Pipeline(rules, max_body_chars=1500, llm=llm)
    t = p.triage(make("friend@gmail.com", "Friend", "hi", "hello"))
    assert t.gate.decision is GateDecision.SENSITIVE
    assert p.classify_safe(t) is None and llm.mock_calls == []


def test_redaction_error_fails_closed(monkeypatch):
    from mailwarden.core import redact

    monkeypatch.setattr(redact, "for_llm", lambda *a, **k: 1 / 0)
    llm = MagicMock(spec=LLMBackend)
    p = Pipeline(RULES, max_body_chars=1500, llm=llm)
    t = p.triage(make("friend@gmail.com", "Friend", "hi", "hello"))
    assert t.gate.decision is GateDecision.SENSITIVE and t.llm_text is None
    assert llm.mock_calls == []


def test_unparsed_content_and_unknown_sender_fail_closed():
    p = Pipeline(RULES, max_body_chars=1500)
    assert p.triage(make("a@b.com", "A", "hi", "", content_complete=False)).gate.sensitive
    assert p.triage(make("", "", "hi", "hello")).gate.sensitive


class _FakeProvider(MailProvider):
    kind = ProviderKind.GMAIL

    def __init__(self, messages):
        self.messages = {str(i): m for i, m in enumerate(messages)}

    def verify_access(self, account):
        return frozenset()

    def list_new(self, account, cursor):
        return SyncResult(list(self.messages), "1", False)

    def list_recent(self, account, limit):
        return list(self.messages)[:limit]

    def get_message(self, account, message_id):
        return self.messages[message_id].model_copy()


def test_dry_run_never_calls_llm_nor_prints_sensitive_content():
    messages = [make(s, n, subj, body, message_id=str(i)) for i, (_, s, n, subj, body) in enumerate(SENSITIVE)]
    provider = _FakeProvider(messages)
    llm = MagicMock(spec=LLMBackend)
    out = io.StringIO()
    account = Account(user_id="local", name="personal", provider=ProviderKind.GMAIL, address="me@gmail.com")
    report = run_dry_run([account], lambda a: provider, Pipeline(RULES, max_body_chars=1500, llm=llm), last=100, out=out)
    printed = out.getvalue()
    assert report.sensitive == len(SENSITIVE) and report.would_classify == 0
    assert llm.mock_calls == []
    for _, _, _, subject, body in SENSITIVE:
        assert subject not in printed
        assert body[:30] not in printed
    for secret in ("739201", "482913", "614022", "ABCDE1234F", "4821"):
        assert secret not in printed
    assert "would send to LLM: nothing" in printed


def test_ignore_tier_is_never_classified():
    rules = SenderRules(domains={"promo.example.com": Tier.IGNORE})
    llm = MagicMock(spec=LLMBackend)
    p = Pipeline(rules, max_body_chars=1500, llm=llm)
    t = p.triage(make("deals@promo.example.com", "Deals", "Big sale", "50% off shoes"))
    assert t.tier is Tier.IGNORE and t.llm_text is None
    assert p.classify_safe(t) is None and llm.mock_calls == []


def test_classify_refuses_forged_non_safe_triage():
    from mailwarden.core.pipeline import GateViolation, Triage
    from mailwarden.core.sensitivity_gate import GateResult

    llm = MagicMock(spec=LLMBackend)
    p = Pipeline(RULES, max_body_chars=1500, llm=llm)
    forged = Triage(Tier.DEFAULT, GateResult(GateDecision.SENSITIVE, ("otp",)), "text")
    with pytest.raises(GateViolation):
        p.classify_safe(forged)
    assert llm.mock_calls == []


def _real_backends():
    from mailwarden.core.classify.groq import GroqBackend
    from mailwarden.core.classify.ollama import OllamaBackend
    from mailwarden.security.net import GROQ_HOSTS, LOCAL_HOSTS, AllowlistedSession

    return [
        GroqBackend(AllowlistedSession(GROQ_HOSTS), "gsk_fake_key_for_tests_only", model="openai/gpt-oss-20b"),
        OllamaBackend(AllowlistedSession(LOCAL_HOSTS), base_url="http://127.0.0.1:11434", model="m", timeout_seconds=1),
    ]


@pytest.mark.parametrize("case", SENSITIVE, ids=[c[0] for c in SENSITIVE])
def test_real_backends_never_contacted_for_sensitive_mail(case):
    """The real Groq/Ollama classes, with the network patched to explode on any call."""
    _, sender, name, subject, body = case
    for backend in _real_backends():
        pipeline = Pipeline(RULES, max_body_chars=1500, llm=backend)
        triage = pipeline.triage(make(sender, name, subject, body))
        assert pipeline.classify_safe(triage) is None  # no_network fixture would raise on any request


def test_runner_never_sends_sensitive_mail(tmp_path, secret_store):
    from mailwarden.core.runner import Runner
    from mailwarden.storage.sqlite_store import SQLCipherRepository

    messages = [make(s, n, subj, body, message_id=str(i)) for i, (_, s, n, subj, body) in enumerate(SENSITIVE)]
    provider = _FakeProvider(messages)
    llm = MagicMock(spec=LLMBackend)
    repo = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    account = Account(user_id="local", name="personal", provider=ProviderKind.GMAIL, address="me@gmail.com")
    stats = Runner(user_id="local", repo=repo, rules=RULES, llm=llm, provider_for=lambda a: provider,
                   max_body_chars=1500, max_per_run=500).run([account])
    assert stats.sensitive == len(SENSITIVE) and llm.mock_calls == []
    for meta in repo.list_email_meta("local"):
        assert meta.sender_address is None and meta.classification is None
    repo.close()
