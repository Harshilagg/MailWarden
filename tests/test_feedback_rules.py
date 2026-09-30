"""Behaviour added from the real-inbox tuning round."""

import datetime as dt
import io
from importlib import resources
from unittest.mock import MagicMock

import pytest

from mailwarden.core.classify.base import LLMBackend
from mailwarden.core.models import Account, Category, GateDecision, ProviderKind, Stage, Tier
from mailwarden.core.pipeline import Pipeline
from mailwarden.core.reasons import friendly_reason
from mailwarden.core.sender_rules import SenderRules
from tests.fixtures.emails import make

RULES = SenderRules.from_yaml(resources.files("mailwarden.templates").joinpath("sender_rules.yaml").read_text())


def triage(sender, name, subject, body, **kw):
    return Pipeline(RULES, max_body_chars=1500).triage(make(sender, name, subject, body, **kw))


# --- recruiting overrides ----------------------------------------------------

def test_recruiting_subdomain_is_priority():
    t = triage("noreply@recruitment.americanexpress.com", "Amex Careers", "Next steps", "We'd like to talk.")
    assert t.tier is Tier.PRIORITY and t.gate.decision is GateDecision.SAFE and t.llm_text


def test_unlisted_recruiting_subdomain_of_bank_overrides_parent():
    t = triage("jobs@careers.hdfcbank.com", "HDFC Careers", "Application update", "Thanks for applying.")
    assert t.tier is Tier.PRIORITY and t.override == "recruiting_subdomain" and not t.gate.sensitive


def test_recruiting_name_on_bank_domain_drops_sender_hold_only():
    benign = triage("hr@americanexpress.com", "Amex Careers", "Your application", "Thanks for applying.")
    assert benign.gate.decision is GateDecision.SAFE and benign.override == "recruiting_name"
    otp = triage("hr@americanexpress.com", "Amex Careers", "Login", "Your OTP is 552190.")
    assert otp.gate.sensitive
    assert otp.held_job is None  # banking domain without a recruiting subdomain: not surfaced


def test_account_security_never_overridden():
    t = triage("no-reply@accounts.google.com", "Google Careers", "Hi", "Hello")
    assert t.tier is Tier.SENSITIVE and t.gate.sensitive and t.override is None and t.held_job is None


def test_exact_address_rule_never_overridden():
    rules = SenderRules.from_yaml("sensitive:\n  senders: [careers@bank.example]\n")
    t = Pipeline(rules, max_body_chars=1500).triage(make("careers@bank.example", "Bank Careers", "hi", "hello"))
    assert t.tier is Tier.SENSITIVE and t.gate.sensitive


# --- held-back job mail (option 1, extended) -------------------------------------

@pytest.mark.parametrize(
    "sender, name, subject, company, stage",
    [
        ("support@hackerearth.com", "HackerEarth", "Your coding challenge: OTP inside", "HackerEarth", Stage.ASSESSMENT),
        ("x@recruitment.americanexpress.com", "Amex Careers", "Interview availability - OTP", "Amex", Stage.INTERVIEW),
        ("recruiting@gs.com", "Goldman Sachs Recruiting", "Your offer - do not share this OTP", "Goldman Sachs", Stage.OFFER),
        ("talent@acme.io", "Acme Talent", "Unfortunately - verification code", "Acme", Stage.REJECTION),
        ("noreply@exl.com", "Campus to EXL", "Portal login code", "EXL", None),
    ],
)
def test_held_job_mail_is_surfaced_with_local_metadata(sender, name, subject, company, stage):
    t = triage(sender, name, subject, "Your verification code is 482913. Do not share this code.")
    assert t.gate.sensitive and t.llm_text is None
    assert t.held_job is not None
    assert t.held_job.company == company and t.held_job.stage is stage


@pytest.mark.parametrize(
    "sender, name",
    [
        ("alerts@hdfcbank.net", "HDFC Bank"),
        ("noreply@phonepe.com", "PhonePe"),
        ("jobalerts-noreply@linkedin.com", "LinkedIn Job Alerts"),  # job_alert tier never surfaces
        ("friend@gmail.com", "Rahul"),
    ],
)
def test_non_job_held_mail_is_not_surfaced(sender, name):
    t = triage(sender, name, "OTP", "Your OTP is 482913")
    assert t.gate.sensitive and t.held_job is None


# --- rule classification (no LLM) ----------------------------------------------

@pytest.mark.parametrize(
    "sender, kw, category, rule",
    [
        ("notification@mail.instagram.com", {}, Category.NOTIFICATION, "social"),
        ("notification@facebookmail.com", {}, Category.NOTIFICATION, "social"),
        ("info@x.com", {}, Category.NOTIFICATION, "social"),
        ("jobalerts-noreply@linkedin.com", {}, Category.JOB_ALERT, "job_alert_sender"),
        ("jobs@match.indeed.com", {}, Category.JOB_ALERT, "job_alert_sender"),
        ("news@substack.com", {"is_bulk": True}, Category.NEWSLETTER, "bulk_header"),
    ],
)
def test_rule_classified_mail_never_reaches_llm(sender, kw, category, rule):
    llm = MagicMock(spec=LLMBackend)
    p = Pipeline(RULES, max_body_chars=1500, llm=llm)
    t = p.triage(make(sender, "Sender", "Hello there", "Some ordinary text", **kw))
    assert t.rule_classification is not None and t.rule_classification.category is category
    assert t.rule_name == rule and t.llm_text is None
    assert p.classify_safe(t) is None and llm.mock_calls == []
    assert t.rule_classification.action_required is False


def test_bulk_mail_from_priority_sender_still_goes_to_llm():
    t = triage("no-reply@greenhouse.io", "Acme", "Interview", "Pick a slot", is_bulk=True)
    assert t.rule_classification is None and t.llm_text


def test_sensitive_beats_rule_classification():
    t = triage("jobs@match.indeed.com", "Indeed", "Login", "Your OTP is 123456", is_bulk=True)
    assert t.gate.sensitive and t.rule_classification is None


# --- friendly reasons ---------------------------------------------------------------

@pytest.mark.parametrize(
    "reasons, label",
    [
        (("otp", "banking"), "Contains a verification code"),
        (("code_near_number",), "Contains a verification code"),
        (("password",), "About an account password"),
        (("aadhaar",), "Contains ID details"),
        (("kyc", "transaction"), "Contains ID details"),
        (("card_ending",), "Banking or payment details"),
        (("sender_tier",), "From a bank, payment or account-security sender"),
        (("gate_error",), "Couldn't be checked safely, so it was held back"),
    ],
)
def test_friendly_reason(reasons, label):
    assert friendly_reason(reasons) == label


# --- what goes to Groq --------------------------------------------------------------

def test_name_employers_and_college_are_not_redacted():
    from mailwarden.core.redact import redact_text

    text = "Harshil Aggarwal, IIT Kharagpur'26, worked at Inspira Enterprise and Fischer Jordan."
    out = redact_text(text)
    for kept in ("Harshil Aggarwal", "IIT Kharagpur", "Inspira Enterprise", "Fischer Jordan"):
        assert kept in out


def test_linkedin_intended_for_line_is_stripped():
    from mailwarden.core.redact import strip_footer

    body = "Backend Developer at HP\nView job\nThis email was intended for Harshil Aggarwal (IIT Kharagpur'26)\nThanks"
    out = strip_footer(body)
    assert "intended for" not in out and "Backend Developer at HP" in out and "Thanks" in out


# --- Gmail bulk headers -------------------------------------------------------------

@pytest.mark.parametrize(
    "headers, bulk",
    [
        ([{"name": "List-Unsubscribe", "value": "<mailto:u@x.com>"}], True),
        ([{"name": "Precedence", "value": "bulk"}], True),
        ([{"name": "Precedence", "value": "list"}], True),
        ([], False),
    ],
)
def test_gmail_bulk_flag(headers, bulk):
    from mailwarden.providers.gmail import parse_message

    data = {"id": "a1", "internalDate": "0", "payload": {
        "mimeType": "text/plain", "headers": [{"name": "From", "value": "a@b.com"}, *headers],
        "body": {"data": "aGVsbG8"}}}
    assert parse_message("local", "p", data).is_bulk is bulk


# --- links and dates ----------------------------------------------------------------

def test_gmail_link():
    from mailwarden.core.links import gmail_link

    assert gmail_link("me@gmail.com", "18f0a1b2") == "https://mail.google.com/mail/u/me@gmail.com/#all/18f0a1b2"
    assert gmail_link("me@gmail.com", "../evil") is None


def test_readable_dates():
    from mailwarden.delivery.format import relative_time, short_date

    today = dt.date(2026, 9, 30)
    assert short_date(dt.date(2026, 10, 5), today) == "Mon, 5 Oct"
    assert short_date(dt.date(2027, 1, 2), today) == "Sat, 2 Jan 2027"
    now = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.UTC)
    assert relative_time(now - dt.timedelta(seconds=20), now) == "just now"
    assert relative_time(now - dt.timedelta(hours=2), now) == "2 hours ago"
    assert relative_time(now - dt.timedelta(minutes=1), now) == "1 minute ago"


def test_alert_titles_have_no_content():
    from mailwarden.delivery.base import JobAlert

    held = JobAlert("local", "p", "m1", "Amex", Stage.ASSESSMENT, None, held=True)
    assert held.title() == "Amex · assessment · needs your attention"
    normal = JobAlert("local", "p", "m1", "Acme", Stage.INTERVIEW, dt.date(2026, 10, 5))
    assert normal.title().startswith("Acme · interview · due ")


# --- dry-run summary lists held job-board / recruiter mail with rules ---------------

def test_dry_run_summary_lists_held_recruiter_mail_without_content():
    from mailwarden.dryrun import run_dry_run
    from tests.test_zero_llm_sensitive import _FakeProvider

    msgs = [
        make("recruiting@gs.com", "Goldman Sachs Recruiting", "Set your password", "Create your password to continue.", message_id="1"),
        make("alerts@hdfcbank.net", "HDFC Bank", "Txn", "Rs 500 debited", message_id="2"),
    ]
    out = io.StringIO()
    account = Account(user_id="local", name="p", provider=ProviderKind.GMAIL, address="me@gmail.com")
    run_dry_run([account], lambda a: _FakeProvider(msgs), Pipeline(RULES, max_body_chars=1500), last=10, out=out, summary_only=True)
    text = out.getvalue()
    assert "Goldman Sachs Recruiting <…@gs.com>" in text and "rules: password" in text
    assert 'surfaced as job mail: yes: "Goldman Sachs · needs your attention"' in text
    assert "Create your password" not in text and "Set your password" not in text
    assert "HDFC Bank <…@hdfcbank.net>" not in text  # bank mail is not listed as job mail
