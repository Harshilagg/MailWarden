"""Regression tests for the hard/soft gate split, dual-use company domains and job alerts."""

import datetime as dt
import json
from importlib import resources
from unittest.mock import MagicMock

import pytest

from mailwarden.core.classify.base import LLMBackend
from mailwarden.core.models import Account, Category, Classification, GateDecision, ProviderKind, Stage, Tier
from mailwarden.core.pipeline import Pipeline
from mailwarden.core.sender_rules import SenderRules
from tests.fixtures.emails import make

RULES = SenderRules.from_yaml(resources.files("mailwarden.templates").joinpath("sender_rules.yaml").read_text())
ACCOUNT = Account(user_id="local", name="personal", provider=ProviderKind.GMAIL, address="me@gmail.com")

PHONEPE_APPLICATION = dict(
    sender="no-reply@phonepe.com", name="PhonePe",
    subject="Application Received - Software Engineer (Backend)",
    body=(
        "Hi Harshil,\n\nThank you for applying for the position of Software Engineer (Backend) at PhonePe, "
        "India's leading UPI payments app. Our hiring team will review your application.\n\n"
        "Regards,\nPhonePe Recruitment Team\n\n"
        "If you notice any suspicious activity on your candidate account, write to us. "
        "Please do not share your password or forward this email.\n"
        "Sent via SmartRecruiters"
    ),
)


def triage(**kw):
    return Pipeline(RULES, max_body_chars=1500).triage(make(kw["sender"], kw["name"], kw["subject"], kw["body"]))


# --- 1 + 2: soft-only holds with strong recruiting markers become SAFE job mail -------------

def test_ats_application_from_payments_domain_is_safe_job_mail():
    t = triage(**PHONEPE_APPLICATION)
    assert t.gate.decision is GateDecision.SAFE, t.gate
    assert {"sender_tier", "login_alert", "do_not_share", "password"} <= set(t.gate.waived)
    assert t.tier is Tier.PRIORITY and t.llm_text is not None
    assert "Software Engineer" in t.llm_text and "SmartRecruiters" in t.llm_text


def test_phonepe_application_updates_applications_table(tmp_path, secret_store):
    from mailwarden.core.runner import Runner
    from mailwarden.storage.sqlite_store import SQLCipherRepository
    from tests.test_runner import FakeLLM, Provider

    applied = Classification(category=Category.JOB, company="PhonePe", role="Software Engineer (Backend)",
                             stage=Stage.APPLIED, action_required=False, deadline=None,
                             summary="Your application to PhonePe was received.")
    msg = make(PHONEPE_APPLICATION["sender"], PHONEPE_APPLICATION["name"], PHONEPE_APPLICATION["subject"],
               PHONEPE_APPLICATION["body"], message_id="pp1")
    repo = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    llm = FakeLLM(applied)
    stats = Runner(user_id="local", repo=repo, rules=RULES, llm=llm, provider_for=lambda a: Provider({"pp1": msg}),
                   max_body_chars=1500, max_per_run=10).run([ACCOUNT])
    assert stats.sensitive == 0 and stats.classified == 1 and stats.waived == 1 and len(llm.calls) == 1
    meta = repo.list_email_meta("local")[0]
    assert meta.classification.category is Category.JOB and meta.classification.stage is Stage.APPLIED
    apps = repo.list_applications("local")
    assert len(apps) == 1 and apps[0].company == "PhonePe" and apps[0].current_stage is Stage.APPLIED
    repo.close()


# --- HARD rules always hold -----------------------------------------------------------------

@pytest.mark.parametrize(
    "sender, name, subject, body, hard",
    [
        ("no-reply@phonepe.com", "PhonePe", "Application Received: your OTP",
         "Your OTP is 482913. Do not share it. Sent via SmartRecruiters.", "otp"),
        ("alerts@hdfcbank.net", "HDFC Bank", "Thank you for applying",
         "Rs 2,450.00 has been debited from your account. Sent via SmartRecruiters.", "debited_credited"),
        ("no-reply@phonepe.com", "PhonePe", "Application received",
         "Card ending 4821 was charged. Recruitment Team.", "card_ending"),
        ("hr@acme.com", "Acme Hiring Team", "Application received",
         "Your Aadhaar 2341 2341 2346 was verified for onboarding.", "aadhaar_number"),
        ("hr@acme.com", "Acme Hiring Team", "Application received", "Your PAN is ABCDE1234F.", "pan"),
    ],
)
def test_hard_rules_hold_despite_recruiting_markers(sender, name, subject, body, hard):
    llm = MagicMock(spec=LLMBackend)
    p = Pipeline(RULES, max_body_chars=1500, llm=llm)
    t = p.triage(make(sender, name, subject, body))
    assert t.gate.sensitive and hard in t.gate.reasons and not t.gate.waived
    assert p.classify_safe(t) is None and llm.mock_calls == []


def test_bank_transaction_still_held():
    t = triage(sender="alerts@idfcfirstbank.com", name="IDFC FIRST Bank", subject="Transaction alert",
               body="INR 1,299.00 debited from A/c XX4821 on 30-09-26.")
    assert t.gate.sensitive and t.held_job is None


def test_account_security_alert_never_waived():
    t = triage(sender="no-reply@accounts.google.com", name="Google", subject="Application received",
               body="Security alert: suspicious activity on your account. Thank you for applying. Sent via SmartRecruiters")
    assert t.gate.sensitive and "login_alert" in t.gate.reasons and not t.gate.waived


def test_login_alert_without_recruiting_markers_stays_held():
    t = triage(sender="security@discordapp.com", name="Discord", subject="New login location",
               body="Someone tried to log into your account from a new location.")
    assert t.gate.sensitive


def test_bank_marketing_with_careers_footer_is_not_waived():
    """Strict mode: a bank/payments sender needs an ATS relay or a subject phrase, not a body phrase."""
    t = triage(sender="offers@idfcfirstbank.com", name="IDFC FIRST Bank", subject="Pre-approved offer for you",
               body="Upgrade your savings. Explore career opportunities with us at our careers page.")
    assert t.gate.sensitive


def test_government_sender_tier_is_hard():
    t = triage(sender="no-reply@incometax.gov.in", name="Income Tax Department", subject="Thank you for applying",
               body="Hiring team update. Sent via SmartRecruiters")
    assert t.gate.sensitive


# --- job alerts -----------------------------------------------------------------------------

CYBER_DIGEST = (
    "Your job alert for Security in Bengaluru\nNew jobs match your preferences.\n\n"
    "Cyber Security Analyst\nAcme Corp\nBengaluru\nView job: https://www.linkedin.com/comm/jobs/view/111?trk=x\n"
    "---------------------------------------------------------\n"
    "Cyber Security Engineer - Security Alert Monitoring\nGlobex\nRemote\n"
    "View job: https://www.linkedin.com/comm/jobs/view/222?trk=y\n"
)


@pytest.mark.parametrize("sender", ["jobalerts-noreply@linkedin.com", "campus@naukri.com"])
def test_cyber_security_job_digest_is_job_alert(sender):
    p = Pipeline(RULES, max_body_chars=1500)
    msg = make(sender, "Job Alerts", "Cyber Security Analyst at Acme Corp and 1 more", CYBER_DIGEST)
    t = p.triage(msg)
    assert t.gate.decision is GateDecision.SAFE
    assert t.rule_classification.category is Category.JOB_ALERT
    posts = p.extract_jobs_safe(t, msg)
    assert [j.title for j in posts] == ["Cyber Security Analyst", "Cyber Security Engineer - Security Alert Monitoring"]
    assert posts[1].company == "Globex" and posts[1].location == "Remote"


JOBS2WEB = dict(
    sender="bayer@noreply12.jobs2web.com", name="noreply12.jobs2web.com",
    subject="New job opportunities matching your Job Agent",
    body="Hello Harshil,\nThe following jobs match your job agent.\n\nData Engineer\nSoftware Engineer\n\n"
         "This is a system-generated email. Your password is never included in this email.",
)


def test_jobs2web_job_agent_with_password_footer():
    p = Pipeline(RULES, max_body_chars=1500)
    links = (("Data Engineer", "https://jobs.bayer.com/job/Bengaluru-Data-Engineer/101/"),
             ("Software Engineer", "https://jobs.bayer.com/job/Remote-Software-Engineer/102/"),
             ("Manage your job agents", "https://jobs.bayer.com/talentcommunity/"))
    msg = make(JOBS2WEB["sender"], JOBS2WEB["name"], JOBS2WEB["subject"], JOBS2WEB["body"], links=links)
    t = p.triage(msg)
    assert t.gate.decision is GateDecision.SAFE
    assert t.rule_classification.category is Category.JOB_ALERT and t.sender == "Bayer"
    posts = p.extract_jobs_safe(t, msg)
    assert [(j.title, j.company) for j in posts] == [("Data Engineer", "Bayer"), ("Software Engineer", "Bayer")]


@pytest.mark.parametrize(
    "address, expected",
    [("bayer@noreply12.jobs2web.com", "Bayer"), ("EYJobAlerts@noreply2.jobs2web.com", "EY"),
     ("careers@noreply.jobs2web.com", "jobs2web.com")],
)
def test_sender_label_from_local_part(address, expected):
    from mailwarden.core.recruiting import sender_label

    assert sender_label("noreply12.jobs2web.com", address) == expected
    assert sender_label("", address) == expected


def test_llm_fallback_never_sees_urls_and_links_map_back():
    captured = []

    class Extractor(LLMBackend):
        name, model, remote = "x", "x", True

        def classify(self, text):
            raise AssertionError

        def extract_jobs(self, text):
            captured.append(text)
            return json.dumps({"jobs": [
                {"title": "Backend Intern", "company": "Zeta", "location": "Bengaluru", "link": 1},
                {"title": "Ignore [NUM] placeholders", "company": None, "location": None, "link": 99},
            ]})

    p = Pipeline(RULES, max_body_chars=1500, llm=Extractor())
    links = (("Backend Intern at Zeta", "https://internshala.com/u/abc?token=SECRET123"),)
    msg = make("student@internshala.com", "Internshala", "Internships for you", "Here are internships for you.", links=links)
    t = p.triage(msg)
    posts = p.extract_jobs_safe(t, msg)
    assert "SECRET123" not in captured[0] and "https://" not in captured[0]
    assert "[L1] Backend Intern at Zeta (internshala.com)" in captured[0]
    assert posts[0].link == "https://internshala.com/u/abc?token=SECRET123"
    assert posts[1].link is None and "[NUM]" not in posts[1].title


def test_extraction_refuses_non_safe_mail():
    from mailwarden.core.pipeline import GateViolation

    p = Pipeline(RULES, max_body_chars=1500)
    msg = make("campus@naukri.com", "Naukri", "OTP", "Your OTP is 482913")
    t = p.triage(msg)
    with pytest.raises(GateViolation):
        p.extract_jobs_safe(t, msg)


def test_matches_filters():
    from mailwarden.core.job_alerts import matches_filters

    kw, loc = ["software engineer", "backend", "full stack", "sde"], ["Bengaluru", "Remote"]
    assert matches_filters("Backend Developer (Go)", "Bangalore, India", kw, loc)
    assert matches_filters("SDE-I, Rewards", None, kw, loc)
    assert not matches_filters("SDE-I, Rewards", "Gurugram", kw, loc)
    assert not matches_filters("Marketing Intern", "Remote", kw, loc)


def test_jobs_deduplicated_across_senders_and_daily_notice(tmp_path, secret_store):
    from mailwarden.core.job_alerts import dedup_key
    from mailwarden.core.models import JobPost
    from mailwarden.storage.sqlite_store import SQLCipherRepository

    repo = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    now = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.UTC)
    a = JobPost(title="Backend Engineer", company="Zeta", location="Bengaluru", link="https://linkedin.com/jobs/view/1")
    b = JobPost(title="Backend  engineer", company="Zeta Pvt Ltd", location=None, link="https://naukri.com/job-listings-9")
    assert repo.save_jobs("local", account="p", message_id="m1", sender="LinkedIn", received_at=now,
                          posts=[a], keys=[dedup_key(a, "LinkedIn")]) == 1
    assert repo.save_jobs("local", account="p", message_id="m2", sender="Naukri", received_at=now,
                          posts=[b], keys=[dedup_key(b, "Naukri")]) == 0
    assert len(repo.list_jobs("local")) == 1

    sent = []

    class N:
        def notify(self, alert):
            raise AssertionError

        def notify_text(self, text, path):
            sent.append((text, path))

    from mailwarden.core.digest_job import maybe_notify_top_jobs

    job_id = repo.list_jobs("local")[0].id
    assert maybe_notify_top_jobs(repo, "local", now=now, profile=None, notifier=N()) == 0  # not scored yet
    repo.save_score("local", job_id, score=7.5, level="full", detail={}, input_hash="h")
    assert maybe_notify_top_jobs(repo, "local", now=now, profile=None, notifier=N()) == 1
    assert sent == [("1 new job scored 7+", "/apply")]
    assert maybe_notify_top_jobs(repo, "local", now=now + dt.timedelta(hours=6), profile=None,
                                 notifier=N()) == 0  # once per day
    assert len(sent) == 1
    repo.close()


def test_runner_extracts_jobs_from_job_alerts_without_llm(tmp_path, secret_store):
    from mailwarden.core.runner import Runner
    from mailwarden.storage.sqlite_store import SQLCipherRepository
    from tests.test_runner import FakeLLM, Provider

    repo = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    msg = make("jobalerts-noreply@linkedin.com", "LinkedIn Job Alerts", "Cyber Security Analyst at Acme",
               CYBER_DIGEST, message_id="ja1")
    llm = FakeLLM(None)
    stats = Runner(user_id="local", repo=repo, rules=RULES, llm=llm, provider_for=lambda a: Provider({"ja1": msg}),
                   max_body_chars=1500, max_per_run=10).run([ACCOUNT])
    assert llm.calls == [] and stats.jobs_new == 2 and stats.alerts == []
    jobs = repo.list_jobs("local")
    assert {j.title for j in jobs} == {"Cyber Security Analyst", "Cyber Security Engineer - Security Alert Monitoring"}
    assert all(j.sender == "LinkedIn Job Alerts" for j in jobs)
    repo.close()


def test_regate_reports_per_sender_and_reprocesses(tmp_path, secret_store):
    import io

    from mailwarden.core.models import EmailMeta
    from mailwarden.core.runner import Runner
    from mailwarden.regate import print_regate, run_regate
    from mailwarden.storage.sqlite_store import SQLCipherRepository
    from tests.test_runner import FakeLLM, Provider

    now = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.UTC)
    repo = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    pp = make(PHONEPE_APPLICATION["sender"], PHONEPE_APPLICATION["name"], PHONEPE_APPLICATION["subject"],
              PHONEPE_APPLICATION["body"], message_id="pp1")
    bank = make("alerts@idfcfirstbank.com", "IDFC FIRST Bank", "Txn", "INR 500 debited from A/c XX1234", message_id="b1")
    # Stored the old way: PhonePe held on sender tier, bank held.
    for m in (pp, bank):
        repo.save_email_meta(EmailMeta(user_id="local", account="personal", message_id=m.message_id,
                                       sender_address=None, sender_name=m.sender_name, received_at=now,
                                       tier=Tier.SENSITIVE, gate=GateDecision.SENSITIVE))
    provider = Provider({"pp1": pp, "b1": bank})
    report = run_regate(repo, "local", [ACCOUNT], lambda a: provider, Pipeline(RULES, max_body_chars=1500),
                        days=7, now=now + dt.timedelta(hours=1))
    out = io.StringIO()
    print_regate(report, out, applied=False)
    text = out.getvalue()
    assert report.held_before == 2 and report.held_after == 1
    assert report.to_reprocess == {"personal": ["pp1"]}
    assert "PhonePe  <…@phonepe.com>" in text and "held -> to LLM" in text
    assert "soft rules waived" in text and "IDFC FIRST Bank" in text
    assert "Application Received" not in text and "INR 500" not in text and "Recruitment Team" not in text  # no content

    applied = Classification(category=Category.JOB, company="PhonePe", role=None, stage=Stage.APPLIED,
                             action_required=False, deadline=None, summary="Your PhonePe application was received.")
    runner = Runner(user_id="local", repo=repo, rules=RULES, llm=FakeLLM(applied), provider_for=lambda a: provider,
                    max_body_chars=1500, max_per_run=10)
    stats = runner.reprocess(ACCOUNT, report.to_reprocess["personal"])
    assert stats.classified == 1
    meta = repo.get_email_meta("local", "personal", "pp1")
    assert meta.gate is GateDecision.SAFE and meta.classification.stage is Stage.APPLIED
    assert repo.get_email_meta("local", "personal", "b1").gate is GateDecision.SENSITIVE
    repo.close()
