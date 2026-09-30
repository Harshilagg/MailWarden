"""Nothing leaves Urgent silently: only the user's Done removes an item."""

import datetime as dt
from importlib import resources

import pytest

from mailwarden.core.alerts import priority_safety_net
from mailwarden.core.dates import find_deadline
from mailwarden.core.models import (
    Account, Category, Classification, EmailMeta, GateDecision, ProviderKind, Stage, Tier,
)
from mailwarden.core.overview import is_urgent, urgent_items
from mailwarden.core.runner import Runner
from mailwarden.core.sender_rules import SenderRules
from mailwarden.storage.sqlite_store import SQLCipherRepository
from tests.fixtures.emails import make
from tests.test_runner import FakeLLM, Provider

RULES = SenderRules.from_yaml(resources.files("mailwarden.templates").joinpath("sender_rules.yaml").read_text())
ACCOUNT = Account(user_id="local", name="personal", provider=ProviderKind.GMAIL, address="me@gmail.com")
RECEIVED = dt.datetime(2026, 9, 29, 13, 20, tzinfo=dt.UTC)

# Synthetic stand-in with the same shape as the real email.
COMPETITION = dict(
    sender="events@hackerearth.com", name="HackerEarth",
    subject="Registration confirmed: Booking Holdings Hiring Challenge",
    body="Hi Harshil, you're registered for the Booking Holdings Hiring Challenge on HackerEarth. "
         "Complete your profile and register by 10 Oct to be considered. The challenge opens on 10 Oct.",
)


def cls(**kw):
    base = dict(category=Category.JOB_ALERT, company="Booking Holdings", role=None, stage=None,
                action_required=True, deadline=None, summary="Booking Holdings hiring challenge on HackerEarth.")
    return Classification(**{**base, **kw})


@pytest.fixture
def repo(tmp_path, secret_store):
    r = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    yield r
    r.close()


def _msg(message_id):
    m = make(COMPETITION["sender"], COMPETITION["name"], COMPETITION["subject"], COMPETITION["body"], message_id=message_id)
    return m.model_copy(update={"received_at": RECEIVED})


def runner(repo, llm, messages):
    return Runner(user_id="local", repo=repo, rules=RULES, llm=llm, provider_for=lambda a: Provider(messages),
                  max_body_chars=1500, max_per_run=10)


def _store_as_held_urgent(repo):
    """How the email was stored before the latest changes: held-back job mail, in Urgent."""
    repo.save_email_meta(EmailMeta(
        user_id="local", account="personal", message_id="he1", sender_address=None, sender_name="HackerEarth",
        received_at=RECEIVED, tier=Tier.PRIORITY, gate=GateDecision.SENSITIVE, held_job=True,
        held_company="HackerEarth", held_stage=Stage.ASSESSMENT, held_reason="Contains ID details"))
    assert [i.message_id for i in urgent_items(repo.list_email_meta("local"))] == ["he1"]


# --- the reported regression ----------------------------------------------------------------

def test_competition_registration_stays_in_urgent_after_reprocessing(repo):
    _store_as_held_urgent(repo)
    stats = runner(repo, FakeLLM(cls()), {"he1": _msg("he1")}).reprocess(ACCOUNT, ["he1"])
    items = urgent_items(repo.list_email_meta("local"))
    assert [i.message_id for i in items] == ["he1"]
    item = items[0]
    # safety net: a PRIORITY assessment platform + action required => job / assessment
    assert item.company == "Booking Holdings" and item.stage is Stage.ASSESSMENT
    assert item.deadline == dt.date(2026, 10, 10)  # found locally: "register by 10 Oct"
    assert stats.safety_net == 1


@pytest.mark.parametrize(
    "new",
    [
        cls(category=Category.NEWSLETTER, action_required=False),
        cls(category=Category.OTHER, action_required=False, company=None),
        None,  # unclassified
    ],
)
def test_pinned_item_survives_any_reclassification(repo, new):
    _store_as_held_urgent(repo)
    llm = FakeLLM(new) if new is not None else FakeLLM(raise_=__import__(
        "mailwarden.core.classify.base", fromlist=["InvalidOutput"]).InvalidOutput("bad"))
    stats = runner(repo, llm, {"he1": _msg("he1")}).reprocess(ACCOUNT, ["he1"])
    items = urgent_items(repo.list_email_meta("local"))
    assert [i.message_id for i in items] == ["he1"] and items[0].pinned
    assert stats.urgent_kept == 1


def test_pinned_item_survives_being_held_again(repo):
    _store_as_held_urgent(repo)
    otp = make("events@hackerearth.com", "HackerEarth", "Your OTP", "Your OTP is 482913", message_id="he1")
    runner(repo, FakeLLM(cls()), {"he1": otp}).reprocess(ACCOUNT, ["he1"])
    assert [i.message_id for i in urgent_items(repo.list_email_meta("local"))] == ["he1"]


def test_done_is_the_only_way_out_and_survives_reprocessing(repo):
    _store_as_held_urgent(repo)
    assert repo.dismiss("local", "personal", "he1")
    assert urgent_items(repo.list_email_meta("local")) == []
    runner(repo, FakeLLM(cls(category=Category.JOB, stage=Stage.ASSESSMENT)), {"he1": _msg("he1")}).reprocess(ACCOUNT, ["he1"])
    assert urgent_items(repo.list_email_meta("local")) == []  # still done


def test_new_mail_is_pinned_when_first_urgent(repo):
    job = cls(category=Category.JOB, stage=Stage.INTERVIEW)
    runner(repo, FakeLLM(job), {"he1": _msg("he1")}).run([ACCOUNT])
    meta = repo.get_email_meta("local", "personal", "he1")
    assert meta.urgent_since is not None


def test_is_urgent_only_cleared_by_dismiss():
    base = EmailMeta(user_id="local", account="p", message_id="m", sender_address="a@b.com", sender_name="A",
                     received_at=RECEIVED, tier=Tier.DEFAULT, gate=GateDecision.SAFE,
                     classification=cls(category=Category.NEWSLETTER, action_required=False),
                     urgent_since=RECEIVED)
    assert is_urgent(base)
    assert not is_urgent(base.model_copy(update={"dismissed": True}))


# --- v5 migration pins what is urgent today -------------------------------------------------

def test_migration_pins_currently_urgent_rows(tmp_path, secret_store):
    path = tmp_path / "d" / "mw.db"
    r = SQLCipherRepository.open(path, secret_store, "local")
    r.save_email_meta(EmailMeta(user_id="local", account="p", message_id="u1", sender_address="a@b.com",
                                sender_name="A", received_at=RECEIVED, tier=Tier.DEFAULT, gate=GateDecision.SAFE,
                                classification=cls(category=Category.JOB, stage=Stage.INTERVIEW)))
    r._db.execute("UPDATE messages SET urgent_since = NULL")
    r._db.execute("ALTER TABLE messages DROP COLUMN urgent_since")  # simulate a v4 database
    r.close()
    r = SQLCipherRepository.open(path, secret_store, "local")
    assert r.get_email_meta("local", "p", "u1").urgent_since is not None
    r.close()


# --- safety net and local deadlines -----------------------------------------------------------

@pytest.mark.parametrize(
    "c, tier, platform, expected",
    [
        (cls(), Tier.PRIORITY, True, (Category.JOB, Stage.ASSESSMENT)),
        (cls(category=Category.NEWSLETTER, action_required=False, deadline=dt.date(2026, 10, 10)), Tier.PRIORITY, False,
         (Category.JOB, Stage.OTHER)),
        (cls(action_required=False), Tier.PRIORITY, True, (Category.JOB_ALERT, None)),  # plain job alert stays
        (cls(), Tier.DEFAULT, True, (Category.JOB_ALERT, None)),  # only PRIORITY senders
        (cls(category=Category.JOB, stage=Stage.INTERVIEW), Tier.PRIORITY, True, (Category.JOB, Stage.INTERVIEW)),
    ],
)
def test_priority_safety_net(c, tier, platform, expected):
    out = priority_safety_net(c, tier=tier, assessment_platform=platform)
    assert (out.category, out.stage) == expected


TODAY = dt.date(2026, 9, 30)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("Register by 10 Oct to be considered", dt.date(2026, 10, 10)),
        ("Last date to apply: 10/10/2026", dt.date(2026, 10, 10)),
        ("Registrations close on October 10th, 2026", dt.date(2026, 10, 10)),
        ("Submission deadline 2026-10-12", dt.date(2026, 10, 12)),
        ("Submit by 5 Jan", dt.date(2027, 1, 5)),
        ("The hackathon was on 5 Sep", None),
        ("Batch of 2026, CGPA 8.5", None),
        ("Founded in 10 Oct 1998", None),
        ("Deadline 10 Oct; reminder by 3 Oct", dt.date(2026, 10, 3)),
    ],
)
def test_find_deadline(text, expected):
    assert find_deadline(text, TODAY) == expected


def test_held_job_mail_gets_local_deadline(repo):
    held = make("events@hackerearth.com", "HackerEarth", "Hiring challenge: verify your account",
                "Use code 482913 to verify. Register by 10 Oct.", message_id="h2")
    held = held.model_copy(update={"received_at": RECEIVED})
    stats = runner(repo, FakeLLM(cls()), {"h2": held}).run([ACCOUNT])
    meta = repo.get_email_meta("local", "personal", "h2")
    assert meta.gate is GateDecision.SENSITIVE and meta.held_job and meta.held_deadline == dt.date(2026, 10, 10)
    assert stats.alerts[0].deadline == dt.date(2026, 10, 10)
    assert urgent_items([meta])[0].deadline == dt.date(2026, 10, 10)


def test_regate_reports_urgent_items_affected(repo):
    import io

    from mailwarden.core.pipeline import Pipeline
    from mailwarden.regate import print_regate, run_regate

    _store_as_held_urgent(repo)
    report = run_regate(repo, "local", [ACCOUNT], lambda a: Provider({"he1": _msg("he1")}),
                        Pipeline(RULES, max_body_chars=1500), days=7, now=RECEIVED + dt.timedelta(hours=1),
                        force_ids={"he1"})
    out = io.StringIO()
    print_regate(report, out, applied=False)
    assert report.urgent_reprocessed == 1
    assert "stay in Urgent until you click Done" in out.getvalue()
