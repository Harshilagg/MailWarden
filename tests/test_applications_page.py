"""Applications page: summary, needs-attention cards, stage filters, search, timelines."""

import datetime as dt
import re

from mailwarden.core.models import Application, EmailMeta, GateDecision, JobPost, Stage, Tier
from mailwarden.delivery.dashboard import app_pages
from tests.test_dashboard import NOW, client, cls, env  # noqa: F401  (fixture)


def text(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def _app(repo, company, role, stage, when, mid, account="personal"):
    repo.upsert_application(Application(user_id="local", company=company, role=role, current_stage=stage,
                                        last_update=when, source_message_ids=(mid,)),
                            event_stage=stage, account=account, message_id=mid, occurred_at=when, domain=None)


def _seed(env):
    repo = env.repo_factory()
    _app(repo, "Zeta", "Backend Engineer", Stage.APPLIED, NOW - dt.timedelta(days=30), "z1")  # no reply
    _app(repo, "Indeed", "2026_Java_Eclipse Development_BAN", Stage.APPLIED, NOW - dt.timedelta(days=2), "i1")
    _app(repo, "Rippling", "SDE 1", Stage.REJECTION, NOW - dt.timedelta(days=5), "r1")
    repo.save_jobs("local", account="personal", message_id="ja", sender="LinkedIn", received_at=NOW,
                   posts=[JobPost(title="SDE 1", company="Kappa", location="Bengaluru",
                                  link="https://careers.kappa.com/j/1")], keys=["k"])
    (job,) = [j for j in repo.list_jobs("local") if j.company == "Kappa"]
    _app(repo, "Kappa", "SDE 1", Stage.APPLIED, NOW - dt.timedelta(hours=1), f"job-{job.id}")
    repo.save_email_meta(EmailMeta(
        user_id="local", account="personal", message_id="t1", sender_address="hr@theta.com", sender_name="Theta",
        received_at=NOW - dt.timedelta(days=1), tier=Tier.DEFAULT, gate=GateDecision.SAFE, classified_by="llm",
        classification=cls(company="Theta", role="SWE", stage=Stage.ASSESSMENT, deadline=(NOW + dt.timedelta(days=1)).date())))
    _app(repo, "Theta", "SWE", Stage.ASSESSMENT, NOW - dt.timedelta(days=1), "t1")
    repo.close()


def test_summary_attention_and_timelines(env):
    _seed(env)
    html = client(env).get("/applications").text
    page = text(html)
    # The env fixture also tracks Acme (interview).
    assert "6 tracked" in page and "2 in progress" in page and "1 without a reply for 3+ weeks" in page
    attention = html.split('id="needs-action"')[1].split('class="pipeline"')[0]
    assert "Theta" in attention and "due tomorrow" in text(attention) and "Acme" in attention
    assert attention.index("Theta") < attention.index("Acme")  # soonest deadline first
    assert "no reply in 30 days" in page
    assert "Java Eclipse Development" in page and "2026_Java" not in page  # readable role
    assert "platform" in text(html.split("Indeed")[1][:400])  # Indeed isn't the employer
    assert 'href="https://careers.kappa.com/j/1"' in html and "you marked it applied" in page
    assert 'href="https://mail.google.com/mail/u/me@gmail.com/#all/t1"' in html


def test_stage_filters_search_and_sort(env):
    _seed(env)
    c = client(env)
    rejected = text(c.get("/applications?stage=rejection").text).split("Sort:")[1]
    assert "Rippling" in rejected and "Zeta" not in rejected
    active = text(c.get("/applications?stage=active").text).split("Sort:")[1]
    assert "Theta" in active and "Acme" in active and "Zeta" not in active
    no_reply = text(c.get("/applications?stage=no_reply").text).split("Sort:")[1]
    assert "Zeta" in no_reply and "Kappa" not in no_reply
    found = text(c.get("/applications?q=rippl").text).split("Sort:")[1]
    assert "Rippling" in found and "Theta" not in found
    by_name = text(c.get("/applications?sort=company").text).split("Sort:")[1]
    assert by_name.index("Acme") < by_name.index("Zeta")
    assert c.get("/applications?stage=bogus&sort=bogus").status_code == 200


def test_filters_are_pure():
    f = app_pages.Filters.parse({"stage": "interview", "sort": "deadline", "q": " acme "})
    assert (f.stage, f.sort, f.q) == ("interview", "deadline", "acme")
    assert f.url(stage="") == "/applications?q=acme&sort=deadline"
    assert app_pages.Filters.parse({"stage": "x"}).stage == ""


def test_empty_page(env):
    repo = env.repo_factory()
    repo._db.execute("DELETE FROM applications")
    repo.close()
    assert "No applications tracked yet" in client(env).get("/applications").text
