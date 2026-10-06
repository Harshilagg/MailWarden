"""Recall audit: jobs outside Apply today, exactly why they were left out, and the report."""

import datetime as dt
import io
import random

import pytest

from mailwarden.core.job_alerts import dedup_key
from mailwarden.core.models import Application, JobPost, Stage, StoredJob
from mailwarden.core.ranking import AppliedIndex
from mailwarden.core.recall import Context, Finding, explain, sample, summarise
from mailwarden.recall import audit_due, print_report, run_session
from mailwarden.storage.sqlite_store import SQLCipherRepository
from tests.test_dashboard import PROFILE as DASH_PROFILE
from tests.test_dashboard import client, env  # noqa: F401  (fixture)

NOW = dt.datetime(2026, 10, 5, 12, 0, tzinfo=dt.UTC)
PROFILE = {"avoid_roles": ["intern / internship", "sales"], "locations": ["Bengaluru", "Remote"], "remote_ok": True}
SKILLS = {"react": 0.85, "go": 0.6, "express": 0.3}


def job(i, title="Backend Engineer", *, score=6.0, level="preliminary", days=1, location="Bengaluru", company=None,
        jd_status=None, jd_text=None, matched=(), missing=(), details=None, dismissed=False):
    return StoredJob(id=i, user_id="local", title=title, company=company or f"Co{i}", location=location, link=None,
                     sender="LinkedIn", account="p", message_id="m", received_at=NOW - dt.timedelta(days=days),
                     details=details, jd_status=jd_status, jd_text=jd_text, score=score, score_level=level,
                     matched_skills=tuple(matched), missing_skills=tuple(missing), dismissed=dismissed)


def ctx(jobs, *, n=3, share=0.0, window=3, expire=14, applied=None, profile=PROFILE):
    return Context(jobs=jobs, profile=profile, effective_skills=SKILLS, now=NOW, n=n, watchlist=[],
                   applied=applied or AppliedIndex(), expire_after_days=expire, window_days=window,
                   family_share=share)


def kinds(findings):
    return [f.kind for f in findings]


# --- explaining -----------------------------------------------------------------------------

def test_filtered_jobs_name_the_rule_and_the_change():
    jobs = [job(1, "Senior Backend Engineer"), job(2, "SDE 1", location="Pune, Maharashtra, India"),
            job(3, "Sales Engineer"), job(4, "Backend Engineer, 5+ years"),
            job(5, "Web Development", details="₹ 10,000 /month")]
    c = ctx(jobs)
    (f,) = explain(jobs[0], c)
    assert f.detail == "seniority rule: the title contains 'senior'" and "stop treating 'senior'" in f.suggestion
    (f,) = explain(jobs[1], c)
    assert "'Pune, Maharashtra, India' is not in your locations" in f.detail
    assert f.suggestion == "profile.yaml: add 'Pune' to locations"
    (f,) = explain(jobs[2], c)
    assert f.detail == "avoid_roles category 'sales' matched" and f.suggestion == \
        "profile.yaml: remove 'sales' from avoid_roles"
    (f,) = explain(jobs[3], c)
    assert "asks for 5+ years" in f.detail and f.suggestion == "rule change: allow roles asking up to 5 years"
    (f,) = explain(jobs[4], c)
    assert f.detail.startswith("avoid_roles entry 'intern / internship' matched (stipend")


def test_not_scored_expired_window_and_applied():
    jobs = [job(1, score=None, level=None), job(2, days=30), job(3, days=5), job(4, jd_status="closed"),
            job(5, company="Acme")]
    applied = AppliedIndex.from_applications([Application(user_id="local", company="Acme", role=None,
                                                          current_stage=Stage.APPLIED, last_update=NOW)])
    c = ctx(jobs, applied=applied)
    assert kinds(explain(jobs[0], c)) == ["not_scored"]
    stale = explain(jobs[1], c)
    assert kinds(stale) == ["expired", "window"]  # not "raise max_scores_per_run": expired jobs aren't scored
    assert "raise [job_alerts] expire_after_days (now 14)" in stale[0].suggestion
    (w,) = explain(jobs[2], c)
    assert w.detail == "first seen 5 days ago; Apply today takes the last 3" and "apply_today_days (now 3)" in w.suggestion
    (closed,) = explain(jobs[3], c)
    assert closed.kind == "expired" and closed.suggestion is None  # a closed posting: nothing to change
    assert kinds(explain(jobs[4], c)) == ["applied"]


def test_family_cap_is_named_when_it_was_the_only_reason():
    jobs = [job(i, "Golang Developer", score=7.0) for i in range(1, 4)] + [job(9, "Software Engineer", score=4.0)]
    c = ctx(jobs, n=3, share=0.25)  # cap = max(2, ceil(0.75)) = 2 Go jobs
    left_out = next(j for j in jobs[:3] if j.id not in c.pick_ids)
    (f,) = explain(left_out, c)
    assert f.kind == "family_cap" and "'Go' already had 2 of 3 slots" in f.detail
    assert "max_family_share (now 0.25)" in f.suggestion


def test_low_rank_explains_cutoff_preliminary_cap_and_weights():
    top = [job(i, score=7.0) for i in range(1, 4)]
    low = job(9, "Full Stack Developer", score=5.0, matched=["React", "Express"], missing=["Docker", "GraphQL"])
    c = ctx([*top, low])
    found = explain(low, c)
    assert kinds(found)[:2] == ["rank", "preliminary"]
    assert found[0].detail == "rank 5.5 (score 5.0 (preliminary) · fresh +0.5), below the cutoff of 7.5 for the top 3"
    assert found[1].detail == "scored from the alert title only, without the job description"
    assert found[1].suggestion == "paste or fetch the job description for a full score"
    texts = [f.suggestion for f in found if f.kind == "skill"]
    assert "profile.yaml skill_overrides: raise 'Express' (now 0.30) if it's a real strength" in texts
    assert "profile.yaml skill_overrides: add 'Docker' if you have it" in texts
    assert not any("React" in t for t in texts)  # React is already weighted 0.85


def test_full_score_caps_are_explained():
    top = [job(i, score=8.0, level="full") for i in range(1, 4)]
    senior_jd = "We need 4+ years of backend experience with Go."
    exp = job(8, score=4.0, level="full", jd_status="ok", jd_text=senior_jd * 3)
    must = job(9, score=6.0, level="full", jd_status="ok", jd_text="Great role. " * 20, missing=["Kafka"])
    c = ctx([*top, exp, must])
    # A JD asking 3+ years is caught by the prefilter before any score cap matters.
    assert [f.detail for f in explain(exp, c)] == ["experience rule: asks for 4+ years (limit is 2)"]
    assert any(f.detail == "missing must-have skill(s) cap the score at 6: Kafka" for f in explain(must, c))


def test_filtered_unscored_job_blames_the_filter_not_the_scorer():
    j = job(1, "Senior SDE (Backend)", score=None, level=None)
    assert kinds(explain(j, ctx([j]))) == ["filter"]
    fresh = job(2, score=None, level=None)
    assert kinds(explain(fresh, ctx([fresh]))) == ["not_scored"]  # a current candidate: the queue is the reason


def test_ties_at_the_cutoff_are_called_ties():
    jobs = [job(1, score=5.0, level="full"), job(2, score=5.0, level="full"), job(3, score=5.0)]
    c = ctx(jobs, n=2)
    (tied, *_) = explain(jobs[2], c)
    assert tied.key == "tie" and "tied with the cutoff for the top 2" in tied.detail


# --- sampling and the summary ------------------------------------------------------------------

def test_sample_skips_apply_today_dismissed_and_audited_and_mixes_kinds():
    jobs = ([job(i, score=7.0) for i in range(1, 4)]  # Apply today
            + [job(10 + i, "Senior Engineer") for i in range(8)]  # filtered
            + [job(20 + i, score=3.0) for i in range(8)]  # low-ranked
            + [job(30 + i, days=30) for i in range(5)]  # expired / outside the window
            + [job(40, dismissed=True)])
    c = ctx(jobs)
    picks = sample(c, audited={20, 21}, count=15, rng=random.Random(1))
    ids = {j.id for j in picks}
    assert len(picks) == 15 and not ids & {1, 2, 3, 40, 20, 21}
    assert len(ids & set(range(10, 18))) == 6 and len(ids & set(range(22, 28))) == 6
    assert len(ids & set(range(30, 35))) == 3


def test_summarise_counts_each_cause_once_per_job():
    f1 = [Finding("filter", "a", "add Pune", "location:pune"), Finding("filter", "b", "add Pune", "location:pune")]
    f2 = [Finding("rank", "r"), Finding("preliminary", "p", "paste the JD")]
    s = summarise([("apply", f1), ("apply", f2), ("no", f1)])
    assert (s.audited, s.would_apply) == (3, 2)
    assert dict(s.causes) == {"prefilter rule": 1, "ranked out of the top (below or tied at the cutoff)": 1, "preliminary score (title only)": 1}
    assert dict(s.suggestions) == {"add Pune": 1, "paste the JD": 1}


# --- the session, storage and report -----------------------------------------------------------

@pytest.fixture
def repo(tmp_path, secret_store):
    r = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    posts = [JobPost(title=t, company=c, location=loc, link=None) for t, c, loc in (
        ("Backend Engineer", "A", "Bengaluru"), ("SDE 1", "B", "Bengaluru"),
        ("Senior Backend Engineer", "C", "Bengaluru"), ("Full Stack Developer", "D", "Pune"))]
    r.save_jobs("local", account="p", message_id="m", sender="LinkedIn", received_at=NOW - dt.timedelta(hours=2),
                posts=posts, keys=[dedup_key(p, "x") for p in posts])
    for j, score in zip(r.list_jobs("local"), (3.0, 4.0, 6.0, 8.0), strict=True):
        r.save_score("local", j.id, score=score, level="preliminary", input_hash="h",
                     detail={"matched_skills": [], "missing_skills": [], "evidence": [], "best_project": None,
                             "why": "x"})
    yield r
    r.close()


def _ctx(repo):
    return ctx(repo.list_jobs("local"), n=1)


def test_session_saves_answers_and_explains_would_apply(repo):
    answers = iter(["y", "x", "n", "y"])  # 3 jobs are outside Apply today; "x" is ignored and asked again
    out = io.StringIO()
    answered, would = run_session(repo, "local", _ctx(repo), count=15, ask=lambda p: next(answers), out=out,
                                  rng=random.Random(0))
    text = out.getvalue()
    assert (answered, would) == (3, 2)
    assert "NOT in today's Apply today (1 jobs)" in text and text.count("Why it wasn't in Apply today:") == 2
    audits = repo.list_audits("local")
    assert [a.answer for a in audits].count("apply") == 2 and len(audits) == 3
    assert all(a.findings for a in audits)  # the explanation is saved with each answer
    assert audit_due(repo, "local", NOW) is None and audit_due(repo, "local", NOW + dt.timedelta(days=8)) == 8
    # Next week's session never repeats an audited job: all three are done.
    out2 = io.StringIO()
    assert run_session(repo, "local", _ctx(repo), count=15, ask=lambda p: "q", out=out2) == (0, 0)
    assert "No jobs outside Apply today left to audit." in out2.getvalue()


def test_quit_and_end_of_input_stop_cleanly(repo):
    def eof(prompt):
        raise EOFError

    assert run_session(repo, "local", _ctx(repo), count=15, ask=eof, out=io.StringIO()) == (0, 0)
    assert repo.list_audits("local") == [] and audit_due(repo, "local", NOW) == -1


def test_report_counts_reasons_and_suggestions(repo):
    out = io.StringIO()
    print_report(repo, "local", out, now=NOW)
    assert "No audits yet" in out.getvalue()
    c = _ctx(repo)
    by_title = {j.title: j for j in c.jobs}
    for title, answer in (("Senior Backend Engineer", "apply"), ("Full Stack Developer", "apply"), ("SDE 1", "no")):
        j = by_title[title]
        repo.save_audit("local", j.id, answer, [f.to_dict() for f in explain(j, c)], score=j.score,
                        level=j.score_level, at=NOW)
    out = io.StringIO()
    print_report(repo, "local", out, now=NOW)
    text = out.getvalue()
    assert "last 7 days: 3 audited, 2/3 (67%) missed-good" in text
    assert "prefilter rule" in text and "profile.yaml: add 'Pune' to locations" in text
    assert "rule change: stop treating 'senior' in a title as too senior" in text
    assert "Senior Backend Engineer · C  [" in text and "preliminary, audited 2026-10-05]" in text
    assert "SDE 1" not in text.split("Missed-good jobs")[1]  # you said no: not a miss


def test_audits_go_when_the_job_goes(repo):
    j = repo.list_jobs("local")[0]
    repo.save_audit("local", j.id, "no", [], score=None, level=None, at=NOW)
    repo._db.execute("DELETE FROM job_postings WHERE id = ?", (j.id,))
    assert repo.list_audits("local") == []


def test_dashboard_reminds_weekly(env):  # noqa: F811
    env.profile_loader = lambda: DASH_PROFILE
    env.now = lambda: NOW
    repo = env.repo_factory()
    repo.save_jobs("local", account="personal", message_id="j", sender="LinkedIn", received_at=NOW,
                   posts=[JobPost(title="Backend Engineer", company="Z", location="Bengaluru", link=None)],
                   keys=["k"])
    (j,) = repo.list_jobs("local")
    repo.save_score("local", j.id, score=6.0, level="preliminary", input_hash="h",
                    detail={"matched_skills": [], "missing_skills": [], "evidence": [], "best_project": None,
                            "why": "x"})
    repo.close()
    c = client(env)
    assert "Weekly recall audit not run yet" in c.get("/apply").text
    repo = env.repo_factory()
    repo.set_state("local", "recall_audit_at", (NOW - dt.timedelta(days=2)).isoformat())
    repo.close()
    assert "Weekly recall audit" not in c.get("/apply").text
