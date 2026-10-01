import datetime as dt
import io
import random

import pytest

from mailwarden.calibrate import agreement, print_report, run_session, sample
from mailwarden.core.job_alerts import dedup_key
from mailwarden.core.models import JobPost, StoredJob
from mailwarden.storage.sqlite_store import SQLCipherRepository

NOW = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.UTC)


def sj(i, score):
    return StoredJob(id=i, user_id="local", title=f"Job {i}", company="C", location=None, link=None, sender="s",
                     account="p", message_id="m", received_at=NOW, score=score, score_level="preliminary")


def test_sample_mixes_bands_and_skips_labelled():
    jobs = [sj(i, 7.0) for i in range(3)] + [sj(10 + i, 5.5) for i in range(10)] + [sj(30 + i, 2.0) for i in range(20)]
    jobs.append(sj(99, None))
    picks = sample(jobs, labelled={30, 31}, count=20, rng=random.Random(1))
    ids = {j.id for j in picks}
    assert len(picks) == 20 and 99 not in ids and not ids & {30, 31}
    assert {0, 1, 2} <= ids  # every high job (band short: filled from others)
    assert sum(1 for j in picks if j.score == 5.5) >= 7


@pytest.fixture
def repo(tmp_path, secret_store):
    r = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    for i, score in enumerate([8.0, 7.0, 6.0, 5.0, 4.0, 2.0]):
        post = JobPost(title=f"Engineer {i}", company=f"Co{i}", location="Bengaluru")
        r.save_jobs("local", account="p", message_id=f"m{i}", sender="LinkedIn", received_at=NOW, posts=[post],
                    keys=[dedup_key(post, "LinkedIn")])
    for j in r.list_jobs("local"):
        score = [8.0, 7.0, 6.0, 5.0, 4.0, 2.0][int(j.title.split()[-1])]
        r.save_score("local", j.id, score=score, level="full" if score == 8.0 else "preliminary",
                     detail={"why": f"why {j.title}", "missing_skills": ["Kafka"]}, input_hash="h")
    yield r
    r.close()


def by_title(repo):
    return {j.title: j for j in repo.list_jobs("local")}


def test_session_saves_labels_handles_typos_skip_and_quit(repo):
    answers = iter(["x", "g", "b", "s", "q"])
    out = io.StringIO()
    done = run_session(repo, "local", count=6, ask=lambda prompt: next(answers), out=out, rng=random.Random(0))
    assert done == 2 and len(repo.list_labels("local")) == 2
    text = out.getvalue()
    assert "score " in text and "why: why Engineer" in text and "missing: Kafka" in text


def test_session_eof_counts_as_quit(repo):
    def ask(prompt):
        raise EOFError

    assert run_session(repo, "local", count=3, ask=ask, out=io.StringIO()) == 0


def test_agreement_and_report(repo):
    jobs = by_title(repo)
    labels = {"Engineer 0": "good", "Engineer 1": "good", "Engineer 2": "good",  # 8, 7 hit; 6 miss
              "Engineer 3": "bad", "Engineer 4": "bad", "Engineer 5": "bad"}     # 5 miss; 4, 2 hit
    for title, label in labels.items():
        j = jobs[title]
        repo.save_label("local", j.id, label, score=j.score, level=j.score_level)
    a = agreement(repo, "local")
    assert (a.good, a.good_hits, a.bad, a.bad_hits) == (3, 2, 3, 2)
    assert [m[2].title for m in a.disagreements] == ["Engineer 2", "Engineer 3"]  # 1 point off each, good first
    out = io.StringIO()
    print_report(repo, "local", out, now=NOW)
    text = out.getvalue()
    assert "scored 7+:      2/3 (67%)" in text and "below 5: 2/3 (67%)" in text
    assert "you said GOOD, scored 6.0 preliminary" in text and "capped at 7" in text
    assert "previous report" not in text
    # rescoring after a profile change, then re-running the report shows before -> now
    repo.save_score("local", jobs["Engineer 2"].id, score=7.5, level="full", detail={}, input_hash="h2")
    out2 = io.StringIO()
    a2 = print_report(repo, "local", out2, now=NOW + dt.timedelta(days=1))
    assert a2.good_hits == 3 and "previous report" in out2.getvalue() and "good 2/3 (67%)" in out2.getvalue()


def test_relabel_overwrites(repo):
    j = next(iter(repo.list_jobs("local")))
    repo.save_label("local", j.id, "good", score=j.score, level=j.score_level)
    repo.save_label("local", j.id, "bad", score=j.score, level=j.score_level)
    assert repo.list_labels("local") == [(j.id, "bad", j.score)]


def test_cli_report_only(tmp_path, monkeypatch, capsys):
    from mailwarden.cli import main

    monkeypatch.setenv("MAILWARDEN_HOME", str(tmp_path / "mw"))
    main(["init"])
    assert main(["jobs", "calibrate", "--report"]) == 2  # needs a profile first
