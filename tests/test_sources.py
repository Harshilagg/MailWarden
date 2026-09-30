import datetime as dt

import pytest

from mailwarden.core.job_alerts import dedup_key, parse_job_anchors, parse_view_job_blocks
from mailwarden.core.models import JobPost
from mailwarden.core.sources import classify_source, display_company, location_key, split_title_location
from mailwarden.storage.sqlite_store import SQLCipherRepository

NOW = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.UTC)


@pytest.mark.parametrize(
    "address, label, expected",
    [
        ("jobalerts-noreply@linkedin.com", "LinkedIn Job Alerts", ("job_board", "LinkedIn")),
        ("naukrialerts@naukri.com", "Naukri", ("job_board", "Naukri")),
        ("campus@naukri.com", "Naukri Campus", ("job_board", "Naukri Campus")),
        ("x@mail.internshala.com", "Internshala", ("job_board", "Internshala")),
        ("x@match.indeed.com", "Indeed", ("job_board", "Indeed")),
        ("x@monsterindia.com", "Vanya from foundit", ("job_board", "foundit")),
        ("x@postoffice.hirist.tech", "hirist", ("job_board", "hirist")),
        ("hello@cutshort.io", "Cutshort Team", ("startup_platform", "Cutshort")),
        ("x@hi.wellfound.com", "Wellfound", ("startup_platform", "Wellfound")),
        ("x@unstop.com", "Unstop", ("community", "Unstop")),
        ("bayer@noreply12.jobs2web.com", "Bayer", ("ats_feed", "Bayer (jobs2web)")),
        ("EYJobAlerts@noreply2.jobs2web.com", "noreply2.jobs2web.com", ("ats_feed", "EY (jobs2web)")),
        ("x@noreply2.jobs2web.com", "Standardch", ("ats_feed", "Standard Chartered (jobs2web)")),
        ("talent@acme.smartrecruiters.com", "Acme Talent", ("ats_feed", "Acme (SmartRecruiters)")),
        ("x@myworkday.com", "Workday", ("ats_feed", "Workday")),
        ("x@careers.kochind.com", "Koch Careers", ("company_careers", "Koch Industries")),
        ("x@recruitment.americanexpress.com", "Amex Careers", ("company_careers", "American Express")),
        ("friend@gmail.com", "Friend", ("other", "Other (gmail.com)")),
        ("ta@horizon-oracle.wsp.com", "Talent Acquisition Team", ("company_careers", "WSP")),
        ("careers@siemens.com", "Siemens P&O Talent Acquisition", ("company_careers", "Siemens P&O")),
        (None, None, ("other", "Other (unknown)")),
        (None, "LinkedIn Job Alerts", ("job_board", "LinkedIn")),     # old rows: sender name only
        (None, "Naukri Campus Jobs", ("job_board", "Naukri Campus")),
    ],
)
def test_classify_source(address, label, expected):
    assert classify_source(address, label) == expected


@pytest.mark.parametrize(
    "raw, shown",
    [("Ey", "EY"), ("EYJobAlerts", "EY"), ("Amex Careers", "American Express"), ("kpmg india", "KPMG India"),
     ("Hcl tech", "HCLTech"), ("tcs", "TCS"), ("Goldman Sachs Recruiting", "Goldman Sachs"),
     ("standardch", "Standard Chartered"), ("Birlasoftl", "Birlasoft"), ("Capgemitecp", "Capgemini"),
     ("Acme Robotics", "Acme Robotics"), ("Pwc", "PwC"), (None, None), ("", None)],
)
def test_display_company(raw, shown):
    assert display_company(raw) == shown


@pytest.mark.parametrize(
    "title, location, expected",
    [
        ("TTT - .NET Full Stack Developer - Senior 4 - Kolkata, WB, IN, 700091", None,
         ("TTT - .NET Full Stack Developer - Senior 4", "Kolkata")),
        ("Consultant - Tax - Gurgaon - Gurugram, HR, IN, 122003", None, ("Consultant - Tax", "Gurugram")),
        ("Lead Architect - INDIA - PUNE - BIRLASOFT OFFICE - HINJAWADI, IN", None, ("Lead Architect", "Pune")),
        ("SAP EAM - Bangalore, IN", None, ("SAP EAM", "Bangalore")),
        ("SAP EAM - Bangalore, IN", "Remote", ("SAP EAM", "Remote")),  # never overwrites a known location
        ("SDE - Go", None, ("SDE - Go", None)),
        ("Backend Engineer - Payments", None, ("Backend Engineer - Payments", None)),
    ],
)
def test_split_title_location(title, location, expected):
    assert split_title_location(title, location) == expected


@pytest.mark.parametrize("loc, key", [("Bangalore, Karnataka, India", "bengaluru"), ("Bengaluru", "bengaluru"),
                                      ("Gurgaon", "gurugram"), ("Remote only, India", "remote"), (None, ""),
                                      ("Work from home", "remote"), ("Hybrid - Pune", "pune")])
def test_location_key(loc, key):
    assert location_key(loc) == key


def test_parsers_tidy_titles_and_companies():
    posts = parse_job_anchors([("Software Engineer - Bengaluru, KA, IN, 560016", "https://jobs.ey.com/job/1/")], "Ey")
    assert posts[0].title == "Software Engineer" and posts[0].location == "Bengaluru" and posts[0].company == "EY"
    text = "Backend Engineer\nkpmg india\nGurgaon, Haryana\nView job: https://www.linkedin.com/jobs/view/9\n"
    p = parse_view_job_blocks(text)[0]
    assert p.company == "KPMG India"


def test_dedup_key_includes_city():
    a = JobPost(title="Backend Engineer", company="Acme", location="Bangalore, Karnataka")
    b = JobPost(title="Backend  engineer", company="Acme Pvt Ltd", location="Bengaluru")
    c = JobPost(title="Backend Engineer", company="Acme", location="Pune")
    assert dedup_key(a, "x") == dedup_key(b, "x") != dedup_key(c, "x")


@pytest.fixture
def repo(tmp_path, secret_store):
    r = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    yield r
    r.close()


def _save(repo, post, mid, source, when=NOW):
    return repo.save_jobs("local", account="p", message_id=mid, sender=source, received_at=when, posts=[post],
                          keys=[dedup_key(post, source)], source_type="job_board", source_name=source)


def test_merge_across_sources_records_also_on(repo):
    assert _save(repo, JobPost(title="Backend Engineer", company="Acme", location="Bengaluru"), "m1", "LinkedIn") == 1
    assert _save(repo, JobPost(title="Backend Engineer", company="Acme", location="Bangalore"), "m2", "Naukri") == 0
    assert _save(repo, JobPost(title="Backend Engineer", company="Acme", location=None), "m3", "Indeed") == 0
    assert _save(repo, JobPost(title="Backend Engineer", company="Acme", location="Pune"), "m4", "Indeed") == 1
    jobs = sorted(repo.list_jobs("local"), key=lambda j: j.id)
    assert len(jobs) == 2
    assert jobs[0].source_name == "LinkedIn" and jobs[0].also_on == ("Naukri", "Indeed")
    assert jobs[1].location == "Pune" and jobs[1].also_on == ()


def test_city_less_job_gets_city_later(repo):
    _save(repo, JobPost(title="SDE 1", company="Zeta", location=None), "m1", "Internshala")
    assert _save(repo, JobPost(title="SDE 1", company="Zeta", location="Remote"), "m2", "LinkedIn") == 0
    (job,) = repo.list_jobs("local")
    assert job.location == "Remote" and job.also_on == ("LinkedIn",)


def test_v7_migration_merges_and_backs_up(tmp_path, secret_store):
    import os

    path = tmp_path / "d" / "mw.db"
    r = SQLCipherRepository.open(path, secret_store, "local")
    db = r._db
    rows = [
        ("c:acme|t:backend engineer", "Backend Engineer - Bengaluru, KA, IN", "Ey", None, "LinkedIn", "m1", "2026-09-28"),
        ("c:acme|t:backend engineer x", "Backend Engineer", "Ey", "Bangalore", "Naukri", "m2", "2026-09-29"),
        ("c:zeta|t:sde", "SDE", "Zeta", None, "Cutshort Team", "m3", "2026-09-29"),
    ]
    for key, title, company, loc, sender, mid, day in rows:
        db.execute("INSERT INTO job_postings (user_id, dedup_key, title, company, location, sender, account, "
                   "message_id, received_at) VALUES ('local', ?, ?, ?, ?, ?, 'p', ?, ?)",
                   (key, title, company, loc, sender, mid, f"{day}T10:00:00+00:00"))
    db.execute("INSERT INTO messages (user_id, account, message_id, status, sender_address, processed_at) "
               "VALUES ('local', 'p', 'm3', 'done', 'hello@cutshort.io', 'x')")
    db.execute("DROP TABLE job_sightings")
    db.execute("ALTER TABLE job_postings DROP COLUMN source_type")
    db.execute("ALTER TABLE job_postings DROP COLUMN source_name")
    r.close()
    r = SQLCipherRepository.open(path, secret_store, "local")
    jobs = sorted(r.list_jobs("local"), key=lambda j: j.id)
    assert len(jobs) == 2  # the two Acme/EY Bengaluru rows merged
    ey = jobs[0]
    assert ey.title == "Backend Engineer" and ey.company == "EY" and ey.location == "Bengaluru"
    assert ey.also_on and jobs[1].source_type == "startup_platform" and jobs[1].source_name == "Cutshort"
    backup = path.with_name("mw.db.before-v7.bak")
    assert backup.exists() and oct(os.stat(backup).st_mode & 0o777) == "0o600"
    r.close()
