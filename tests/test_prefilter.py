import pytest

from mailwarden.core.prefilter import prefilter

P = {"avoid_roles": ["security-only", "sales", "support", "non-engineering", "qa / test engineer"],
     "locations": ["Bengaluru", "Remote"], "remote_ok": True}


@pytest.mark.parametrize(
    "title, location, reason",
    [
        ("Senior Software Engineer", "Bengaluru", "seniority (Senior)"),
        ("Sr. Backend Developer", "Bengaluru", "seniority (Sr)"),
        ("Tech Lead - Payments", "Remote", "seniority (Lead)"),
        ("Engineering Manager", "Bengaluru", "seniority (Manager)"),
        ("Solutions Architect", "Bengaluru", "seniority (Architect)"),
        ("Staff Engineer", "Remote", "seniority (Staff)"),
        ("Principal SDE", "Bengaluru", "seniority (Principal)"),
        ("Head of Engineering", "Bengaluru", "seniority (Head)"),
        ("Software Engineer II", "Bengaluru", "level above new grad (II)"),
        ("SDE-2, Payments", "Bengaluru", "level above new grad (2)"),
        ("SDE3", "Bengaluru", "level above new grad (3)"),
        ("Backend Engineer, L5", "Bengaluru", "level above new grad (L5)"),
        ("Full Stack Engineer (3+ years)", "Remote", "needs 3+ years"),
        ("Java Developer 4-6 yrs", "Bengaluru", "needs 4+ years"),
        ("Cyber Security Analyst", "Bengaluru", "security-only role"),
        ("SOC Analyst L1", "Bengaluru", "security-only role"),
        ("Sales Engineer", "Bengaluru", "sales role"),
        ("Technical Support Engineer", "Bengaluru", "support role"),
        ("Marketing Intern", "Remote", "non-engineering role"),
        ("Civil Site Engineer", "Bengaluru", "non-engineering role"),
        ("QA Engineer", "Bengaluru", "avoid role: qa / test engineer"),  # "qa" is one of the alternatives
        ("Test Engineer", "Bengaluru", "avoid role: qa / test engineer"),
        ("Backend Developer", "Gurugram", "location (Gurugram)"),
        ("Backend Developer", "Hybrid - Pune", "location (Hybrid - Pune)"),
    ],
)
def test_filtered(title, location, reason):
    result = prefilter(title, location, P)
    if reason is None:
        assert not result.excluded, result
    else:
        assert reason in result.reasons, result.reasons
        assert result.label.startswith("Filtered: ")


@pytest.mark.parametrize(
    "title, location",
    [
        ("SDE-I, Rewards", "Bengaluru"),
        ("SDE 1", "Bangalore, Karnataka"),
        ("Software Engineer", "Remote"),
        ("Backend Developer ( Go Lang)", "Work from home"),
        ("Software Engineer, Security Platform", "Bengaluru"),  # builds software: not security-only
        ("Product Security Engineer", "Bengaluru"),
        ("Data Engineer", "India"),                           # country-wide: can't tell, keep
        ("Graduate Engineer Trainee", None),                   # unknown location: keep
        ("Software Engineer 2026 Batch", "Bengaluru"),         # a year is not a level
        ("Associate Software Engineer (0-2 years)", "Remote"),
        ("Platform Engineer, Headless CMS", "Remote"),         # 'Headless' is not 'Head'
        ("Staffing-platform Backend Developer", "Remote"),
    ],
)
def test_kept(title, location):
    assert not prefilter(title, location, P).excluded, prefilter(title, location, P).reasons


def test_level_ok_when_jd_says_entry_level():
    jd = "We are hiring freshers (0-2 years) for our 2026 graduate program."
    assert not prefilter("Software Engineer II", "Bengaluru", P, jd_text=jd).excluded
    assert prefilter("Software Engineer II", "Bengaluru", P).excluded


def test_years_from_jd():
    assert "needs 3+ years" in prefilter("Backend Engineer", "Remote", P, jd_text="Minimum 3 years of Go.").reasons
    assert not prefilter("Backend Engineer", "Remote", P, jd_text="1-2 years preferred").excluded


def test_remote_not_ok():
    no_remote = {**P, "remote_ok": False, "locations": ["Bengaluru"]}
    assert prefilter("Backend Engineer", "Remote", no_remote).excluded
    assert not prefilter("Backend Engineer", "Bengaluru", no_remote).excluded


def test_multiple_reasons_all_reported():
    r = prefilter("Senior Sales Manager", "Chennai", P)
    assert {"seniority (Senior)", "sales role", "location (Chennai)"} <= set(r.reasons)


def test_empty_profile_filters_only_seniority_and_levels():
    assert not prefilter("Marketing Intern", "Mars", {}).excluded
    assert prefilter("Senior Engineer", None, {}).excluded
