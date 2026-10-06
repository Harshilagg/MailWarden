"""The policy prefilter: hard exclusions + experience + location. Stack never filters."""

import pytest

from mailwarden.core.experience import STRETCH, TOO_SENIOR, UNKNOWN, VERIFIED_FRESHER, classify
from mailwarden.core.models import StoredJob
from mailwarden.core.prefilter import location_ok, penalty, prefilter
from tests.policy_helpers import POLICY, policy


def verdict(title, location="Bengaluru", **kw):
    return prefilter(POLICY, title=title, location=location, **kw)


# --- the synthetic jobs from the matching plan ----------------------------------------------

@pytest.mark.parametrize("title, status, filtered", [
    ("Senior Software Engineer", TOO_SENIOR, True),
    ("Software Engineer (2-5 yrs)", STRETCH, False),
    ("SDE 1 Java", VERIFIED_FRESHER, False),
    ("Golang Developer 0-2 yrs", VERIFIED_FRESHER, False),
    ("GenAI Engineer, Python", UNKNOWN, False),
    ("MERN Developer fresher", VERIFIED_FRESHER, False),
    (".NET Developer 0-1 yrs", VERIFIED_FRESHER, False),
])
def test_plan_examples(title, status, filtered):
    v = verdict(title)
    assert v.experience.status == status and v.excluded is filtered, v.reasons


def test_dotnet_passes_with_a_soft_penalty_only():
    job = StoredJob(id=1, user_id="u", title=".NET Developer 0-1 yrs", company="X", location="Bengaluru", link=None,
                    sender="s", account="a", message_id="m", received_at="2026-10-06T00:00:00+00:00")
    assert not verdict(job.title).excluded and penalty(job, POLICY) == (".net",)


def test_internship_is_filtered_whatever_the_stack():
    v = verdict("Python Development (Internship)")
    assert v.excluded and v.reasons[0] == "excluded role: internship (title has 'Internship')"


# --- hard exclusions ----------------------------------------------------------------------------

@pytest.mark.parametrize("title, reason", [
    ("Cyber Security Analyst", "excluded role: security analyst"),
    ("SOC Analyst L1", "excluded role: soc analyst"),
    ("Sales Engineer", "excluded role: sales"),
    ("Technical Support Engineer", "excluded role: technical support"),
    ("Marketing Intern", "excluded role: internship (title has 'Intern')"),
    ("Civil Site Engineer", "excluded role: site engineer"),
    ("Manual QA Tester", "excluded role: manual qa"),
    ("Test Engineer", "excluded role: test engineer"),
    ("BPO Voice Process", "excluded role: bpo"),
])
def test_role_exclusions(title, reason):
    assert verdict(title).reasons[0] == reason


def test_role_types_are_whole_words_and_title_only():
    assert not verdict("Salesforce Integration Engineer").excluded  # "sales" ≠ "salesforce" (a soft penalty)
    assert not verdict("QA Automation Engineer").excluded  # only *manual* QA is excluded
    assert not verdict("Backend Engineer", jd_text="You will work with our sales team and customer support.").excluded


def test_conditions_anywhere_and_stipend_internships():
    assert verdict("Backend Developer", jd_text="A 2-year service bond applies.").reasons == \
        ("excluded condition: service bond",)
    assert verdict("Web Development", details="Unpaid").reasons[0].startswith("excluded role: internship (stipend")
    link = "https://et.internshala.com/CL0/https:%2F%2Finternshala.com%2Finternship%2Fdetail%2Fx/1"
    assert "(Internshala internship)" in verdict("Python Development", link=link).reasons[0]
    assert not verdict("Web Development", details="₹ 3,00,000 - 5,00,000 /year").excluded


def test_non_engineering_is_opt_in():
    p = policy(hard_exclusions={"role_types": ["non-engineering"]})
    assert prefilter(p, title="Relationship Manager - Banking").reasons  # also too senior ("manager")
    assert prefilter(p, title="Specialist - Financial Control").reasons == \
        ("excluded role: non-engineering (no engineering word in the title)",)
    for ok in ("Java Development", "Python Development", "SDE 1", "Data Engineer", "React Native"):
        assert not prefilter(p, title=ok).excluded, ok
    assert not verdict("Specialist - Financial Control").excluded  # not in the template's role types


def test_stack_never_filters():
    for title in ("PHP Developer", "SAP ABAP Consultant", "Salesforce Developer", "Golang Developer", "C# Engineer"):
        assert not verdict(title).excluded, title


# --- experience ---------------------------------------------------------------------------------

@pytest.mark.parametrize("title", [
    "Sr. Backend Developer", "Tech Lead - Payments", "Engineering Manager", "Solutions Architect", "Staff Engineer",
    "Principal SDE", "Head of Engineering", "Software Engineer II", "SDE-2, Payments", "SDE3", "Backend Engineer, L5",
    "Full Stack Engineer (3+ years)", "Java Developer 4-6 yrs", "VP Engineering",
])
def test_too_senior(title):
    v = verdict(title)
    assert v.experience.status == TOO_SENIOR and v.reasons[-1].startswith("too senior:"), v


@pytest.mark.parametrize("title", [
    "SDE-I, Rewards", "SDE 1", "Graduate Engineer Trainee", "Software Engineer 2026 Batch",
    "Associate Software Engineer (0-2 years)", "Junior Backend Developer", "Software Engineer I",
])
def test_verified_fresher(title):
    assert verdict(title).experience.status == VERIFIED_FRESHER


@pytest.mark.parametrize("title", ["Platform Engineer, Headless CMS", "Staffing-platform Backend Developer",
                                   "Leadership Development Program Engineer", "Software Engineer"])
def test_signal_words_are_whole_words(title):
    assert verdict(title).experience.status == UNKNOWN  # no "head", "staff", "lead"; and no level at all


def test_years_decide_before_title_words():
    assert verdict("SDE II", jd_text="We need 1-3 years of experience.").experience.status == VERIFIED_FRESHER
    assert verdict("SDE 1", jd_text="Requires 3+ years of Go.").experience.status == TOO_SENIOR
    assert verdict("Backend Engineer", details="salary-1 year(s) 3 weeks ago").experience.min_years == 1


def test_jd_years_need_a_requirement_context():
    jd = ("Founded 25 years ago, we serve 500 clients. You have 2+ years of experience with Java. "
          "4+ years of Kafka is a plus. Graduate degree in CS.")
    e = classify(POLICY, title="Backend Engineer", jd_text=jd)
    assert (e.status, e.min_years) == (STRETCH, 2)  # not 25 (company), not 4 (a plus), no "graduate" fresher signal


def test_fresher_sources_and_your_quick_check():
    assert classify(POLICY, title="Backend Developer", sources=("Naukri Campus",)).status == VERIFIED_FRESHER
    assert classify(POLICY, title="Backend Developer", check="fresher").evidence == "you checked it: fresher OK"
    assert classify(POLICY, title="SDE 1", check="senior").status == TOO_SENIOR  # your check wins


def test_unknown_passes_but_needs_a_check():
    v = verdict("Software Engineer")
    assert not v.excluded and v.needs_check
    assert not verdict("Senior Software Engineer").needs_check  # filtered, not "check"


def test_thresholds_follow_the_policy():
    strict = policy(experience={"pass_max_min_years": 1, "stretch_min_years": 1})
    assert prefilter(strict, title="Software Engineer (2-4 yrs)").experience.status == TOO_SENIOR


# --- location -----------------------------------------------------------------------------------

@pytest.mark.parametrize("location", ["Gurugram", "Gurgaon, Haryana", "Noida", "Greater Noida", "New Delhi",
                                      "Delhi, India", "Delhi NCR", "Bangalore", "Ghaziabad", "Faridabad",
                                      "Noida, 201301", "201301", "Karnataka, India", "Remote", "Work from home",
                                      "India", "Multiple locations"])
def test_allowed_locations(location):
    assert location_ok(location, ["Bengaluru", "Delhi NCR"], True), location


@pytest.mark.parametrize("location", ["Pune", "Hyderabad", "Chennai", "Mumbai", "Hybrid - Pune", "Morena",
                                      "Ncrypted Labs, Pune", "Maharashtra", "411001"])
def test_other_locations_are_filtered(location):
    assert not location_ok(location, ["Bengaluru", "Delhi NCR"], True), location


def test_remote_needs_remote_ok_and_empty_list_means_no_filter():
    assert not location_ok("Remote", ["Bengaluru"], False)
    assert verdict("Backend Developer", location="Pune").reasons == ("location (Pune)",)
    assert not prefilter(policy(), title="Backend Developer", location="Pune").excluded  # template: allowed = []


def test_multiple_reasons_all_reported():
    r = verdict("Senior Sales Manager", location="Chennai")
    assert r.reasons == ("excluded role: sales", "too senior: title has 'senior'", "location (Chennai)")
