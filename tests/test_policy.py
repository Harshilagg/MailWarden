"""matching.yaml: strict parsing, helpful warnings, private file handling."""

import os

import pytest
import yaml

from mailwarden import matching
from mailwarden.core.policy import PolicyError, parse
from mailwarden.security.fs import InsecurePermissions

PROJECTS = ["agent_witness", "MailWarden", "Observable Job Queue", "PaymentLedger", "Trade Doc Processor"]


def _template():
    return yaml.safe_load(matching.template_text())


def _policy(**overrides):
    data = _template()
    for fam in data["stack_families"].values():
        fam["evidence_project"] = None
    data.update(overrides)
    return data


def test_template_parses_and_normalises():
    p = parse(_template())
    assert "sr" in p.experience.senior_signals and "sr " not in p.experience.senior_signals  # trimmed
    assert p.experience.unknown_policy == "needs_check" and p.soft_penalties.rank_penalty == 1.0
    assert "general_swe" in p.stack_families and len(p.scoring_rubric) == 6
    assert p.check([]) == []  # empty evidence projects are fine in the template


@pytest.mark.parametrize("bad, message", [
    ({"experience": {"pass_max_min_yrs": 1}}, "experience.pass_max_min_yrs"),  # typo: unknown key
    ({"experience": {"pass_max_min_years": 3, "stretch_min_years": 2}}, "stretch_min_years must be >="),
    ({"experience": {"unknown_policy": "maybe"}}, "unknown_policy"),
    ({"stack_families": {"Java Backend": {"keywords": ["java"]}}}, "lower_snake_case"),
    ({"stack_families": {"java": {"keywords": []}}}, "stack_families.java.keywords"),
    ({"scoring_rubric": ["x" * 301]}, "at most 300 characters"),
    ({"scoring_rubric": []}, "scoring_rubric"),
])
def test_invalid_policies_are_rejected_with_the_field(bad, message):
    with pytest.raises(PolicyError, match="matching.yaml is invalid") as e:
        parse(_policy(**bad))
    assert message in str(e.value)


def test_not_a_mapping():
    with pytest.raises(PolicyError, match="must be a mapping"):
        parse(["experience"])


def test_check_warns_about_likely_mistakes():
    data = _policy()
    data["stack_families"]["java_backend"]["evidence_project"] = "PaymentLedgr"  # typo
    data["stack_families"]["python_ai"]["keywords"].append("kafka")  # also in java_backend
    data["soft_penalties"]["stacks"].append("react")  # also a js_fullstack keyword
    data["hard_exclusions"]["role_types"].append("devops")  # always filters go_infra jobs
    data["experience"]["fresher_signals"].append("lead")
    del data["stack_families"]["general_swe"]
    warnings = "\n".join(parse(data).check(PROJECTS))
    assert "evidence_project 'PaymentLedgr' is not a project in profile.yaml" in warnings
    assert "'kafka' is in both java_backend and python_ai" in warnings
    assert "soft-penalty stack 'react' is also a keyword of js_fullstack" in warnings
    assert "hard-exclusion role type 'devops' is also a keyword of go_infra" in warnings
    assert "in both fresher_signals and senior_signals: lead" in warnings
    assert "no 'general_swe' family" in warnings


def test_fingerprint_tracks_any_change():
    a = parse(_policy())
    b = parse(_policy(scoring_rubric=["Score fit 0-10."]))
    assert a.fingerprint() == parse(_policy()).fingerprint() != b.fingerprint()


# --- the file -------------------------------------------------------------------------------

def test_init_creates_a_private_file_and_never_overwrites(tmp_path):
    home = tmp_path / "home"
    assert matching.load(home) is None
    path, created = matching.init(home)
    assert created and path == home / "config" / "matching.yaml"
    assert oct(path.stat().st_mode & 0o777) == "0o600" and oct(path.parent.stat().st_mode & 0o777) == "0o700"
    assert matching.load(home) is not None
    path.write_text(path.read_text() + "\n# my edit\n")
    assert matching.init(home) == (path, False) and "# my edit" in path.read_text()


def test_load_refuses_shared_or_broken_files(tmp_path):
    path, _ = matching.init(tmp_path)
    os.chmod(path, 0o644)
    with pytest.raises(InsecurePermissions):
        matching.load(tmp_path)
    os.chmod(path, 0o600)
    path.write_text("experience: [unclosed")
    with pytest.raises(PolicyError, match="not valid YAML"):
        matching.load(tmp_path)
    path.write_text("#" * (matching.MAX_BYTES + 1))
    with pytest.raises(PolicyError, match="larger than 64 KB"):
        matching.load(tmp_path)
