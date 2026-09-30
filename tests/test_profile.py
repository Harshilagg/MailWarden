"""profile build: local parsing of a (synthetic) CV and project files."""

import datetime as dt
import os

import pytest
import yaml

from mailwarden import profile as prof

TODAY = dt.date(2026, 9, 30)

CV_LINES = [
    "Aarav Mehta",
    "aarav.mehta@example.com | +91 98765 43210 | linkedin.com/in/aarav | github: aaravm",
    "EDUCATION",
    "Indian Institute of Technology, B.Tech Computer Science, 2022 - 2026",
    "EXPERIENCE",
    "Software Engineering Intern, Acme Corp  May 2025 - Jul 2025",
    "Built REST APIs with FastAPI and PostgreSQL; containerised services with Docker.",
    "Backend Intern, Globex  Dec 2024 - Jan 2025",
    "Node.js services with Redis caching; wrote Python tooling.",
    "PROJECTS",
    "Chess engine in Rust with alpha-beta search",
    "TECHNICAL SKILLS",
    "Languages: Python, Java, C++, JavaScript",
    "Frameworks: React, FastAPI, Django",
    "Tools: Git, Docker, AWS, Kubernetes",
]

PROJECTS = {
    "mailwarden.md": "# Mailwarden\n\nPrivacy-first email triage in Python with FastAPI and SQLite. "
                     "Mail aarav.mehta@example.com or see https://github.com/aaravm/mailwarden.\n",
    "chat.md": "# Realtime chat\n\n- Built by Aarav Mehta: a WebSocket chat using Node.js, React and Redis.\n",
}


def _pdf(lines: list[str]) -> bytes:
    """A minimal valid single-page PDF with one text line per entry."""
    esc = [l.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") for l in lines]
    content = "BT /F1 10 Tf 40 800 Td 12 TL " + " ".join(f"({l}) Tj T*" for l in esc) + " ET"
    objs = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
        "/Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(content)} >>\nstream\n{content}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = b"%PDF-1.4\n", []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{body}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return out


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "mw"
    base = prof.init_dirs(home)
    (base / "cv.pdf").write_bytes(_pdf(CV_LINES))
    os.chmod(base / "cv.pdf", 0o600)
    for name, text in PROJECTS.items():
        (base / "projects" / name).write_text(text)
        os.chmod(base / "projects" / name, 0o600)
    return home


def test_pdf_text_is_read_locally(home):
    text = prof.read_pdf_text(home / "profile" / "cv.pdf")
    assert "TECHNICAL SKILLS" in text and "FastAPI" in text


def test_build_profile(home):
    p = prof.build_profile(home, locations=["Bengaluru", "Remote"], today=TODAY)
    skills = p["skills"]
    assert list(skills)[0] in ("python", "fastapi") and max(skills.values()) == 1.0
    for s in ("python", "fastapi", "postgresql", "docker", "node.js", "redis", "react", "sqlite", "aws"):
        assert s in skills, s
    assert "rust" not in skills  # CV Projects section is ignored: only project files count
    assert skills["fastapi"] > skills["aws"]  # experience + project evidence outranks a skills-list mention
    assert p["experience_years"] == 0.5  # May-Jul 2025 + Dec 2024-Jan 2025 = 5 months
    assert p["seniority"] == "new_grad"
    assert p["locations"] == ["Bengaluru", "Remote"] and p["remote_ok"] is True
    assert "sde" in p["target_roles"] and "sales" in p["avoid_roles"]
    names = [x["name"] for x in p["projects"]]
    assert names == ["Realtime chat", "Mailwarden"]
    mw = p["projects"][1]
    assert mw["skills"][:2] == ["python", "fastapi"] or set(mw["skills"]) >= {"python", "fastapi", "sqlite"}


def test_no_contact_details_anywhere(home):
    text = prof.dump(prof.build_profile(home, locations=["Remote"], today=TODAY))
    for leak in ("aarav", "Aarav", "Mehta", "example.com", "98765", "github", "linkedin", "http"):
        assert leak not in text.split("\n", prof.HEADER.count("\n"))[-1], leak
    assert prof.contact_leaks(text, "Aarav Mehta") == []


def test_contact_leaks_detected():
    assert "an email address" in prof.contact_leaks(prof.HEADER + "x: a@b.com\n", None)
    assert "a phone number" in prof.contact_leaks(prof.HEADER + "x: +91 98765 43210\n", None)
    assert "your name" in prof.contact_leaks(prof.HEADER + "one_line: made by Aarav\n", "Aarav Mehta")


def test_preferences_survive_rebuild(home):
    first = prof.build_profile(home, locations=["Remote"], today=TODAY)
    first["target_roles"] = ["backend"]
    first["avoid_roles"] = ["sales", "frontend-only"]
    first["remote_ok"] = False
    first["skills"] = {"cobol": 1.0}  # derived: will be refreshed
    prof.write(home, prof.dump(first))
    again = prof.build_profile(home, locations=["Mumbai"], today=TODAY, existing=prof.load_existing(home))
    assert again["target_roles"] == ["backend"] and again["remote_ok"] is False
    assert again["locations"] == ["Remote"]  # a preference: kept
    assert "cobol" not in again["skills"] and "python" in again["skills"]


def test_write_is_private_with_backup_and_diff(home):
    p1 = prof.dump(prof.build_profile(home, locations=["Remote"], today=TODAY))
    path = prof.write(home, p1)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    p2 = p1.replace("remote_ok: true", "remote_ok: false")
    prof.write(home, p2)
    assert (home / "profile.yaml.bak").read_text() == p1
    d = prof.diff(p1, p2)
    assert "-remote_ok: true" in d and "+remote_ok: false" in d


def test_loose_permissions_refused(home):
    os.chmod(home / "profile" / "cv.pdf", 0o644)
    with pytest.raises(Exception, match="chmod 600"):
        prof.build_profile(home, locations=[], today=TODAY)


def test_missing_cv(tmp_path):
    home = tmp_path / "mw"
    prof.init_dirs(home)
    with pytest.raises(prof.ProfileError, match="no CV"):
        prof.build_profile(home, locations=[], today=TODAY)


@pytest.mark.parametrize(
    "text, years",
    [
        ("Intern  Jun 2024 - Aug 2024", 0.0),            # 3 months -> 0.25 -> rounds to 0.0 (half-year steps)
        ("SWE  Jan 2023 - Dec 2024", 2.0),
        ("A  May 2025 - Present", 1.5),                   # May 2025 .. Sep 2026 = 17 months
        ("A  Jan 2024 - Jun 2024\nB  Mar 2024 - Aug 2024", 0.5),  # overlap counted once (8 months)
        ("A  06/2023 - 05/2024", 1.0),
        ("no dates here", 0.0),
    ],
)
def test_experience_years(text, years):
    assert prof.experience_years(text, TODAY) == years


def test_cli_build_dry_run_then_write(home, monkeypatch, capsys):
    from mailwarden.cli import main

    monkeypatch.setenv("MAILWARDEN_HOME", str(home))
    main(["init"])
    assert main(["profile", "build", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "+++ profile.yaml (new)" in out and "(dry run: nothing written)" in out
    assert not (home / "profile.yaml").exists()
    assert main(["profile", "build"]) == 0
    assert (home / "profile.yaml").exists()
    assert yaml.safe_load((home / "profile.yaml").read_text())["seniority"] == "new_grad"
    assert main(["profile", "build"]) == 0
    assert "already up to date" in capsys.readouterr().out



@pytest.mark.parametrize(
    "md, expected",
    [
        ("# X\nRepo: https://github.com/a/x\nStack: Go, gRPC\n\nA durable job queue with retries and tracing.\n",
         "A durable job queue with retries and tracing."),
        ("# X\n**Repo:** https://github.com/a/x\n- **Summary:** Ledger service for payments, built with Spring Boot.\n",
         "Ledger service for payments, built with Spring Boot."),
        ("# X\n```\ncode block line that is long enough\n```\nReal description of the project here. Second one.\n",
         "Real description of the project here."),
        ("# X\nRepo: https://github.com/a/x\n", ""),
    ],
)
def test_project_one_line_skips_metadata(md, expected):
    assert prof.parse_project(md, "x.md", None).one_line == expected


# --- hand-written sections, overrides, role matching, one-liners --------------------------

HAND = {
    "skill_overrides": {"go": 0.95, "react": 0.4, "saga pattern": 0.7},
    "extra_project_skills": {"mailwarden": ["regex", "security"], "Realtime chat": ["websockets"]},
    "education": "B.Tech, Computer Science, Indian Institute of Technology (2022-2026)",
    "experience_summary": "Two backend internships building REST services.",
    "highlights": ["Built a privacy-first email triage tool used daily"],
}


def test_hand_sections_survive_rebuild_and_merge(home):
    first = prof.build_profile(home, locations=["Remote"], today=TODAY)
    prof.write(home, prof.dump({**first, **HAND}))
    again = prof.build_profile(home, locations=["Remote"], today=TODAY, existing=prof.load_existing(home))
    for key, value in HAND.items():
        assert again[key] == value, key
    mw = next(p for p in again["projects"] if p["name"] == "Mailwarden")
    assert "regex" in mw["skills"] and "security" in mw["skills"] and "python" in mw["skills"]
    chat = next(p for p in again["projects"] if p["name"] == "Realtime chat")
    assert chat["skills"].count("websockets") == 1  # already detected: not duplicated
    assert list(again)[:3] == ["skills", "skill_overrides", "experience_years"]


def test_effective_skills_overrides_replace_and_add():
    eff = prof.effective_skills({"skills": {"react": 1.0, "go": 0.44, "python": 0.44},
                                 "skill_overrides": {"React": 0.4, "go": 0.95, "saga pattern": 0.7}})
    assert eff == {"go": 0.95, "saga pattern": 0.7, "python": 0.44, "react": 0.4}
    assert prof.effective_skills({"skills": {"a": 1}}) == {"a": 1.0}


@pytest.mark.parametrize(
    "bad, match",
    [
        ({"skill_overrides": {"go": "high"}}, "skill_overrides"),
        ({"skill_overrides": ["go"]}, "skill_overrides"),
        ({"extra_project_skills": {"x": "go"}}, "extra_project_skills"),
        ({"highlights": "one string"}, "highlights"),
    ],
)
def test_invalid_hand_sections_rejected(home, bad, match):
    base = prof.build_profile(home, locations=["Remote"], today=TODAY)
    prof.write(home, prof.dump({**base, **bad}))
    with pytest.raises(prof.ProfileError, match=match):
        prof.build_profile(home, locations=["Remote"], today=TODAY, existing=prof.load_existing(home))


def test_unmatched_extra_projects_reported():
    p = {"projects": [{"name": "Mailwarden"}], "extra_project_skills": {"mailwarden": [], "Ghost": []}}
    assert prof.unmatched_extra_projects(p) == ["Ghost"]


def test_contact_details_in_hand_sections_block_the_write():
    text = prof.dump({"skills": {}, "education": "B.Tech, contact aarav@example.com"})
    assert "an email address" in prof.contact_leaks(text, None)


@pytest.mark.parametrize(
    "title, entries, expected",
    [
        ("SDE-I, Rewards", ["sde / sde-1 / sde i"], "sde / sde-1 / sde i"),
        ("SDE 1 - Backend", ["sde / sde-1 / sde i"], "sde / sde-1 / sde i"),
        ("Sr. SDE II", ["sde ii / sde-2"], "sde ii / sde-2"),
        ("Software Engineer (Backend)", ["backend / platform", "software engineer"], "backend / platform"),
        ("Full-Stack Developer", ["full stack / fullstack / full-stack"], "full stack / fullstack / full-stack"),
        ("Sales Engineer", ["SALES / business development"], "SALES / business development"),
        ("Principal Designer", ["sde / sde-1"], None),
        ("Backendish Wizard", ["backend"], None),  # whole words only
        ("C++ Developer", ["c++ / c#"], "c++ / c#"),
    ],
)
def test_match_role(title, entries, expected):
    assert prof.match_role(title, entries) == expected


@pytest.mark.parametrize(
    "md, expected",
    [
        ("# X\nRepo: https://github.com/a/x\n**One line:** Durable job queue in Go, built end to end: storage, "
         "a gRPC API, retries with backoff and dead letters, an analytics dashboard, plus chaos tests and load "
         "testing across three nodes. Second sentence here.\nStack: Go\n",
         "Durable job queue in Go, built end to end: storage, a gRPC API, retries with backoff and dead letters, "
         "an analytics dashboard, plus chaos tests and load testing across three nodes."),
        ("# X\nSome earlier paragraph that is long enough to count.\n- One line: Ledger with Node.js and v1.2 "
         "APIs, e.g. transfers.\n", "Ledger with Node.js and v1.2 APIs, e.g. transfers."),
        ("# X\nRepo: https://github.com/a/x\nFirst real paragraph sentence goes here. Then more.\n",
         "First real paragraph sentence goes here."),
    ],
)
def test_one_line_is_full_first_sentence(md, expected):
    assert prof.parse_project(md, "x.md", None).one_line == expected


HAND_TEXT = """# My own header comment.
# refreshed; skill_overrides and everything below experience_years keep your edits.

# Hand-set weights. These win.
skill_overrides: {go: 0.95, react: 0.4}

experience_years: 3.0

education: B.Tech, Indian Institute of Technology (2026)
experience_summary: >
  Two backend internships
  building REST services.
# Skills the parser misses.
extra_project_skills:
  Mailwarden: [regex, security]
target_roles:
  - sde / sde-1 / sde i   # alternatives
remote_ok: true
"""


def test_render_keeps_hand_formatting_and_replaces_generated_blocks(home):
    old = yaml.safe_load(HAND_TEXT)
    new = prof.build_profile(home, locations=["Remote"], today=TODAY, existing=old)
    text = prof.render(HAND_TEXT, new)
    for line in HAND_TEXT.splitlines():
        if not line.startswith("experience_years"):
            assert line in text.splitlines(), line  # every hand-written line kept verbatim
    parsed = yaml.safe_load(text)
    assert parsed["experience_years"] == 0.5  # generated: refreshed
    assert "python" in parsed["skills"] and parsed["skill_overrides"] == {"go": 0.95, "react": 0.4}
    assert text.index("skills:") < text.index("skill_overrides:")  # inserted before the first key
    mw = next(p for p in parsed["projects"] if p["name"] == "Mailwarden")
    assert {"regex", "security", "python"} <= set(mw["skills"])
    d = prof.diff(HAND_TEXT, text)
    assert "-# Hand-set weights" not in d and "-experience_summary" not in d and "-extra_project_skills" not in d


def test_render_replaces_existing_generated_blocks_in_place(home):
    new = prof.build_profile(home, locations=["Remote"], today=TODAY)
    text1 = prof.render(None, new)
    edited = text1.replace("remote_ok: true", "remote_ok: true  # keep this comment")
    text2 = prof.render(edited, new)
    assert text2 == edited  # nothing generated changed -> identical file
    assert prof.diff(edited, text2) == ""


def test_contact_leaks_ignore_comments_but_check_data():
    text = "# made by Aarav, see https://example.com\nskills: {python: 1.0}\n"
    assert prof.contact_leaks(text, "Aarav Mehta") == []
    assert "your name" in prof.contact_leaks("highlights: [Aarav built it]\n", "Aarav Mehta")
