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
