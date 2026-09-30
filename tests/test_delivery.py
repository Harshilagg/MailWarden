import datetime as dt
import os
import plistlib
import xml.dom.minidom

import pytest

from mailwarden.core.models import Category, Classification, EmailMeta, GateDecision, Stage, Tier
from mailwarden.core.overview import Digest, build_digest, digest_markdown, urgent_items
from mailwarden.delivery.base import JobAlert
from mailwarden.delivery.desktop_notify import DesktopNotifier, notification_text

NOW = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.UTC)


# --- notifications -------------------------------------------------------------------

class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append(argv)


def notifier(backend="auto", platform="darwin", installed=True):
    rec = Recorder()
    n = DesktopNotifier(backend=backend, dashboard_base_url="http://127.0.0.1:8765", platform=platform,
                        which=lambda name: "/usr/local/bin/terminal-notifier" if installed else None, run=rec)
    return n, rec


ALERT = JobAlert("local", "personal", "18f0a", "Acme", Stage.INTERVIEW, dt.date(2026, 10, 5))


def test_macos_prefers_terminal_notifier_with_click_url():
    n, rec = notifier()
    n.notify(ALERT)
    argv = rec.calls[0]
    assert n.backend == "terminal-notifier" and argv[0].endswith("terminal-notifier")
    assert argv[argv.index("-open") + 1] == "http://127.0.0.1:8765/i/personal/18f0a"
    assert argv[argv.index("-message") + 1].startswith("Acme · interview · due ")


def test_macos_falls_back_to_osascript_with_argv_not_interpolation():
    n, rec = notifier(installed=False)
    evil = JobAlert("local", "p", "m", 'Acme" & do shell script "rm -rf ~', Stage.OFFER, None)
    n.notify(evil)
    argv = rec.calls[0]
    assert n.backend == "osascript" and argv[0] == "/usr/bin/osascript"
    script = " ".join(argv[1:7])
    assert "rm -rf" not in script  # the company text is only ever an argv item
    assert argv[7].startswith('Acme" & do shell')


def test_other_platforms_use_desktop_notifier():
    assert notifier(platform="linux")[0].backend == "desktop-notifier"
    assert notifier(platform="win32")[0].backend == "desktop-notifier"


def test_notification_text_has_no_summary_and_is_sanitised():
    held = JobAlert("local", "p", "m", "Amex", Stage.ASSESSMENT, None, held=True)
    assert notification_text(held) == "Amex · assessment · needs your attention"
    weird = JobAlert("local", "p", "m", "--Acme\n\x1b[31mRed", None, None)
    text = notification_text(weird)
    assert "\n" not in text and "\x1b" not in text and not text.startswith("-")


def test_notify_failure_never_raises():
    def boom(*a, **k):
        raise OSError("no")

    n = DesktopNotifier(backend="osascript", dashboard_base_url="http://127.0.0.1:8765", run=boom)
    n.notify(ALERT)


# --- urgent + digest -----------------------------------------------------------------

def meta(mid, *, gate=GateDecision.SAFE, category=Category.NEWSLETTER, stage=None, action=False, held=False,
         hours=1, tier=Tier.DEFAULT, deadline=None, dismissed=False, name="Sender"):
    c = None
    if gate is GateDecision.SAFE and category is not None:
        c = Classification(category=category, company="Acme" if category is Category.JOB else None, role=None,
                           stage=stage, action_required=action, deadline=deadline, summary=f"Summary {mid}.")
    return EmailMeta(user_id="local", account="p", message_id=mid,
                     sender_address=None if gate is GateDecision.SENSITIVE else "a@b.com", sender_name=name,
                     received_at=NOW - dt.timedelta(hours=hours), tier=tier, gate=gate, classification=c,
                     held_job=held, held_company="Amex" if held else None, dismissed=dismissed)


def test_urgent_selection_and_order():
    metas = [
        meta("late", category=Category.JOB, stage=Stage.INTERVIEW, deadline=dt.date(2026, 10, 9)),
        meta("soon", category=Category.JOB, stage=Stage.ASSESSMENT, deadline=dt.date(2026, 10, 1)),
        meta("nodl", category=Category.JOB, stage=Stage.OTHER, action=True),
        meta("rej", category=Category.JOB, stage=Stage.REJECTION, action=True),
        meta("held", gate=GateDecision.SENSITIVE, held=True),
        meta("done", category=Category.JOB, stage=Stage.OFFER, dismissed=True),
        meta("news"),
        meta("bank", gate=GateDecision.SENSITIVE),
    ]
    ids = [i.message_id for i in urgent_items(metas)]
    assert ids[:2] == ["soon", "late"] and set(ids) == {"soon", "late", "nodl", "held"}


def test_digest_groups_and_excludes_urgent():
    metas = [
        meta("n1"), meta("n2", category=Category.JOB_ALERT), meta("p1", category=Category.PERSONAL),
        meta("j1", category=Category.JOB, stage=Stage.INTERVIEW),
        meta("s1", gate=GateDecision.SENSITIVE, name="IDFC FIRST Bank"),
        meta("s2", gate=GateDecision.SENSITIVE, name="IDFC FIRST Bank"),
        meta("i1", category=None, tier=Tier.IGNORE),
        meta("old", hours=48),
    ]
    d = build_digest(metas, now=NOW, period_start=NOW - dt.timedelta(days=1))
    assert set(d.sections) == {"newsletter", "job_alert", "personal"}
    assert d.urgent == 1 and d.sensitive_by_sender == {"IDFC FIRST Bank": 2} and d.ignored == 1
    assert Digest.from_json(d.to_json()) == d
    md = digest_markdown(d)
    assert "2 sensitive email(s) (not processed)" in md and "Summary n1." in md and "http" not in md


def test_run_digest_stores_and_writes_private_markdown(tmp_path, secret_store):
    from mailwarden.core.digest_job import run_digest
    from mailwarden.delivery.digest_file import MarkdownDigestSink
    from mailwarden.storage.sqlite_store import SQLCipherRepository

    repo = SQLCipherRepository.open(tmp_path / "d" / "mw.db", secret_store, "local")
    repo.save_email_meta(meta("n1"))
    folder = tmp_path / "digests"
    d = run_digest(repo, "local", now=NOW, sink=MarkdownDigestSink(folder))
    assert d.sections["newsletter"][0].message_id == "n1"
    assert repo.latest_digest("local")[2] == d.to_json()
    files = list(folder.iterdir())
    assert len(files) == 1 and oct(files[0].stat().st_mode & 0o777) == "0o600"
    assert oct(folder.stat().st_mode & 0o777) == "0o700"
    # next digest starts where the last one ended
    d2 = run_digest(repo, "local", now=NOW + dt.timedelta(hours=6))
    assert d2.period_start == NOW.isoformat() and d2.sections == {}
    repo.close()


# --- scheduling ------------------------------------------------------------------------

def test_launchd_plists(tmp_path):
    from mailwarden.schedule import launchd

    files = {f.name: plistlib.loads(f.content) for f in launchd(tmp_path, "/py", ["08:00", "18:30"])}
    run = files["com.mailwarden.run.plist"]
    assert run["ProgramArguments"] == ["/py", "-m", "mailwarden", "--quiet", "run"]
    assert run["StartCalendarInterval"] == [{"Minute": m} for m in range(0, 60, 10)]  # not cron
    assert run["Umask"] == 0o077 and run["EnvironmentVariables"]["MAILWARDEN_HOME"] == str(tmp_path)
    assert files["com.mailwarden.digest.plist"]["StartCalendarInterval"] == [{"Hour": 8, "Minute": 0}, {"Hour": 18, "Minute": 30}]
    assert files["com.mailwarden.dashboard.plist"]["RunAtLoad"] is True


def test_systemd_units(tmp_path):
    from mailwarden.schedule import systemd

    files = {f.name: f.content.decode() for f in systemd(tmp_path, "/py", ["08:00"])}
    assert "OnCalendar=*:0/10" in files["mailwarden-run.timer"] and "Persistent=true" in files["mailwarden-run.timer"]
    assert "OnCalendar=*-*-* 08:00:00" in files["mailwarden-digest.timer"]
    assert "UMask=0077" in files["mailwarden-run.service"] and "ExecStart=/py -m mailwarden --quiet run" in files["mailwarden-run.service"]


def test_windows_tasks_parse(tmp_path):
    from mailwarden.schedule import windows

    for f in windows(tmp_path, r"C:\py\python.exe", ["08:00"]):
        doc = xml.dom.minidom.parseString(f.content.decode("utf-16"))
        assert doc.getElementsByTagName("StartWhenAvailable")[0].firstChild.data == "true"
        assert "mailwarden --quiet" in doc.getElementsByTagName("Arguments")[0].firstChild.data


def test_schedule_command_writes_files(tmp_path, monkeypatch):
    from mailwarden.cli import main

    monkeypatch.setenv("MAILWARDEN_HOME", str(tmp_path / "mw"))
    main(["init"])
    assert main(["schedule", "--platform", "linux"]) == 0
    out = tmp_path / "mw" / "schedule" / "linux"
    assert (out / "mailwarden-run.timer").exists()
    assert oct(out.stat().st_mode & 0o777) == "0o700"


def test_install_commands_quote_paths_and_have_no_comment_lines(tmp_path):
    import shlex as _shlex

    from mailwarden.schedule import launchd_instructions, systemd_instructions

    out = tmp_path / "Application Support" / "mailwarden" / "schedule" / "macos"
    text = launchd_instructions(out)
    for line in text.splitlines():
        assert not line.lstrip().startswith("#")
        if line.startswith("cp "):
            assert len(_shlex.split(line)) == 3  # the spaced path stays one argument
    assert "launchctl bootout gui/$(id -u)/com.mailwarden.dashboard" in text
    assert "'" in systemd_instructions(out)


def test_launcher_script_quotes_paths_and_runs_only_open(tmp_path, monkeypatch):
    from mailwarden import launcher

    script = launcher.applescript('/Users/x/My "Apps"/py', tmp_path / "Application Support" / "mw")
    assert 'quoted form of py' in script and 'quoted form of mwhome' in script
    assert '\\"Apps\\"' in script  # embedded quotes escaped for AppleScript
    assert script.count("do shell script") == 1 and "-m mailwarden --quiet open" in script

    calls = []
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    app = launcher.build(tmp_path, "/py", tmp_path, run=lambda argv, **kw: calls.append(argv))
    assert app == tmp_path / "mailwarden.app"
    assert calls[0][:3] == ["/usr/bin/osacompile", "-o", str(app)]
