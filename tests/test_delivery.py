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


def test_launcher_bundle(tmp_path, monkeypatch):
    import plistlib as _plistlib
    import shlex as _shlex

    from mailwarden import launcher

    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    monkeypatch.setattr(launcher, "framework_interpreter", lambda py: None)  # non-framework Python
    home = tmp_path / "Application Support" / "mw"
    app = launcher.build(tmp_path, "/Users/x/My Apps/python", home, run=lambda *a, **k: None)
    info = _plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    assert info["CFBundleURLTypes"] == [{"CFBundleURLName": "com.mailwarden.app", "CFBundleURLSchemes": ["mailwarden"]}]
    assert info["CFBundleExecutable"] == "mailwarden" and info["CFBundleIconFile"] == "mailwarden"
    assert info["CFBundleIdentifier"] == "com.mailwarden.app"
    exe = app / "Contents" / "MacOS" / "mailwarden"
    assert exe.stat().st_mode & 0o111
    lines = exe.read_text().splitlines()
    assert lines[0] == "#!/bin/sh"
    assert _shlex.split(lines[1]) == ["export", f"MAILWARDEN_HOME={home}"]
    assert _shlex.split(lines[2]) == ["exec", "/Users/x/My Apps/python", "-m", "mailwarden", "--quiet", "app"]
    assert (app / "Contents" / "Resources" / "mailwarden.icns").read_bytes()[:4] == b"icns"


def test_launcher_bundles_its_own_signed_interpreter(tmp_path, monkeypatch):
    import shlex as _shlex

    from mailwarden import launcher

    fake = tmp_path / "Python"
    fake.write_bytes(b"\xcf\xfa\xed\xfe fake mach-o")
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    monkeypatch.setattr(launcher, "framework_interpreter", lambda py: fake)
    calls = []
    app = launcher.build(tmp_path / "out", "/Users/x/proj/.venv/bin/python", tmp_path, run=lambda argv, **k: calls.append(argv))
    copy = app / "Contents" / "MacOS" / "mailwarden-python"
    assert copy.read_bytes() == fake.read_bytes() and copy.stat().st_mode & 0o111
    assert ["/usr/bin/codesign", "--force", "--sign", "-", str(copy)] in calls
    lines = (app / "Contents" / "MacOS" / "mailwarden").read_text().splitlines()
    assert _shlex.split(lines[2]) == ["export", "__PYVENV_LAUNCHER__=/Users/x/proj/.venv/bin/python"]
    assert lines[3] == 'exec "$(dirname "$0")/mailwarden-python" -m mailwarden --quiet app'


def test_launcher_browser_mode_and_rebuild(tmp_path, monkeypatch):
    from mailwarden import launcher

    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    launcher.build(tmp_path, "/py", tmp_path, run=lambda *a, **k: None)
    app = launcher.build(tmp_path, "/py", tmp_path, browser=True, run=lambda *a, **k: None)  # replaces cleanly
    assert "--quiet open" in (app / "Contents" / "MacOS" / "mailwarden").read_text()


def test_launcher_refuses_other_platforms(tmp_path, monkeypatch):
    from mailwarden import launcher

    monkeypatch.setattr(launcher.sys, "platform", "linux")
    with pytest.raises(RuntimeError):
        launcher.build(tmp_path, "/py", tmp_path)



# --- deep links and single instance --------------------------------------------------------

@pytest.mark.parametrize(
    "url, path",
    [
        ("mailwarden://i/personal/18f0a", "/i/personal/18f0a"),
        ("mailwarden://jobs?match=1", "/jobs?match=1"),
        ("MAILWARDEN://applications", "/applications"),
        ("mailwarden:///evil.example.com", None),  # would become //evil...
        ("mailwarden://i/../../etc", None),
        ("mailwarden://x?next=https://evil", None),
        ("https://evil.example.com", None),
        ("mailwarden://" + "a" * 300, None),
    ],
)
def test_path_from_app_link(url, path):
    from mailwarden.core.links import path_from_app_link

    assert path_from_app_link(url) == path


def test_app_link_roundtrip():
    from mailwarden.core.links import app_link, path_from_app_link

    assert path_from_app_link(app_link("/i/personal/18f0a")) == "/i/personal/18f0a"


def test_single_instance_handoff():
    import os
    import stat
    import tempfile
    import time
    from pathlib import Path

    from mailwarden.security.net import send_to_running_app, serve_app_socket

    sock = Path(tempfile.mkdtemp(dir="/tmp")) / "app.sock"  # AF_UNIX paths must be short on macOS
    assert send_to_running_app(sock, "/jobs") is False  # nothing running yet
    got = []
    serve_app_socket(sock, got.append)
    assert stat.S_IMODE(os.stat(sock).st_mode) == 0o600
    assert send_to_running_app(sock, "/i/personal/abc") is True
    for _ in range(50):
        if got:
            break
        time.sleep(0.02)
    assert got == ["/i/personal/abc"]


def test_notifier_uses_app_links_when_app_installed():
    rec = Recorder()
    n = DesktopNotifier(backend="terminal-notifier", dashboard_base_url="http://127.0.0.1:8765",
                        which=lambda name: "/usr/local/bin/terminal-notifier", run=rec, click_target="app")
    n.notify(ALERT)
    argv = rec.calls[0]
    assert argv[argv.index("-open") + 1] == "mailwarden://i/personal/18f0a"
    n.notify_text("3 new jobs match your filters", "/jobs?match=1")
    argv = rec.calls[1]
    assert argv[argv.index("-open") + 1] == "mailwarden://jobs?match=1"


def test_notifier_browser_links_by_default():
    n, rec = notifier()
    n.notify(ALERT)
    assert rec.calls[0][rec.calls[0].index("-open") + 1].startswith("http://127.0.0.1:8765/i/")


def test_app_backend_preferred_and_posts_only_path_and_text():
    rec = Recorder()
    n = DesktopNotifier(backend="auto", dashboard_base_url="http://127.0.0.1:8765", platform="darwin",
                        which=lambda name: None, run=rec, click_target="app",
                        app_helper="/Users/x/Applications/mailwarden.app/Contents/MacOS/mailwarden-notify")
    assert n.backend == "app"
    n.notify(ALERT)
    argv = rec.calls[0]
    assert argv[0].endswith("mailwarden-notify")
    assert argv[argv.index("--path") + 1] == "/i/personal/18f0a"
    assert argv[argv.index("--text") + 1].startswith("Acme · interview")
    n.notify_text("3 new jobs match your filters", "https://evil.example")  # unsafe path -> "/"
    assert rec.calls[1][rec.calls[1].index("--path") + 1] == "/"


def test_launcher_writes_notify_helper(tmp_path, monkeypatch):
    import shlex as _shlex

    from mailwarden import launcher

    fake = tmp_path / "Python"
    fake.write_bytes(b"fake")
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    monkeypatch.setattr(launcher, "framework_interpreter", lambda py: fake)
    out = tmp_path / "Apps"
    launcher.build(out, "/v/.venv/bin/python", tmp_path / "home", run=lambda *a, **k: None)
    helper = launcher.notify_helper(out)
    assert helper is not None
    lines = helper.read_text().splitlines()
    assert _shlex.split(lines[2]) == ["export", "__PYVENV_LAUNCHER__=/v/.venv/bin/python"]
    assert lines[3] == 'exec "$(dirname "$0")/mailwarden-python" -m mailwarden --quiet notify-post "$@"'


def test_notify_post_needs_no_keychain(monkeypatch):
    """The helper runs as the app; it must not touch secrets (no Keychain prompts)."""
    import mailwarden.cli as cli

    posted = []
    monkeypatch.setattr("mailwarden.delivery.app_notify.post",
                        lambda text, path, group=None: posted.append((text, path)) or True)
    monkeypatch.setattr(cli, "build_app", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no app/keyring")))
    assert cli.main(["notify-post", "--text", "Acme · interview", "--path", "/i/p/m1"]) == 0
    assert posted == [("Acme · interview", "/i/p/m1")]
