"""Generate scheduler definitions: launchd (macOS), systemd user units (Linux), Task Scheduler (Windows).

Files are written to <home>/schedule/ for review; installing them is a manual step
(the printed commands). Every job runs `python -m mailwarden --quiet <command>`.
launchd uses StartCalendarInterval (not cron): runs missed while asleep are run once on wake.
systemd timers use Persistent=true for the same reason; Windows uses StartWhenAvailable.
"""

from __future__ import annotations

import plistlib
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

LABEL = "com.mailwarden"


@dataclass(frozen=True)
class GeneratedFile:
    name: str
    content: bytes


def _hm(times: list[str]) -> list[tuple[int, int]]:
    return [(int(t[:2]), int(t[3:5])) for t in times]


def _argv(python: str, command: str) -> list[str]:
    return [python, "-m", "mailwarden", "--quiet", command]


# --- macOS ---------------------------------------------------------------------------

def launchd(home: Path, python: str, digest_times: list[str], interval_minutes: int = 10) -> list[GeneratedFile]:
    logs = home / "logs"
    env = {"MAILWARDEN_HOME": str(home)}

    def plist(name: str, command: str, **extra) -> GeneratedFile:
        data = {
            "Label": f"{LABEL}.{name}",
            "ProgramArguments": _argv(python, command),
            "EnvironmentVariables": env,
            "WorkingDirectory": str(home),
            "StandardOutPath": str(logs / f"{name}.log"),
            "StandardErrorPath": str(logs / f"{name}.log"),
            "Umask": 0o077,  # logs and any files created are private
            "ProcessType": "Background",
            **extra,
        }
        return GeneratedFile(f"{LABEL}.{name}.plist", plistlib.dumps(data))

    minutes = [{"Minute": m} for m in range(0, 60, interval_minutes)]
    return [
        plist("run", "run", StartCalendarInterval=minutes),
        plist("digest", "digest", StartCalendarInterval=[{"Hour": h, "Minute": m} for h, m in _hm(digest_times)]),
        plist("dashboard", "dashboard", RunAtLoad=True, KeepAlive={"SuccessfulExit": False}, ProcessType="Interactive"),
    ]


def launchd_instructions(out: Path) -> str:
    # Paths are shell-quoted ("Application Support" has a space); no comment lines,
    # because zsh does not treat pasted "# ..." lines as comments.
    names = ("run", "digest", "dashboard")
    install = [
        "mkdir -p ~/Library/LaunchAgents",
        *[f"cp {shlex.quote(str(out / f'{LABEL}.{n}.plist'))} ~/Library/LaunchAgents/" for n in names],
        *[f"launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/{LABEL}.{n}.plist" for n in names],
    ]
    remove = [f"launchctl bootout gui/$(id -u)/{LABEL}.{n}" for n in names]
    return "\n".join(install) + "\n\nTo remove them later:\n\n" + "\n".join(remove)


# --- Linux ---------------------------------------------------------------------------

def systemd(home: Path, python: str, digest_times: list[str], interval_minutes: int = 10) -> list[GeneratedFile]:
    def cmd(command: str) -> str:
        return " ".join(f'"{a}"' if " " in a else a for a in _argv(python, command))

    common = f"Environment=MAILWARDEN_HOME={home}\nWorkingDirectory={home}\nUMask=0077\nNoNewPrivileges=yes\n"

    def service(name: str, command: str, kind: str = "oneshot", extra: str = "") -> GeneratedFile:
        body = (f"[Unit]\nDescription=mailwarden {name}\n\n[Service]\nType={kind}\nExecStart={cmd(command)}\n"
                f"{common}{extra}")
        return GeneratedFile(f"mailwarden-{name}.service", body.encode())

    def timer(name: str, calendars: list[str]) -> GeneratedFile:
        lines = "".join(f"OnCalendar={c}\n" for c in calendars)
        body = f"[Unit]\nDescription=mailwarden {name} timer\n\n[Timer]\n{lines}Persistent=true\n\n[Install]\nWantedBy=timers.target\n"
        return GeneratedFile(f"mailwarden-{name}.timer", body.encode())

    return [
        service("run", "run"),
        timer("run", [f"*:0/{interval_minutes}"]),
        service("digest", "digest"),
        timer("digest", [f"*-*-* {h:02d}:{m:02d}:00" for h, m in _hm(digest_times)]),
        service("dashboard", "dashboard", kind="simple",
                extra="Restart=on-failure\n\n[Install]\nWantedBy=default.target\n"),
    ]


def systemd_instructions(out: Path) -> str:
    return "\n".join(
        [
            f"mkdir -p ~/.config/systemd/user && cp {shlex.quote(str(out))}/mailwarden-* ~/.config/systemd/user/",
            "systemctl --user daemon-reload",
            "systemctl --user enable --now mailwarden-run.timer mailwarden-digest.timer mailwarden-dashboard.service",
        ]
    )


# --- Windows -------------------------------------------------------------------------

def _task_xml(description: str, triggers: str, python: str, command: str, time_limit: str) -> bytes:
    args = " ".join(_argv(python, command)[1:])
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>{escape(description)}</Description></RegistrationInfo>
  <Triggers>{triggers}</Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>{time_limit}</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{escape(python)}</Command><Arguments>{escape(args)}</Arguments></Exec></Actions>
</Task>
"""
    return xml.encode("utf-16")


def windows(home: Path, python: str, digest_times: list[str], interval_minutes: int = 10) -> list[GeneratedFile]:
    start = "2026-01-01T00:00:00"
    run_trigger = (f"<TimeTrigger><StartBoundary>{start}</StartBoundary><Repetition><Interval>PT{interval_minutes}M</Interval>"
                   "</Repetition><Enabled>true</Enabled></TimeTrigger>")
    digest_triggers = "".join(
        f"<CalendarTrigger><StartBoundary>2026-01-01T{h:02d}:{m:02d}:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval>"
        "</ScheduleByDay><Enabled>true</Enabled></CalendarTrigger>"
        for h, m in _hm(digest_times)
    )
    return [
        GeneratedFile("mailwarden-run.xml", _task_xml("mailwarden sync + classify", run_trigger, python, "run", "PT30M")),
        GeneratedFile("mailwarden-digest.xml", _task_xml("mailwarden digest", digest_triggers, python, "digest", "PT10M")),
        GeneratedFile("mailwarden-dashboard.xml",
                      _task_xml("mailwarden dashboard", "<LogonTrigger><Enabled>true</Enabled></LogonTrigger>", python,
                                "dashboard", "PT0S")),
    ]


def windows_instructions(out: Path) -> str:
    return "\n".join(
        f'schtasks /Create /TN "mailwarden\\{n}" /XML "{out}\\mailwarden-{n}.xml"' for n in ("run", "digest", "dashboard")
    )


GENERATORS = {
    "macos": (launchd, launchd_instructions),
    "linux": (systemd, systemd_instructions),
    "windows": (windows, windows_instructions),
}


def current_platform() -> str:
    return {"darwin": "macos", "win32": "windows"}.get(sys.platform, "linux")
