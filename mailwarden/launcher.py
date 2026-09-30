"""macOS launcher app: a Dock/Spotlight icon that opens the dashboard.

Builds ~/Applications/mailwarden.app with `osacompile`. The app runs one fixed
command, `python -m mailwarden open`, which opens the dashboard in your browser
with a fresh one-time sign-in link (so it works even after the cookie expires).
"""

from __future__ import annotations

import os
import subprocess  # nosec B404: fixed argv, no shell
import sys
from pathlib import Path

APP_NAME = "mailwarden.app"


def _applescript_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def applescript(python: str, home: Path) -> str:
    """The launcher's script. Paths go through `quoted form of`, never raw into the shell."""
    return (
        f"set py to {_applescript_string(python)}\n"
        f"set mwhome to {_applescript_string(str(home))}\n"
        'do shell script "MAILWARDEN_HOME=" & quoted form of mwhome & " " & quoted form of py & '
        '" -m mailwarden --quiet open"\n'
    )


def build(target_dir: Path, python: str, home: Path, *, run=subprocess.run) -> Path:
    if sys.platform != "darwin":
        raise RuntimeError("the launcher app is macOS only; bookmark http://127.0.0.1:8765 instead")
    target_dir.mkdir(parents=True, exist_ok=True)
    app = target_dir / APP_NAME
    run(["/usr/bin/osacompile", "-o", str(app), "-e", applescript(python, home)],
        check=True, capture_output=True, timeout=60)
    return app


def default_dir() -> Path:
    return Path(os.path.expanduser("~/Applications"))
