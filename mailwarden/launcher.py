"""macOS launcher: ~/Applications/mailwarden.app for the Dock and Spotlight.

A minimal app bundle (Info.plist, icon, and a tiny shell executable). The
executable runs one fixed command:

- default: `python -m mailwarden app`: the dashboard in its own native window;
- --browser: `python -m mailwarden open`: the dashboard in your default browser.

Both sign in with a fresh one-time code, so it works even after the cookie expires.
"""

from __future__ import annotations

import os
import plistlib
import shlex
import shutil
import subprocess  # nosec B404: fixed argv, no shell
import sys
from importlib import resources
from pathlib import Path

from mailwarden import __version__

APP_NAME = "mailwarden.app"
BUNDLE_ID = "com.mailwarden.app"
_LSREGISTER = ("/System/Library/Frameworks/CoreServices.framework/Frameworks/"
               "LaunchServices.framework/Support/lsregister")


def executable_script(python: str, home: Path, *, browser: bool = False) -> str:
    """The bundle's executable. Every value is shell-quoted; `exec` keeps the app's PID."""
    command = "open" if browser else "app"
    return (
        "#!/bin/sh\n"
        f"export MAILWARDEN_HOME={shlex.quote(str(home))}\n"
        f"exec {shlex.quote(python)} -m mailwarden --quiet {command}\n"
    )


def info_plist() -> bytes:
    return plistlib.dumps({
        "CFBundleName": "mailwarden",
        "CFBundleDisplayName": "mailwarden",
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleExecutable": "mailwarden",
        "CFBundleIconFile": "mailwarden",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": __version__,
        "CFBundleVersion": __version__,
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
    })


def build(target_dir: Path, python: str, home: Path, *, browser: bool = False, run=subprocess.run) -> Path:
    if sys.platform != "darwin":
        raise RuntimeError("the launcher app is macOS only; bookmark http://127.0.0.1:8765 instead")
    app = target_dir / APP_NAME
    if app.exists():
        shutil.rmtree(app)
    macos, res = app / "Contents" / "MacOS", app / "Contents" / "Resources"
    macos.mkdir(parents=True)
    res.mkdir(parents=True)
    (app / "Contents" / "Info.plist").write_bytes(info_plist())
    exe = macos / "mailwarden"
    exe.write_text(executable_script(python, home, browser=browser))
    exe.chmod(0o755)
    with resources.as_file(resources.files("mailwarden.assets").joinpath("mailwarden.icns")) as icon:
        shutil.copyfile(icon, res / "mailwarden.icns")
    os.utime(app)
    if Path(_LSREGISTER).exists():  # refresh Launch Services so Spotlight/Dock see the icon now
        run([_LSREGISTER, "-f", str(app)], check=False, capture_output=True, timeout=30)
    return app


def default_dir() -> Path:
    return Path(os.path.expanduser("~/Applications"))
