"""macOS launcher: ~/Applications/mailwarden.app for the Dock and Spotlight.

A minimal app bundle: Info.plist (which registers the mailwarden:// link type
used by notification clicks), the icon, a tiny shell executable, and a private,
ad-hoc-signed copy of the Python interpreter stub. Running Python from inside the
bundle makes macOS treat the window as the "mailwarden" app (one Dock icon, one
instance), instead of as "Python". The executable runs one fixed command:

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


INTERPRETER = "mailwarden-python"


def framework_interpreter(python: str) -> Path | None:
    """The real interpreter inside a macOS framework build (Python.app/Contents/MacOS/Python)."""
    base = Path(os.path.realpath(getattr(sys, "_base_executable", python) or python))
    # .../Python.framework/Versions/3.x/bin/python3.x -> .../Versions/3.x/Resources/Python.app/...
    candidate = base.parent.parent / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
    return candidate if candidate.is_file() else None


def executable_script(python: str, home: Path, *, browser: bool = False, bundled: bool = False) -> str:
    """The bundle's executable. Every value is shell-quoted; `exec` keeps the app's PID."""
    command = "open" if browser else "app"
    lines = ["#!/bin/sh", f"export MAILWARDEN_HOME={shlex.quote(str(home))}"]
    if bundled:
        # Run the bundle's own interpreter copy against the project's virtualenv.
        lines.append(f"export __PYVENV_LAUNCHER__={shlex.quote(python)}")
        lines.append(f'exec "$(dirname "$0")/{INTERPRETER}" -m mailwarden --quiet {command}')
    else:
        lines.append(f"exec {shlex.quote(python)} -m mailwarden --quiet {command}")
    return "\n".join(lines) + "\n"


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
        "CFBundleURLTypes": [{"CFBundleURLName": BUNDLE_ID, "CFBundleURLSchemes": ["mailwarden"]}],
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
    interpreter = framework_interpreter(python)
    if interpreter is not None:
        copy = macos / INTERPRETER
        shutil.copyfile(interpreter, copy)
        copy.chmod(0o755)
        run(["/usr/bin/codesign", "--force", "--sign", "-", str(copy)], check=False, capture_output=True, timeout=60)
    exe = macos / "mailwarden"
    exe.write_text(executable_script(python, home, browser=browser, bundled=interpreter is not None))
    exe.chmod(0o755)
    with resources.as_file(resources.files("mailwarden.assets").joinpath("mailwarden.icns")) as icon:
        shutil.copyfile(icon, res / "mailwarden.icns")
    os.utime(app)
    if Path(_LSREGISTER).exists():  # refresh Launch Services so Spotlight/Dock see the icon now
        run([_LSREGISTER, "-f", str(app)], check=False, capture_output=True, timeout=30)
    return app


def default_dir() -> Path:
    return Path(os.path.expanduser("~/Applications"))
