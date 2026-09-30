"""Desktop notifications for urgent job mail.

Content is limited to company, stage and deadline (``JobAlert.title``): never
a summary, subject or link text. Clicking opens the matching dashboard entry
(a local 127.0.0.1 URL).

macOS: terminal-notifier (signed; click opens the URL without keeping any
process alive) when installed, else osascript (no click action).
Unsigned Python builds (e.g. Homebrew) cannot use desktop-notifier on macOS.
Linux/Windows: desktop-notifier.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess  # nosec B404: fixed argv, no shell
import sys
import webbrowser
from collections.abc import Callable
from typing import Any

from mailwarden.core.text import clean
from mailwarden.delivery.base import JobAlert, Notifier

log = logging.getLogger(__name__)

APP_TITLE = "mailwarden"


def notification_text(alert: JobAlert) -> str:
    text = clean(alert.title()).replace("\n", " ").strip()
    return text.lstrip("-")[:120] or "Job email needs your attention"


class DesktopNotifier(Notifier):
    def __init__(
        self,
        *,
        backend: str,
        dashboard_base_url: str,
        click_wait_seconds: float = 0,
        platform: str = sys.platform,
        which: Callable[[str], str | None] = shutil.which,
        run: Callable[..., Any] = subprocess.run,
    ) -> None:
        self._base = dashboard_base_url.rstrip("/")
        self._click_wait = click_wait_seconds
        self._run = run
        self._which = which
        self.backend = self._resolve(backend, platform)

    def _resolve(self, backend: str, platform: str) -> str:
        if backend != "auto":
            return backend
        if platform == "darwin":
            return "terminal-notifier" if self._which("terminal-notifier") else "osascript"
        return "desktop-notifier"

    def url_for(self, alert: JobAlert) -> str:
        return f"{self._base}/i/{alert.account}/{alert.message_id}"

    def notify(self, alert: JobAlert) -> None:
        text = notification_text(alert)
        try:
            if self.backend == "terminal-notifier":
                self._terminal_notifier(text, self.url_for(alert), alert.message_id)
            elif self.backend == "osascript":
                self._osascript(text)
            elif self.backend == "desktop-notifier":
                self._desktop_notifier(text, self.url_for(alert))
        except Exception as e:  # a failed notification must never break a run
            log.warning("desktop notification failed (%s): %s", self.backend, type(e).__name__)

    def _terminal_notifier(self, text: str, url: str, message_id: str) -> None:
        exe = self._which("terminal-notifier")
        if not exe:
            raise FileNotFoundError("terminal-notifier")
        self._run(
            [exe, "-title", APP_TITLE, "-message", text, "-open", url, "-group", f"mailwarden-{message_id[:40]}"],
            check=False, timeout=15, capture_output=True,
        )

    def _osascript(self, text: str) -> None:
        # Text is passed as argv, never interpolated into the script: no AppleScript injection.
        self._run(
            ["/usr/bin/osascript", "-e", "on run argv", "-e",
             "display notification (item 1 of argv) with title (item 2 of argv)", "-e", "end run",
             text, APP_TITLE],
            check=False, timeout=15, capture_output=True,
        )

    def _desktop_notifier(self, text: str, url: str) -> None:
        from desktop_notifier import DesktopNotifier as _DN

        async def send() -> None:
            notifier = _DN(app_name=APP_TITLE)
            await notifier.send(title=APP_TITLE, message=text, on_clicked=lambda: webbrowser.open(url))
            if self._click_wait:
                await asyncio.sleep(self._click_wait)

        asyncio.run(send())
