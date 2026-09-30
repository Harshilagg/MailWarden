"""Desktop notifications for urgent job mail.

Content is limited to company, stage and deadline (``JobAlert.title``): never
a summary, subject or link text. Clicking opens the matching dashboard entry
(a local 127.0.0.1 URL).

macOS, in order of preference:
- app: posted as the mailwarden app itself (built by `mailwarden launcher`); shows
  "mailwarden" with its logo, and a click opens the entry in the app window;
- terminal-notifier, if installed;
- osascript (macOS attributes these to Script Editor, so a click opens Script Editor).
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

from mailwarden.core.links import app_link, safe_local_path
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
        click_target: str = "browser",
        content_image: str | None = None,
        app_helper: str | None = None,
    ) -> None:
        self._app_helper = app_helper
        self._base = dashboard_base_url.rstrip("/")
        # "app": clicks open mailwarden:// links, handled by the (single) desktop app window.
        self._click_target = click_target
        self._content_image = content_image
        self._click_wait = click_wait_seconds
        self._run = run
        self._which = which
        self.backend = self._resolve(backend, platform)

    def _resolve(self, backend: str, platform: str) -> str:
        if backend != "auto":
            return backend
        if platform == "darwin":
            if self._app_helper:
                return "app"
            return "terminal-notifier" if self._which("terminal-notifier") else "osascript"
        return "desktop-notifier"

    def url_for(self, alert: JobAlert) -> str:
        return self._url(f"/i/{alert.account}/{alert.message_id}")

    def _url(self, path: str) -> str:
        path = safe_local_path(path) or "/"
        return app_link(path) if self._click_target == "app" else f"{self._base}{path}"

    def notify(self, alert: JobAlert) -> None:
        path = f"/i/{alert.account}/{alert.message_id}"
        self._send(notification_text(alert), self._url(path), f"mailwarden-{alert.message_id[:40]}", path)

    def notify_text(self, text: str, dashboard_path: str) -> None:
        text = clean(text).replace("\n", " ").strip().lstrip("-")[:120]
        self._send(text, self._url(dashboard_path), "mailwarden-notice", safe_local_path(dashboard_path) or "/")

    def _send(self, text: str, url: str, group: str, path: str = "/") -> None:
        try:
            if self.backend == "app":
                self._app_notify(text, path, group)
            elif self.backend == "terminal-notifier":
                self._terminal_notifier(text, url, group)
            elif self.backend == "osascript":
                self._osascript(text)
            elif self.backend == "desktop-notifier":
                self._desktop_notifier(text, url)
        except Exception as e:  # a failed notification must never break a run
            log.warning("desktop notification failed (%s): %s", self.backend, type(e).__name__)

    def _app_notify(self, text: str, path: str, group: str) -> None:
        if not self._app_helper:
            raise FileNotFoundError("mailwarden app notification helper")
        self._run([self._app_helper, "--text", text, "--path", path, "--group", group],
                  check=False, timeout=30, capture_output=True)

    def _terminal_notifier(self, text: str, url: str, group: str) -> None:
        exe = self._which("terminal-notifier")
        if not exe:
            raise FileNotFoundError("terminal-notifier")
        argv = [exe, "-title", APP_TITLE, "-message", text, "-open", url, "-group", group]
        if self._content_image:
            argv += ["-contentImage", self._content_image]  # the mailwarden logo, shown in the notification
        self._run(argv, check=False, timeout=15, capture_output=True)

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
