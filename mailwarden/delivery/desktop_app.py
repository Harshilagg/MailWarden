"""Native macOS window for the dashboard (WebKit via pywebview), instead of a browser tab.

- Loads only the local dashboard (http://127.0.0.1:<port>); links that open in a new
  tab ("Open in Gmail", job links) go to your default browser, not this window.
- No JavaScript bridge to Python is exposed, developer tools are off, downloads are
  off, and private mode keeps no cookies on disk: navigation always goes through a
  fresh one-time sign-in code.
- Single window: `mailwarden://...` links (notification clicks) and later
  `mailwarden app` calls are delivered to this window, which navigates and comes to
  the front. A malicious link can only open a read-only dashboard page.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from importlib import resources
from pathlib import Path

from mailwarden.core.links import path_from_app_link, safe_local_path

log = logging.getLogger(__name__)

TITLE = "mailwarden"
_handler = None  # keep the Apple-event handler alive


def _brand_process() -> None:
    """Show 'mailwarden' and its logo (not 'Python') even when not run from the app bundle."""
    try:
        from AppKit import NSApplication, NSImage
        from Foundation import NSBundle

        info = NSBundle.mainBundle().infoDictionary()
        if info is not None:
            info["CFBundleName"] = TITLE
        with resources.as_file(resources.files("mailwarden.assets").joinpath("mailwarden.icns")) as icon:
            image = NSImage.alloc().initWithContentsOfFile_(str(icon))
        if image is not None:
            NSApplication.sharedApplication().setApplicationIconImage_(image)
    except Exception:  # cosmetic only
        log.debug("could not set app name/icon")


def _bring_to_front(window) -> None:
    try:
        from AppKit import NSApplication
        from PyObjCTools import AppHelper

        def front() -> None:
            window.restore()
            NSApplication.sharedApplication().activateIgnoringOtherApps_(True)

        AppHelper.callAfter(front)
    except Exception:
        log.debug("could not bring the window to front")


def _register_url_handler(show: Callable[[str], None]) -> None:
    """Receive mailwarden:// links (from notifications) via the macOS GetURL Apple event."""
    global _handler
    from Foundation import NSAppleEventManager, NSObject

    class _URLHandler(NSObject):
        def handleURLEvent_withReplyEvent_(self, event, reply):  # noqa: N802
            url = event.paramDescriptorForKeyword_(0x2D2D2D2D).stringValue()  # keyDirectObject '----'
            path = path_from_app_link(url or "")
            if path:
                show(path)

    _handler = _URLHandler.alloc().init()
    gurl = int.from_bytes(b"GURL", "big")
    NSAppleEventManager.sharedAppleEventManager().setEventHandler_andSelector_forEventClass_andEventID_(
        _handler, "handleURLEvent:withReplyEvent:", gurl, gurl)


def open_window(login_url: Callable[[str], str], *, socket_path: Path, first_path: str = "/") -> None:
    """Open the single dashboard window. ``login_url(path)`` returns a fresh sign-in URL for a path."""
    import webview

    from mailwarden.security.net import serve_app_socket

    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
    webview.settings["ALLOW_DOWNLOADS"] = False
    _brand_process()
    window = webview.create_window(TITLE, login_url(safe_local_path(first_path) or "/"),
                                   width=1200, height=820, min_size=(720, 520), text_select=True)

    def show(path: str) -> None:
        path = safe_local_path(path) or "/"
        window.load_url(login_url(path))
        _bring_to_front(window)

    try:
        _register_url_handler(show)
    except Exception:
        log.warning("could not register for mailwarden:// links")
    try:
        from mailwarden.delivery.app_notify import install_click_handler

        install_click_handler(show)
    except Exception:
        log.warning("could not register for notification clicks")
    try:
        serve_app_socket(socket_path, show)
    except OSError:
        log.warning("single-instance hand-off unavailable (socket path too long?)")
    try:
        webview.start(private_mode=True, debug=False)
    finally:
        try:
            socket_path.unlink()
        except OSError:
            pass
