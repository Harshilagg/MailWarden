"""Native macOS window for the dashboard (WebKit via pywebview), instead of a browser tab.

- Loads only the local dashboard (http://127.0.0.1:<port>); links that open in a new
  tab ("Open in Gmail", job links) go to your default browser, not this window.
- No JavaScript bridge to Python is exposed, developer tools are off, downloads are
  off, and private mode keeps no cookies on disk: every launch signs in with a fresh
  one-time code.
"""

from __future__ import annotations

import logging
from importlib import resources

log = logging.getLogger(__name__)

TITLE = "mailwarden"


def _brand_process() -> None:
    """Show 'mailwarden' and its logo (not 'Python') in the menu bar and Dock."""
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


def open_window(url: str) -> None:
    import webview

    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
    webview.settings["ALLOW_DOWNLOADS"] = False
    _brand_process()
    webview.create_window(TITLE, url, width=1200, height=820, min_size=(720, 520), text_select=True)
    webview.start(private_mode=True, debug=False)
