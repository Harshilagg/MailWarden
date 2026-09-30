"""Native macOS notifications posted as the mailwarden app itself.

Runs inside the app bundle (its own interpreter copy), so notifications show as
"mailwarden" with its icon, and macOS routes clicks to the mailwarden app. Uses
NSUserNotificationCenter: the newer UserNotifications framework refuses apps that
are not signed with a paid Developer ID, which a self-built app cannot have.

Content rules are the same as every other notifier: company, stage, deadline or
a count, never a subject or summary. Each notification carries only a validated
dashboard path, which the app opens when the notification is clicked.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from mailwarden.core.links import safe_local_path
from mailwarden.core.text import clean

log = logging.getLogger(__name__)

_delegate = None  # keep the Objective-C delegate alive


def post(text: str, path: str, *, title: str = "mailwarden", group: str | None = None) -> bool:
    """Deliver one notification. Must run inside the app bundle. Returns True if accepted."""
    from Foundation import NSDate, NSRunLoop, NSUserNotification, NSUserNotificationCenter

    center = NSUserNotificationCenter.defaultUserNotificationCenter()
    if center is None:
        return False
    note = NSUserNotification.alloc().init()
    note.setTitle_(clean(title)[:60])
    note.setInformativeText_(clean(text).replace("\n", " ")[:200])
    note.setUserInfo_({"path": safe_local_path(path) or "/"})
    if group:
        note.setIdentifier_(group[:60])  # re-posting the same identifier replaces the old one
    center.deliverNotification_(note)
    NSRunLoop.currentRunLoop().runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(1.0))
    return True


def _path_of(note) -> str | None:
    info = note.userInfo() if note is not None else None
    raw = info.get("path") if info is not None else None
    return safe_local_path(str(raw)) if raw is not None else None


def install_click_handler(show: Callable[[str], None]) -> None:
    """In the app process: open the clicked notification's page in the existing window."""
    global _delegate
    from AppKit import NSApplicationDidFinishLaunchingNotification
    from Foundation import NSNotificationCenter, NSObject, NSUserNotificationCenter

    class _Delegate(NSObject):
        def userNotificationCenter_shouldPresentNotification_(self, center, note):  # noqa: N802
            return True  # show banners even while the app is in front

        def userNotificationCenter_didActivateNotification_(self, center, note):  # noqa: N802
            path = _path_of(note)
            if path:
                show(path)
            center.removeDeliveredNotification_(note)

        def appLaunched_(self, notification):  # noqa: N802
            # App started by clicking a notification while it was closed.
            info = notification.userInfo()
            note = info.get("NSApplicationLaunchUserNotificationKey") if info is not None else None
            path = _path_of(note)
            if path:
                show(path)

    _delegate = _Delegate.alloc().init()
    NSUserNotificationCenter.defaultUserNotificationCenter().setDelegate_(_delegate)
    NSNotificationCenter.defaultCenter().addObserver_selector_name_object_(
        _delegate, "appLaunched:", NSApplicationDidFinishLaunchingNotification, None)
