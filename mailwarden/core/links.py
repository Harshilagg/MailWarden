"""Deep links into the mail provider's web UI (opened by the user's browser).

These are never fetched by mailwarden, so they do not touch the network allowlist.
"""

from __future__ import annotations

import re
from urllib.parse import quote

_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def gmail_link(account_address: str, message_id: str) -> str | None:
    if not _ID.match(message_id):
        return None
    user = quote(account_address, safe="@.") if account_address else "0"
    return f"https://mail.google.com/mail/u/{user}/#all/{message_id}"


_LOCAL_PATH = re.compile(r"^/(?!/)[A-Za-z0-9/_\-]*(?:\?[A-Za-z0-9=&_\-]*)?$")


def safe_local_path(path: str | None) -> str | None:
    """A dashboard path like /jobs?match=1 or /i/<account>/<id>; None for anything else."""
    if not path or len(path) > 200 or not _LOCAL_PATH.match(path):
        return None
    return path


def app_link(path: str) -> str:
    """mailwarden:// deep link for the desktop app (path must be a safe local path)."""
    return "mailwarden:/" + path


def path_from_app_link(url: str) -> str | None:
    """mailwarden://i/acct/id -> /i/acct/id ; mailwarden://jobs?match=1 -> /jobs?match=1."""
    if not url.lower().startswith("mailwarden://"):
        return None
    return safe_local_path("/" + url[len("mailwarden://"):])
