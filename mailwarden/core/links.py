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
