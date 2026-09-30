"""Gmail provider: read-only, via the REST API over the allowlisted session.

Uses only these read endpoints: users.getProfile, users.history.list,
users.messages.list, users.messages.get. Attachment bodies are never
requested; the attachment-download endpoint is not referenced anywhere.
"""

from __future__ import annotations

import base64
import codecs
import datetime as dt
import logging
import re
from collections.abc import Callable, Iterator
from email.utils import parseaddr
from typing import Any

from mailwarden.core.models import Account, FetchedMessage, ProviderKind
from mailwarden.providers.base import MailProvider, ProviderError, SyncResult
from mailwarden.providers.google_oauth import GoogleCredentials
from mailwarden.providers.html_text import HtmlParseError, html_to_text, looks_like_html
from mailwarden.security.net import AllowlistedSession

log = logging.getLogger(__name__)

API = "https://gmail.googleapis.com/gmail/v1/users/me"
_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SKIP_LABELS = frozenset({"SPAM", "TRASH", "SENT", "DRAFT", "CHAT"})
_MAX_BODY_CHARS = 100_000  # bound memory; the classifier sees far less
_MAX_MIME_PARTS = 200


class HistoryExpired(ProviderError):
    pass


class _NotFound(ProviderError):
    pass


def _wanted(label_ids: list[str] | None) -> bool:
    return not (set(label_ids or ()) & _SKIP_LABELS)


def _charset(part: dict[str, Any]) -> str:
    for h in part.get("headers") or ():
        if h.get("name", "").lower() == "content-type":
            m = re.search(r'charset\s*=\s*"?([\w.:-]+)', h.get("value", ""), re.IGNORECASE)
            if m:
                return m.group(1)
    return "utf-8"


def _decode(data: str, charset: str) -> str:
    raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    try:
        codecs.lookup(charset)
    except LookupError:
        charset = "utf-8"
    return raw.decode(charset, errors="replace")


def _walk(payload: dict[str, Any]) -> Iterator[dict[str, Any]]:
    stack, seen = [payload], 0
    while stack and seen < _MAX_MIME_PARTS:
        part = stack.pop(0)
        seen += 1
        yield part
        stack.extend(part.get("parts") or ())


def extract_body(payload: dict[str, Any]) -> tuple[str, bool]:
    """Return (text, complete). ``complete`` is False if anything failed to decode."""
    plain: list[str] = []
    html: list[str] = []
    for part in _walk(payload):
        body = part.get("body") or {}
        if part.get("filename") or body.get("attachmentId"):
            continue  # attachment: never fetched, never read
        data = body.get("data")
        if not data:
            continue
        mime = (part.get("mimeType") or "").lower()
        if mime == "text/plain":
            plain.append(_decode(data, _charset(part)))
        elif mime == "text/html":
            html.append(_decode(data, _charset(part)))
    joined = "\n".join(plain).strip()
    if plain and not looks_like_html(joined):
        return joined[:_MAX_BODY_CHARS], True
    try:
        # Some senders put HTML in the text/plain part; treat it as HTML.
        return html_to_text(joined if plain else "\n".join(html))[:_MAX_BODY_CHARS], True
    except HtmlParseError:
        return "", False


def parse_message(user_id: str, account: str, data: dict[str, Any]) -> FetchedMessage:
    payload = data.get("payload") or {}
    headers: dict[str, str] = {}
    for h in payload.get("headers") or ():
        headers.setdefault(h.get("name", "").lower(), h.get("value", ""))
    name, address = parseaddr(headers.get("from", ""))
    try:
        body, complete = extract_body(payload)
    except (ValueError, TypeError):  # bad base64 etc.
        body, complete = "", False
    received = dt.datetime.fromtimestamp(int(data.get("internalDate", "0")) / 1000, tz=dt.UTC)
    return FetchedMessage(
        user_id=user_id,
        account=account,
        message_id=data["id"],
        thread_id=data.get("threadId"),
        sender_address=address.strip().lower(),
        sender_name=name.strip()[:200],
        subject=headers.get("subject", "")[:1000],
        body_text=body,
        received_at=received,
        label_ids=tuple(data.get("labelIds") or ()),
        content_complete=complete,
    )


class GmailProvider(MailProvider):
    kind = ProviderKind.GMAIL

    def __init__(
        self,
        session: AllowlistedSession,
        credentials_for: Callable[[Account], GoogleCredentials],
        *,
        full_sync_days: int = 7,
        max_messages: int = 200,
    ) -> None:
        self._session = session
        self._credentials_for = credentials_for
        self._creds: dict[tuple[str, str], GoogleCredentials] = {}
        self._full_sync_days = full_sync_days
        self._max_messages = max_messages

    def _credentials(self, account: Account) -> GoogleCredentials:
        key = (account.user_id, account.name)
        if key not in self._creds:
            self._creds[key] = self._credentials_for(account)
        return self._creds[key]

    def _get(self, account: Account, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        token = self._credentials(account).access_token()
        resp = self._session.get(
            API + path,
            params={k: v for k, v in (params or {}).items() if v is not None},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        if resp.status_code == 404:
            raise _NotFound(path)
        if resp.status_code != 200:
            raise ProviderError(f"Gmail API {path.split('/')[1]} failed (HTTP {resp.status_code})")
        return resp.json()

    def verify_access(self, account: Account) -> frozenset[str]:
        creds = self._credentials(account)
        creds.access_token()  # refresh => verify_scopes on the token response
        return creds.scopes

    def profile_address(self, account: Account) -> str:
        return self._get(account, "/profile")["emailAddress"]

    def list_new(self, account: Account, cursor: str | None) -> SyncResult:
        if cursor:
            try:
                return self._incremental(account, cursor)
            except HistoryExpired:
                log.info("history cursor expired for account %s; running full sync", account.name)
        return self._full(account)

    def _incremental(self, account: Account, cursor: str) -> SyncResult:
        ids: list[str] = []
        latest, page = cursor, None
        while True:
            try:
                data = self._get(
                    account,
                    "/history",
                    {"startHistoryId": cursor, "historyTypes": "messageAdded", "pageToken": page, "maxResults": 500},
                )
            except _NotFound:
                raise HistoryExpired(account.name) from None
            for record in data.get("history") or ():
                for added in record.get("messagesAdded") or ():
                    msg = added.get("message") or {}
                    if msg.get("id") and _wanted(msg.get("labelIds")):
                        ids.append(msg["id"])
            latest = data.get("historyId", latest)
            page = data.get("nextPageToken")
            if not page:
                break
        # Not truncated: the runner defers anything over its per-run cap as pending.
        return SyncResult(list(dict.fromkeys(ids)), str(latest), full_sync=False)

    def _full(self, account: Account) -> SyncResult:
        # Take the history id BEFORE listing so nothing arriving mid-sync is lost.
        history_id = str(self._get(account, "/profile")["historyId"])
        return SyncResult(self._recent_ids(account, self._max_messages), history_id, full_sync=True)

    def _recent_ids(self, account: Account, limit: int) -> list[str]:
        query = f"newer_than:{self._full_sync_days}d -in:spam -in:trash -in:sent -in:drafts -in:chats"
        ids: list[str] = []
        page = None
        while len(ids) < limit:
            data = self._get(
                account, "/messages", {"q": query, "pageToken": page, "maxResults": min(500, limit)}
            )
            ids.extend(m["id"] for m in data.get("messages") or ())
            page = data.get("nextPageToken")
            if not page:
                break
        return ids[:limit]

    def list_recent(self, account: Account, limit: int) -> list[str]:
        """Most recent message ids regardless of cursor (used by dry-run)."""
        return self._recent_ids(account, limit)

    def get_message(self, account: Account, message_id: str) -> FetchedMessage:
        if not _ID.match(message_id):
            raise ProviderError("invalid message id")
        data = self._get(account, f"/messages/{message_id}", {"format": "full"})
        return parse_message(account.user_id, account.name, data)
