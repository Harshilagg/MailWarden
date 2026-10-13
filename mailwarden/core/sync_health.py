"""Per-account sync health, so a broken sync is visible instead of silently emptying the pages.

Each run records, per account, when it last synced and, while it fails, since when and
why. An expired Google sign-in (ReauthRequired) also sends one notification a day.
The dashboard shows a banner from ``problems``.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass

from mailwarden.storage.base import Repository

STATE_KEY = "sync_health"
SHOW_AFTER = dt.timedelta(minutes=30)  # one failed run is often a network blip; say nothing yet


@dataclass(frozen=True)
class SyncProblem:
    account: str
    since: dt.datetime
    error: str
    reauth: bool  # the sign-in expired: only `add-account` fixes it
    last_ok: dt.datetime | None


def _load(repo: Repository, user_id: str) -> dict:
    try:
        data = json.loads(repo.get_state(user_id, STATE_KEY) or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def record_ok(repo: Repository, user_id: str, account: str, now: dt.datetime) -> None:
    data = _load(repo, user_id)
    data[account] = {"ok_at": now.isoformat()}
    repo.set_state(user_id, STATE_KEY, json.dumps(data))


def record_failure(repo: Repository, user_id: str, account: str, error: str, *, reauth: bool,
                   now: dt.datetime) -> bool:
    """Remember the failure. Returns True when a notification should be sent (reauth, once a day)."""
    data = _load(repo, user_id)
    entry = data.get(account) if isinstance(data.get(account), dict) else {}
    entry.setdefault("failing_since", now.isoformat())
    entry["error"] = error[:200]
    entry["reauth"] = reauth
    today = now.astimezone().date().isoformat()
    notify = reauth and entry.get("notified_on") != today
    if notify:
        entry["notified_on"] = today
    data[account] = entry
    repo.set_state(user_id, STATE_KEY, json.dumps(data))
    return notify


def forget(repo: Repository, user_id: str, account: str) -> None:
    data = _load(repo, user_id)
    if data.pop(account, None) is not None:
        repo.set_state(user_id, STATE_KEY, json.dumps(data))


def problems(repo: Repository, user_id: str, now: dt.datetime, accounts: list[str] | None = None) -> list[SyncProblem]:
    """Accounts that are failing (an expired sign-in at once, anything else after 30 minutes)."""
    out = []
    for account, entry in sorted(_load(repo, user_id).items()):
        if accounts is not None and account not in accounts:
            continue
        if not isinstance(entry, dict) or not entry.get("failing_since"):
            continue
        try:
            since = dt.datetime.fromisoformat(entry["failing_since"])
            last_ok = dt.datetime.fromisoformat(entry["ok_at"]) if entry.get("ok_at") else None
        except (TypeError, ValueError):
            continue
        reauth = bool(entry.get("reauth"))
        if reauth or now - since >= SHOW_AFTER:
            out.append(SyncProblem(account, since, str(entry.get("error") or "sync failed"), reauth, last_ok))
    return out
