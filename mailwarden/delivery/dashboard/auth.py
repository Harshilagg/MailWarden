"""Dashboard authentication.

- A random per-install access token lives in the OS keyring and is the value
  of an HttpOnly, SameSite=Strict cookie.
- The cookie is set by visiting a one-time login URL (`mailwarden dashboard`
  or `mailwarden open` prints/opens it). The code is single use, expires in
  10 minutes, and only its SHA-256 hash is stored (in the keyring), so any
  mailwarden process can issue one for a running dashboard.
- State-changing requests carry a CSRF token derived from the access token.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable

from mailwarden.security.secrets import SecretKeys, SecretStore

LOGIN_TTL_SECONDS = 600
COOKIE_NAME = "mw_session"
COOKIE_MAX_AGE = 90 * 24 * 3600


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def ensure_install_token(store: SecretStore, user_id: str) -> str:
    key = SecretKeys.dashboard_token(user_id)
    token = store.get(key)
    if not token:
        token = secrets.token_urlsafe(32)
        store.set(key, token)
    return token


def issue_login_code(store: SecretStore, user_id: str, *, now: Callable[[], float] = time.time) -> str:
    code = secrets.token_urlsafe(24)
    store.set(SecretKeys.dashboard_login(user_id), json.dumps({"h": _hash(code), "exp": now() + LOGIN_TTL_SECONDS}))
    return code


def redeem_login_code(store: SecretStore, user_id: str, code: str, *, now: Callable[[], float] = time.time) -> bool:
    key = SecretKeys.dashboard_login(user_id)
    raw = store.get(key)
    if not raw or not code:
        return False
    try:
        data = json.loads(raw)
        expected, expires = str(data["h"]), float(data["exp"])
    except (ValueError, KeyError, TypeError):
        store.delete(key)
        return False
    if now() > expires:
        store.delete(key)
        return False
    if not hmac.compare_digest(_hash(code), expected):
        return False
    store.delete(key)  # single use
    return True


def token_matches(presented: str | None, token: str) -> bool:
    return bool(presented) and hmac.compare_digest(presented.encode(), token.encode())


def csrf_token(install_token: str) -> str:
    return hmac.new(install_token.encode(), b"mailwarden-csrf-v1", hashlib.sha256).hexdigest()
