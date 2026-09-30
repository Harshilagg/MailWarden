"""Google OAuth for installed (Desktop) apps: loopback redirect + PKCE.

Implemented directly (rather than via google-auth-oauthlib) so every token
request goes through the allowlisted session, and so the granted scopes are
checked on every token response: anything other than exactly
gmail.readonly is refused and the grant is revoked.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
import webbrowser
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from mailwarden.providers.base import ProviderError, ReauthRequired
from mailwarden.security.net import AllowlistedSession

log = logging.getLogger(__name__)

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"

GMAIL_READONLY = "https://www.googleapis.com/auth/gmail.readonly"
ALLOWED_SCOPES = frozenset({GMAIL_READONLY})


class ScopeError(ProviderError):
    pass


def parse_scopes(granted: str | Iterable[str] | None) -> frozenset[str]:
    if granted is None:
        return frozenset()
    if isinstance(granted, str):
        return frozenset(granted.split())
    return frozenset(granted)


def verify_scopes(granted: str | Iterable[str] | None) -> frozenset[str]:
    """Raise unless the grant is exactly gmail.readonly."""
    scopes = parse_scopes(granted)
    if not scopes:
        raise ScopeError("token response did not report granted scopes; refusing to continue")
    extra = scopes - ALLOWED_SCOPES
    if extra:
        raise ScopeError(
            "grant includes scopes broader than gmail.readonly: " + ", ".join(sorted(extra))
        )
    if GMAIL_READONLY not in scopes:
        raise ScopeError("grant does not include gmail.readonly")
    return scopes


@dataclass(frozen=True)
class OAuthClient:
    client_id: str
    client_secret: str

    def __repr__(self) -> str:
        return f"OAuthClient(client_id={self.client_id!r}, client_secret=***)"

    @classmethod
    def from_client_json(cls, text: str) -> OAuthClient:
        data = json.loads(text)
        if "installed" not in data:
            if "web" in data:
                raise ValueError(
                    "this is a 'Web application' OAuth client; create a 'Desktop app' client instead"
                )
            raise ValueError("not a Google OAuth client file (missing 'installed')")
        inst = data["installed"]
        client_id = inst.get("client_id", "")
        client_secret = inst.get("client_secret", "")
        if not client_id.endswith(".apps.googleusercontent.com") or not client_secret:
            raise ValueError("client file is missing client_id or client_secret")
        return cls(client_id, client_secret)

    def to_secret(self) -> str:
        return json.dumps({"client_id": self.client_id, "client_secret": self.client_secret})

    @classmethod
    def from_secret(cls, text: str) -> OAuthClient:
        data = json.loads(text)
        return cls(data["client_id"], data["client_secret"])


@dataclass(frozen=True)
class TokenGrant:
    access_token: str
    refresh_token: str
    expires_in: int
    scopes: frozenset[str]

    def __repr__(self) -> str:
        return f"TokenGrant(scopes={sorted(self.scopes)!r}, expires_in={self.expires_in})"


def revoke(session: AllowlistedSession, token: str) -> None:
    try:
        session.post(REVOKE_URL, data={"token": token}, timeout=15)
    except Exception:
        log.warning("token revocation request failed; revoke manually at myaccount.google.com")


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class _CallbackServer(HTTPServer):
    expected_state: str
    result: tuple[str, str] | None = None


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _CallbackServer

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        if parts.path != "/":
            self.send_response(404)
            self.end_headers()
            return
        qs = parse_qs(parts.query)
        state = qs.get("state", [""])[0]
        if not secrets.compare_digest(state.encode(), self.server.expected_state.encode()):
            self.server.result = ("error", "state_mismatch")
        elif "error" in qs:
            self.server.result = ("error", qs["error"][0][:100])
        elif "code" in qs:
            self.server.result = ("code", qs["code"][0])
        else:
            self.server.result = ("error", "no_code")
        body = b"<!doctype html><title>mailwarden</title><p>mailwarden: you can close this tab.</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass  # default logging would print the auth code to stderr


def run_loopback_flow(
    client: OAuthClient,
    session: AllowlistedSession,
    *,
    open_browser: Callable[[str], object] = webbrowser.open,
    announce: Callable[[str], None] = print,
    timeout_seconds: int = 300,
) -> TokenGrant:
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(32)

    server = _CallbackServer(("127.0.0.1", 0), _CallbackHandler)
    server.expected_state = state
    server.timeout = 1
    redirect_uri = f"http://127.0.0.1:{server.server_address[1]}/"

    params = {
        "client_id": client.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": GMAIL_READONLY,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
        # include_granted_scopes deliberately omitted: never merge other grants.
    }
    url = f"{AUTH_URL}?{urlencode(params)}"
    announce(f"Opening your browser for Google sign-in. If it does not open, visit:\n{url}")
    open_browser(url)

    deadline = time.monotonic() + timeout_seconds
    try:
        while server.result is None and time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()

    if server.result is None:
        raise ProviderError("timed out waiting for Google sign-in")
    kind, value = server.result
    if kind != "code":
        raise ProviderError(f"Google sign-in failed: {value}")

    resp = session.post(
        TOKEN_URL,
        data={
            "code": value,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "code_verifier": verifier,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        },
        timeout=30,
    )
    if resp.status_code != 200:
        raise ProviderError(f"token exchange failed (HTTP {resp.status_code})")
    data = resp.json()
    access, refresh = data.get("access_token"), data.get("refresh_token")
    try:
        scopes = verify_scopes(data.get("scope"))
    except ScopeError:
        revoke(session, refresh or access or "")
        raise
    if not access or not refresh:
        raise ProviderError("Google did not return a refresh token; remove the app's access and retry")
    return TokenGrant(access, refresh, int(data.get("expires_in", 3600)), scopes)


class GoogleCredentials:
    """Holds a refresh token; mints access tokens in memory, checking scopes each time."""

    def __init__(
        self,
        client: OAuthClient,
        refresh_token: str,
        session: AllowlistedSession,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._refresh_token = refresh_token
        self._session = session
        self._clock = clock
        self._access: str | None = None
        self._expiry = 0.0
        self.scopes: frozenset[str] = frozenset()

    def __repr__(self) -> str:
        return f"GoogleCredentials(scopes={sorted(self.scopes)!r})"

    def seed(self, grant: TokenGrant) -> None:
        self._access = grant.access_token
        self._expiry = self._clock() + grant.expires_in
        self.scopes = grant.scopes

    def access_token(self) -> str:
        if self._access and self._clock() < self._expiry - 60:
            return self._access
        resp = self._session.post(
            TOKEN_URL,
            data={
                "client_id": self._client.client_id,
                "client_secret": self._client.client_secret,
                "refresh_token": self._refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=30,
        )
        if resp.status_code in (400, 401):
            try:
                err = resp.json().get("error", "")
            except ValueError:
                err = ""
            if err in ("invalid_grant", "unauthorized_client", "invalid_client"):
                raise ReauthRequired(f"Google rejected the stored grant ({err}); run add-account again")
        if resp.status_code != 200:
            raise ProviderError(f"token refresh failed (HTTP {resp.status_code})")
        data = resp.json()
        self._access = None
        self.scopes = verify_scopes(data.get("scope"))
        token = data.get("access_token")
        if not token:
            raise ProviderError("token refresh returned no access token")
        self._access = token
        self._expiry = self._clock() + int(data.get("expires_in", 3600))
        return token

    def revoke(self) -> None:
        revoke(self._session, self._refresh_token)
