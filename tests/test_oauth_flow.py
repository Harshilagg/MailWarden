import threading
import urllib.request
from urllib.parse import parse_qs, urlsplit

import pytest

from mailwarden.providers.base import ProviderError
from mailwarden.providers.google_oauth import (
    AUTH_URL,
    GMAIL_READONLY,
    REVOKE_URL,
    TOKEN_URL,
    OAuthClient,
    ScopeError,
    run_loopback_flow,
)
from mailwarden.security.net import GOOGLE_HOSTS, AllowlistedSession
from tests.conftest import FakeTransport, mount

CLIENT = OAuthClient("123-abc.apps.googleusercontent.com", "GOCSPX-test")


def _browser(tamper_state=False):
    seen = {}

    def open_browser(url):
        seen["url"] = url
        q = parse_qs(urlsplit(url).query)
        state = "wrong" if tamper_state else q["state"][0]
        callback = f"{q['redirect_uri'][0]}?code=4/abc&state={state}"
        threading.Thread(target=lambda: urllib.request.urlopen(callback, timeout=5).read()).start()

    return open_browser, seen


def _session(token_body):
    def handler(req):
        if req.url.startswith(TOKEN_URL):
            return 200, token_body, {}
        return 200, {}, {}

    s = AllowlistedSession(GOOGLE_HOSTS)
    return s, mount(s, FakeTransport(handler))


def test_flow_requests_only_readonly_with_pkce():
    session, transport = _session(
        {"access_token": "ya29.a", "refresh_token": "1//r", "expires_in": 3600, "scope": GMAIL_READONLY}
    )
    browser, seen = _browser()
    grant = run_loopback_flow(CLIENT, session, open_browser=browser, announce=lambda _: None, timeout_seconds=10)
    assert grant.refresh_token == "1//r"
    q = parse_qs(urlsplit(seen["url"]).query)
    assert seen["url"].startswith(AUTH_URL)
    assert q["scope"] == [GMAIL_READONLY]
    assert q["code_challenge_method"] == ["S256"]
    assert "include_granted_scopes" not in q
    assert q["redirect_uri"][0].startswith("http://127.0.0.1:")
    exchange = parse_qs(transport.requests[0].body)
    assert "code_verifier" in exchange


def test_flow_with_broader_grant_revokes_and_refuses():
    session, transport = _session(
        {"access_token": "ya29.a", "refresh_token": "1//r", "expires_in": 3600, "scope": "https://mail.google.com/"}
    )
    browser, _ = _browser()
    with pytest.raises(ScopeError):
        run_loopback_flow(CLIENT, session, open_browser=browser, announce=lambda _: None, timeout_seconds=10)
    assert any(r.url.startswith(REVOKE_URL) for r in transport.requests)


def test_flow_rejects_state_mismatch():
    session, transport = _session({})
    browser, _ = _browser(tamper_state=True)
    with pytest.raises(ProviderError, match="state_mismatch"):
        run_loopback_flow(CLIENT, session, open_browser=browser, announce=lambda _: None, timeout_seconds=10)
    assert transport.requests == []  # never exchanged the code
