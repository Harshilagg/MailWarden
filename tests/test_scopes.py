import json
from urllib.parse import parse_qs

import pytest

from mailwarden.providers.base import ReauthRequired
from mailwarden.providers.google_oauth import (
    GMAIL_READONLY,
    GoogleCredentials,
    OAuthClient,
    ScopeError,
    verify_scopes,
)
from mailwarden.security.net import GOOGLE_HOSTS, AllowlistedSession
from tests.conftest import FakeTransport, mount

CLIENT = OAuthClient("123-abc.apps.googleusercontent.com", "GOCSPX-test")


def test_exact_readonly_scope_accepted():
    assert verify_scopes(GMAIL_READONLY) == {GMAIL_READONLY}


@pytest.mark.parametrize(
    "granted",
    [
        f"{GMAIL_READONLY} https://www.googleapis.com/auth/gmail.modify",
        f"{GMAIL_READONLY} https://www.googleapis.com/auth/gmail.send",
        "https://mail.google.com/",
        f"{GMAIL_READONLY} https://www.googleapis.com/auth/drive",
        f"{GMAIL_READONLY} openid email",
        "https://www.googleapis.com/auth/gmail.metadata",
        "",
        None,
    ],
)
def test_anything_else_refused(granted):
    with pytest.raises(ScopeError):
        verify_scopes(granted)


def _creds(token_response, status=200):
    transport = FakeTransport(lambda r: (status, token_response, {}))
    session = AllowlistedSession(GOOGLE_HOSTS)
    mount(session, transport)
    return GoogleCredentials(CLIENT, "1//refresh", session), transport


def test_refresh_with_readonly_scope_returns_token():
    creds, transport = _creds({"access_token": "ya29.ok", "expires_in": 3600, "scope": GMAIL_READONLY})
    assert creds.access_token() == "ya29.ok"
    body = parse_qs(transport.requests[0].body)
    assert body["grant_type"] == ["refresh_token"]


def test_refresh_with_broader_scope_refuses_and_keeps_no_token():
    creds, _ = _creds(
        {"access_token": "ya29.bad", "expires_in": 3600, "scope": "https://mail.google.com/"}
    )
    with pytest.raises(ScopeError):
        creds.access_token()
    with pytest.raises(ScopeError):
        creds.access_token()  # still refuses; nothing cached


def test_refresh_without_scope_field_is_refused():
    creds, _ = _creds({"access_token": "ya29.x", "expires_in": 3600})
    with pytest.raises(ScopeError):
        creds.access_token()


def test_invalid_grant_requires_reauth():
    creds, _ = _creds({"error": "invalid_grant"}, status=400)
    with pytest.raises(ReauthRequired):
        creds.access_token()


def test_client_json_must_be_desktop_type():
    web = json.dumps({"web": {"client_id": "x.apps.googleusercontent.com", "client_secret": "s"}})
    with pytest.raises(ValueError, match="Desktop app"):
        OAuthClient.from_client_json(web)
    desktop = json.dumps(
        {"installed": {"client_id": "x.apps.googleusercontent.com", "client_secret": "s"}}
    )
    assert OAuthClient.from_client_json(desktop).client_id == "x.apps.googleusercontent.com"


def test_client_repr_hides_secret():
    assert "GOCSPX" not in repr(CLIENT)
