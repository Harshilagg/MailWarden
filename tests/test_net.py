import pytest

from mailwarden.config import Settings
from mailwarden.security.net import (
    GOOGLE_HOSTS,
    AllowlistedSession,
    EgressBlocked,
    allowed_hosts,
    check_url,
)
from tests.conftest import FakeTransport, mount


def ok(request):
    return 200, {}, {}


@pytest.fixture
def session():
    s = AllowlistedSession(GOOGLE_HOSTS | {"127.0.0.1"})
    mount(s, FakeTransport(ok))
    return s


def test_allowed_host_passes(session):
    assert session.get("https://gmail.googleapis.com/gmail/v1/users/me/profile").status_code == 200


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/",
        "https://gmail.googleapis.com.evil.com/",
        "https://evilgmail.googleapis.com/",
        "https://api.groq.com/openai/v1/chat/completions",
        "https://graph.microsoft.com/v1.0/me",
        "https://user:pass@gmail.googleapis.com/",
        "ftp://gmail.googleapis.com/",
    ],
)
def test_disallowed_urls_raise_before_sending(url):
    transport = FakeTransport(ok)
    s = AllowlistedSession(GOOGLE_HOSTS)
    mount(s, transport)
    with pytest.raises(EgressBlocked):
        s.get(url)
    assert transport.requests == []


def test_plain_http_only_to_localhost(session):
    assert session.get("http://127.0.0.1:11434/api/tags").status_code == 200
    with pytest.raises(EgressBlocked):
        session.get("http://gmail.googleapis.com/")


def test_tls_verification_cannot_be_disabled(session):
    with pytest.raises(EgressBlocked):
        session.get("https://gmail.googleapis.com/", verify=False)
    with pytest.raises(EgressBlocked):
        session.get("https://gmail.googleapis.com/", verify="/tmp/evil-ca.pem")


def test_environment_proxies_ignored(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker:8080")
    s = AllowlistedSession(GOOGLE_HOSTS)
    assert s.trust_env is False


def test_redirect_to_disallowed_host_is_blocked():
    def handler(request):
        if "gmail.googleapis.com" in request.url:
            return 302, b"", {"Location": "https://evil.example.com/steal"}
        return 200, {}, {}

    transport = FakeTransport(handler)
    s = AllowlistedSession(GOOGLE_HOSTS)
    mount(s, transport)
    with pytest.raises(EgressBlocked):
        s.get("https://gmail.googleapis.com/x")
    assert all("evil" not in r.url for r in transport.requests)


def test_default_allowlist_is_google_plus_local_ollama():
    assert allowed_hosts(Settings()) == GOOGLE_HOSTS | {"127.0.0.1"}


def test_groq_and_outlook_hosts_only_when_enabled():
    s = Settings.model_validate({"groq": {"enabled": True}, "outlook": {"enabled": True}})
    hosts = allowed_hosts(s)
    assert "api.groq.com" in hosts
    assert {"graph.microsoft.com", "login.microsoftonline.com"} <= hosts


def test_check_url_is_case_insensitive_on_host():
    check_url("https://GMAIL.googleapis.com/x", GOOGLE_HOSTS)
