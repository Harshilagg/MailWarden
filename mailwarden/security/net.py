"""The only module allowed to make outbound HTTP requests.

Every request (including each redirect hop) is checked against a host
allowlist. TLS verification cannot be disabled, proxies/netrc from the
environment are ignored, and plain HTTP is only permitted to localhost.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import requests

if TYPE_CHECKING:
    from mailwarden.config import Settings

GOOGLE_HOSTS = frozenset({"gmail.googleapis.com", "oauth2.googleapis.com", "accounts.google.com"})
MICROSOFT_HOSTS = frozenset({"graph.microsoft.com", "login.microsoftonline.com"})
GROQ_HOSTS = frozenset({"api.groq.com"})
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})

HTTPError = requests.HTTPError
RequestException = requests.RequestException


class EgressBlocked(RuntimeError):
    pass


def allowed_hosts(settings: Settings) -> frozenset[str]:
    """The full outbound allowlist for a given configuration.

    SECURITY.md must describe exactly this function's output.
    """
    hosts = set(GOOGLE_HOSTS)
    ollama_host = urlsplit(settings.ollama.base_url).hostname
    if ollama_host:
        hosts.add(ollama_host.lower())
    if settings.outlook.enabled:
        hosts |= MICROSOFT_HOSTS
    if settings.groq.enabled:
        hosts |= GROQ_HOSTS
    return frozenset(hosts)


def check_url(url: str, allowed: frozenset[str]) -> None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.username or parts.password:
        raise EgressBlocked("credentials in URL are not allowed")
    if not host or host not in allowed:
        raise EgressBlocked(f"outbound request to {host or '<none>'!r} is not on the allowlist")
    if parts.scheme == "https":
        return
    if parts.scheme == "http" and host in LOCAL_HOSTS:
        return
    raise EgressBlocked(f"scheme {parts.scheme!r} not allowed for {host!r}")


class AllowlistedSession(requests.Session):
    def __init__(self, allowed: Iterable[str], *, max_redirects: int = 3) -> None:
        super().__init__()
        self._allowed = frozenset(h.lower() for h in allowed)
        self.trust_env = False  # ignore HTTP(S)_PROXY, netrc, REQUESTS_CA_BUNDLE
        self.verify = True
        self.max_redirects = max_redirects

    @property
    def allowed(self) -> frozenset[str]:
        return self._allowed

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        check_url(request.url or "", self._allowed)
        verify = kwargs.get("verify", True)
        if verify is not True:
            raise EgressBlocked("TLS verification must stay on (custom verify values are rejected)")
        kwargs["verify"] = True
        return super().send(request, **kwargs)
