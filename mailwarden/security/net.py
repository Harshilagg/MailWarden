"""The only module allowed to make outbound HTTP requests.

Every request (including each redirect hop) is checked against a host
allowlist. TLS verification cannot be disabled, proxies/netrc from the
environment are ignored, and plain HTTP is only permitted to localhost.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import socket

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
    if settings.llm.backend == "ollama":
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


def local_port_open(port: int, timeout: float = 0.5) -> bool:
    """True if something is listening on 127.0.0.1:<port>. Loopback only."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


# --- single-instance hand-off for the desktop app (Unix domain socket, owner-only) -----

_IPC_MAX = 1024


def send_to_running_app(socket_path, path: str, timeout: float = 1.0) -> bool:
    """Ask an already-running desktop app to show ``path``. False if none is running."""
    import json

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(str(socket_path))
            s.sendall(json.dumps({"path": path}).encode()[:_IPC_MAX])
            s.shutdown(socket.SHUT_WR)
            return s.recv(16) == b"ok"
    except OSError:
        return False


def serve_app_socket(socket_path, on_path):
    """Listen on a 0600 Unix socket; call ``on_path(path)`` for each request. Returns the thread."""
    import json
    import os
    import threading

    path = str(socket_path)
    if os.path.exists(path):
        os.unlink(path)  # stale socket from a previous crash
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        server.bind(path)
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    server.listen(4)

    def loop() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(2)
                    data = conn.recv(_IPC_MAX)
                    target = json.loads(data.decode("utf-8")).get("path", "/")
                    on_path(target if isinstance(target, str) else "/")
                    conn.sendall(b"ok")
                except (OSError, ValueError):
                    continue

    thread = threading.Thread(target=loop, name="mailwarden-app-ipc", daemon=True)
    thread.start()
    return thread
