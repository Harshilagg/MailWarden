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
# Public job-board APIs used for automatic job-description fetches ([job_alerts] jd_auto_fetch).
JD_API_HOSTS = frozenset({"boards-api.greenhouse.io", "api.lever.co", "api.eu.lever.co", "api.ashbyhq.com"})

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
    if settings.job_alerts.jd_auto_fetch:
        hosts |= JD_API_HOSTS
    return frozenset(hosts)


def fetch_json(session: requests.Session, url: str, *, max_bytes: int = 5_000_000,
               timeout: float = 15) -> tuple[int, object]:
    """GET a JSON API through ``session`` (allowlist applies). Returns (status, parsed JSON or None)."""
    import json

    with session.get(url, timeout=timeout, stream=True, headers={"Accept": "application/json"}) as response:
        if response.status_code != 200:
            return response.status_code, None
        body = bytearray()
        for chunk in response.iter_content(65536):
            body += chunk
            if len(body) > max_bytes:
                return 413, None
        try:
            return 200, json.loads(bytes(body).decode("utf-8", errors="replace"))
        except ValueError:
            return 200, None


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


# --- job-description fetches (the "Fetch job description" button) --------------------------
#
# A separate session used only to GET job pages/APIs on an allowlist of hiring-system
# domains (see core/jd.py BUTTON_FETCH_SUFFIXES). The URLs come from email, so it is also
# hardened against SSRF: every hop (including redirects) must be on the allowlist, HTTPS
# on the default port, no IP literals, the host must resolve only to public addresses, and
# the address actually connected to is re-checked. No cookies, credentials or proxies.

import http.cookiejar
import ipaddress

_SHARED_NAT = ipaddress.ip_network("100.64.0.0/10")


class PublicFetchBlocked(EgressBlocked):
    pass


def _public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_reserved or addr.is_unspecified or (addr.version == 4 and addr in _SHARED_NAT))


def check_public_url(url: str, resolve=socket.getaddrinfo) -> None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https":
        raise PublicFetchBlocked("only https:// pages are fetched")
    if parts.username or parts.password:
        raise PublicFetchBlocked("credentials in URL are not allowed")
    if parts.port not in (None, 443):
        raise PublicFetchBlocked("non-standard port")
    if not host or "." not in host or host.endswith((".local", ".internal", ".localhost", ".lan", ".home")):
        raise PublicFetchBlocked("not a public host name")
    try:
        ipaddress.ip_address(host.strip("[]"))
        raise PublicFetchBlocked("IP-address URLs are not fetched")
    except ValueError:
        pass
    try:
        infos = resolve(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise PublicFetchBlocked("host does not resolve") from None
    ips = {info[4][0] for info in infos}
    if not ips or not all(_public_ip(ip) for ip in ips):
        raise PublicFetchBlocked("host resolves to a private or internal address")


class _NoCookies(http.cookiejar.DefaultCookiePolicy):
    def set_ok(self, cookie, request):  # never store cookies
        return False

    def return_ok(self, cookie, request):
        return False


class PublicWebSession(requests.Session):
    USER_AGENT = "Mozilla/5.0 (compatible; mailwarden/0.1; personal job-alert reader)"

    def __init__(self, allowed_suffixes: tuple[str, ...], *, max_redirects: int = 5,
                 resolve=socket.getaddrinfo) -> None:
        super().__init__()
        if not allowed_suffixes:
            raise ValueError("an explicit site allowlist is required")
        self._suffixes = tuple(x.lower() for x in allowed_suffixes)
        self.trust_env = False
        self.verify = True
        self.max_redirects = max_redirects
        self.cookies.set_policy(_NoCookies())
        self.headers.update({"User-Agent": self.USER_AGENT,
                             "Accept": "text/html,application/xhtml+xml,application/json;q=0.9",
                             "Accept-Language": "en-IN,en;q=0.8"})
        self._resolve = resolve

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        if request.method not in ("GET", "HEAD"):
            raise PublicFetchBlocked("only GET requests")
        host = (urlsplit(request.url or "").hostname or "").lower()
        if not any(host == sfx or host.endswith("." + sfx) for sfx in self._suffixes):
            raise PublicFetchBlocked(f"{host or 'that site'} is not on the job-description fetch list")
        check_public_url(request.url or "", resolve=self._resolve)
        request.headers.pop("Cookie", None)
        request.headers.pop("Authorization", None)
        if kwargs.get("verify", True) is not True:
            raise PublicFetchBlocked("TLS verification must stay on")
        kwargs["verify"] = True
        kwargs["stream"] = True
        response = super().send(request, **kwargs)
        peer = _peer_ip(response)
        if peer is not None and not _public_ip(peer):
            response.close()
            raise PublicFetchBlocked("connected address is private or internal")
        return response

    def fetch_html(self, url: str, *, max_bytes: int = 2_000_000, timeout: float = 15) -> tuple[int, str, str]:
        """GET a page. Returns (status, final_url, text); text is '' unless it is HTML."""
        with self.get(url, timeout=timeout, allow_redirects=True) as response:
            ctype = response.headers.get("content-type", "").lower()
            if response.status_code != 200 or ("html" not in ctype and "xml" not in ctype):
                return response.status_code, response.url, ""
            body = bytearray()
            for chunk in response.iter_content(65536):
                body += chunk
                if len(body) > max_bytes:
                    break
            encoding = response.encoding or "utf-8"
            try:
                return 200, response.url, bytes(body[:max_bytes]).decode(encoding, errors="replace")
            except LookupError:
                return 200, response.url, bytes(body[:max_bytes]).decode("utf-8", errors="replace")


    def fetch_json(self, url: str, *, max_bytes: int = 5_000_000, timeout: float = 15) -> tuple[int, object]:
        """GET a JSON API. Returns (status, parsed JSON or None)."""
        import json

        with self.get(url, timeout=timeout, allow_redirects=True, headers={"Accept": "application/json"}) as response:
            if response.status_code != 200:
                return response.status_code, None
            body = bytearray()
            for chunk in response.iter_content(65536):
                body += chunk
                if len(body) > max_bytes:
                    return 413, None
            try:
                return 200, json.loads(bytes(body).decode("utf-8", errors="replace"))
            except ValueError:
                return 200, None


def _peer_ip(response: requests.Response) -> str | None:
    try:
        conn = getattr(response.raw, "_connection", None) or getattr(response.raw, "connection", None)
        sock = getattr(conn, "sock", None)
        return sock.getpeername()[0] if sock is not None else None
    except (OSError, AttributeError):
        return None
