from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
import requests
from keyring.backend import KeyringBackend
from requests.adapters import BaseAdapter

from mailwarden.security.secrets import SecretStore


class MemoryKeyring(KeyringBackend):
    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        from keyring.errors import PasswordDeleteError

        if (service, username) not in self.store:
            raise PasswordDeleteError(username)
        del self.store[(service, username)]


class FakeTransport(BaseAdapter):
    """Records requests and answers from a handler; never touches the network."""

    def __init__(self, handler: Callable[[requests.PreparedRequest], tuple[int, Any, dict[str, str]]]):
        super().__init__()
        self.handler = handler
        self.requests: list[requests.PreparedRequest] = []

    def send(self, request, **kwargs):  # type: ignore[override]
        self.requests.append(request)
        status, body, headers = self.handler(request)
        resp = requests.Response()
        resp.status_code = status
        resp.url = request.url
        resp.request = request
        resp.headers.update(headers)
        resp._content = body if isinstance(body, bytes) else json.dumps(body).encode()
        return resp

    def close(self) -> None:
        pass


def mount(session: requests.Session, transport: FakeTransport) -> FakeTransport:
    session.mount("https://", transport)
    session.mount("http://", transport)
    return transport


@pytest.fixture
def secret_store() -> SecretStore:
    return SecretStore(MemoryKeyring())


@pytest.fixture(autouse=True)
def _isolate_from_real_system(monkeypatch, tmp_path_factory):
    """Tests must never touch the real keyring, real config or the real network.

    - SecretStore() without an explicit backend gets a fresh in-memory keyring.
    - MAILWARDEN_HOME points at an empty temp dir.
    - Any real HTTP send (requests' HTTPAdapter) fails the test. Tests that need
      HTTP mount a FakeTransport, which is not an HTTPAdapter.
    """
    import keyring as _keyring
    from requests.adapters import HTTPAdapter

    memory = MemoryKeyring()
    monkeypatch.setattr(_keyring, "get_keyring", lambda: memory)
    monkeypatch.setenv("MAILWARDEN_HOME", str(tmp_path_factory.mktemp("mailwarden-home")))

    def no_real_network(self, request, *a, **k):
        raise AssertionError(f"test attempted a real network request to {request.url}")

    monkeypatch.setattr(HTTPAdapter, "send", no_real_network)


# The zero-LLM-calls suite must never be skipped: a skip is reported as a failure.
NEVER_SKIP_MODULES = {"test_zero_llm_sensitive"}


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if item.module.__name__.rsplit(".", 1)[-1] in NEVER_SKIP_MODULES and report.skipped:
        report.outcome = "failed"
        report.longrepr = f"{item.nodeid} is a mandatory safety test and must not be skipped"
