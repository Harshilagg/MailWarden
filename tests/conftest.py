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
