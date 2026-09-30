"""OS keyring wrapper. The only place secrets are read or written.

Refuses to operate on a keyring backend that is not a real OS keyring
(the "fail" and "null" backends, or keyrings.alt plaintext/file stores).
"""

from __future__ import annotations

import keyring
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError

SERVICE = "mailwarden"

_INSECURE_MODULE_PREFIXES = (
    "keyring.backends.fail",
    "keyring.backends.null",
    "keyrings.alt",
)


class InsecureKeyringError(RuntimeError):
    pass


def _leaf_backends(backend: KeyringBackend) -> list[KeyringBackend]:
    inner = getattr(backend, "backends", None)  # ChainerBackend
    if inner is not None:
        return list(inner)
    return [backend]


def assert_secure_backend(backend: KeyringBackend) -> None:
    leaves = _leaf_backends(backend)
    if not leaves:
        raise InsecureKeyringError("No usable OS keyring backend found.")
    for b in leaves:
        module = type(b).__module__
        if module.startswith(_INSECURE_MODULE_PREFIXES) or b.priority <= 0:
            raise InsecureKeyringError(
                f"Keyring backend {module}.{type(b).__name__} is not an OS keyring; "
                "refusing to store secrets in it."
            )


class SecretKeys:
    """Keyring entry names. Namespaced by user_id for future multi-tenancy."""

    @staticmethod
    def oauth_refresh(user_id: str, account: str) -> str:
        return f"{user_id}/oauth-refresh/{account}"

    @staticmethod
    def oauth_client(user_id: str, provider: str) -> str:
        return f"{user_id}/oauth-client/{provider}"

    @staticmethod
    def account_index(user_id: str) -> str:
        return f"{user_id}/accounts"

    @staticmethod
    def db_key(user_id: str) -> str:
        return f"{user_id}/db-key"

    @staticmethod
    def dashboard_token(user_id: str) -> str:
        return f"{user_id}/dashboard-token"

    @staticmethod
    def dashboard_login(user_id: str) -> str:
        return f"{user_id}/dashboard-login-code"

    @staticmethod
    def groq_api_key(user_id: str) -> str:
        return f"{user_id}/groq-api-key"


class SecretStore:
    def __init__(self, backend: KeyringBackend | None = None) -> None:
        self._kr = backend if backend is not None else keyring.get_keyring()
        assert_secure_backend(self._kr)

    @property
    def backend_name(self) -> str:
        cls = type(self._kr)
        return f"{cls.__module__.rsplit('.', 1)[-1]}.{cls.__name__}"

    def get(self, key: str) -> str | None:
        return self._kr.get_password(SERVICE, key)

    def set(self, key: str, value: str) -> None:
        if not value:
            raise ValueError("refusing to store an empty secret")
        self._kr.set_password(SERVICE, key, value)

    def delete(self, key: str) -> None:
        try:
            self._kr.delete_password(SERVICE, key)
        except PasswordDeleteError:
            pass
