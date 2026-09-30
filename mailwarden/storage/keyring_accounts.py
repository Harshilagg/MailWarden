"""Account registry kept in the OS keyring (v1).

Account addresses are personal data; keeping the tiny account index in the
keyring avoids a plaintext file on disk before the encrypted DB exists.
"""

from __future__ import annotations

import json

from mailwarden.core.models import Account
from mailwarden.security.secrets import SecretKeys, SecretStore
from mailwarden.storage.base import AccountRegistry


class KeyringAccountRegistry(AccountRegistry):
    def __init__(self, secrets: SecretStore) -> None:
        self._secrets = secrets

    def _load(self, user_id: str) -> list[Account]:
        raw = self._secrets.get(SecretKeys.account_index(user_id))
        if not raw:
            return []
        return [Account.model_validate(a) for a in json.loads(raw)]

    def _save(self, user_id: str, accounts: list[Account]) -> None:
        key = SecretKeys.account_index(user_id)
        if not accounts:
            self._secrets.delete(key)
            return
        self._secrets.set(key, json.dumps([a.model_dump(mode="json") for a in accounts]))

    def list(self, user_id: str) -> list[Account]:
        return self._load(user_id)

    def get(self, user_id: str, name: str) -> Account | None:
        return next((a for a in self._load(user_id) if a.name == name), None)

    def add(self, account: Account) -> None:
        accounts = self._load(account.user_id)
        if any(a.name == account.name for a in accounts):
            raise ValueError(f"account {account.name!r} already exists")
        self._save(account.user_id, [*accounts, account])

    def remove(self, user_id: str, name: str) -> bool:
        accounts = self._load(user_id)
        kept = [a for a in accounts if a.name != name]
        self._save(user_id, kept)
        return len(kept) != len(accounts)
