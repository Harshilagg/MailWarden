import os

import pytest
from keyring.backends import fail

from mailwarden.config import ConfigError, Settings, init_home, load_settings
from mailwarden.core.models import Account, ProviderKind
from mailwarden.security.fs import InsecurePermissions
from mailwarden.security.secrets import InsecureKeyringError, SecretKeys, SecretStore
from mailwarden.storage.keyring_accounts import KeyringAccountRegistry


def test_fail_backend_rejected():
    with pytest.raises(InsecureKeyringError):
        SecretStore(fail.Keyring())


def test_secret_roundtrip_and_namespacing(secret_store):
    secret_store.set(SecretKeys.oauth_refresh("local", "personal"), "1//abc")
    assert secret_store.get("local/oauth-refresh/personal") == "1//abc"
    assert secret_store.get(SecretKeys.oauth_refresh("other", "personal")) is None
    secret_store.delete(SecretKeys.oauth_refresh("local", "personal"))
    secret_store.delete(SecretKeys.oauth_refresh("local", "personal"))  # idempotent
    with pytest.raises(ValueError):
        secret_store.set("k", "")


def test_account_registry(secret_store):
    reg = KeyringAccountRegistry(secret_store)
    acct = Account(user_id="local", name="work", provider=ProviderKind.GMAIL, address="a@b.com")
    reg.add(acct)
    with pytest.raises(ValueError):
        reg.add(acct)
    assert reg.get("local", "work") == acct
    assert reg.list("someone-else") == []
    assert reg.remove("local", "work") and reg.list("local") == []


def test_init_creates_private_files(tmp_path):
    home = tmp_path / "mw"
    init_home(home)
    assert oct(home.stat().st_mode & 0o777) == "0o700"
    assert oct((home / "config.toml").stat().st_mode & 0o777) == "0o600"
    settings = load_settings(home)
    # The shipped template opts in to Groq explicitly...
    assert settings.llm.backend == "groq" and settings.groq.enabled is True
    # ...but the code default never sends anything to the cloud.
    assert Settings().llm.backend == "ollama" and Settings().groq.enabled is False


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_loose_permissions_refused(tmp_path):
    home = tmp_path / "mw"
    init_home(home)
    os.chmod(home / "config.toml", 0o644)
    with pytest.raises(InsecurePermissions):
        load_settings(home)
    os.chmod(home / "config.toml", 0o600)
    os.chmod(home, 0o755)
    with pytest.raises(InsecurePermissions):
        load_settings(home)


def test_remote_ollama_refused():
    with pytest.raises(ValueError):
        Settings.model_validate({"ollama": {"base_url": "http://192.168.1.20:11434"}})


def test_groq_backend_requires_explicit_enable():
    with pytest.raises(ValueError):
        Settings.model_validate({"llm": {"backend": "groq"}})


def test_unknown_config_keys_rejected(tmp_path):
    home = tmp_path / "mw"
    init_home(home)
    with (home / "config.toml").open("a") as f:
        f.write("\n[telemetry]\nenabled = true\n")
    with pytest.raises(ConfigError):
        load_settings(home)
