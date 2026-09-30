import os

from mailwarden.cli import main
from mailwarden.config import load_sender_rules
from mailwarden.core.models import Tier


def test_init_reset_rules_and_promote(tmp_path, monkeypatch, capsys):
    home = tmp_path / "mw"
    monkeypatch.setenv("MAILWARDEN_HOME", str(home))
    assert main(["init"]) == 0
    (home / "sender_rules.yaml").write_text("priority: []\n")  # an old/placeholder file
    os.chmod(home / "sender_rules.yaml", 0o600)
    assert main(["init", "--reset-rules"]) == 0
    assert (home / "sender_rules.yaml.bak").read_text() == "priority: []\n"
    assert oct((home / "sender_rules.yaml").stat().st_mode & 0o777) == "0o600"

    assert main(["promote", "offers.shop.example", "ignore"]) == 0
    assert load_sender_rules(home).tier_for("x@offers.shop.example") is Tier.IGNORE
    assert oct((home / "sender_rules.yaml").stat().st_mode & 0o777) == "0o600"


def test_demoting_sensitive_requires_confirmation(tmp_path, monkeypatch):
    home = tmp_path / "mw"
    monkeypatch.setenv("MAILWARDEN_HOME", str(home))
    main(["init"])
    monkeypatch.setattr("builtins.input", lambda _: "no")
    assert main(["promote", "hdfcbank.net", "default"]) == 1
    assert load_sender_rules(home).tier_for("a@hdfcbank.net") is Tier.SENSITIVE
    assert main(["promote", "hdfcbank.net", "default", "--yes"]) == 0
    assert load_sender_rules(home).tier_for("a@hdfcbank.net") is Tier.DEFAULT


def test_dry_run_with_llm_requires_groq_key(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MAILWARDEN_HOME", str(tmp_path / "mw"))
    main(["init"])
    from mailwarden.app import build_app
    from mailwarden.core.models import Account, ProviderKind

    app = build_app()
    app.accounts.add(Account(user_id="local", name="x", provider=ProviderKind.GMAIL, address="a@b.com"))
    assert main(["dry-run", "--with-llm"]) == 2
    assert "set-groq-key" in capsys.readouterr().err


def test_tests_use_isolated_keyring():
    from mailwarden.security.secrets import SecretKeys, SecretStore

    assert SecretStore().get(SecretKeys.groq_api_key("local")) is None
