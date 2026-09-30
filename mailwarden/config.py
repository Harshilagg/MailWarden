"""Non-secret settings, loaded from config.toml in the mailwarden home dir.

Secrets never live here; they are in the OS keyring (security/secrets.py).
"""

from __future__ import annotations

import os
import tomllib
from importlib import resources
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import platformdirs
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mailwarden.core.models import SLUG_PATTERN
from mailwarden.core.sender_rules import RulesError, SenderRules
from mailwarden.security.fs import check_private, ensure_private_dir, write_private
from mailwarden.security.net import LOCAL_HOSTS

CONFIG_FILE = "config.toml"
RULES_FILE = "sender_rules.yaml"
TEMPLATE_FILES = ("config.toml", "sender_rules.yaml")


class ConfigError(RuntimeError):
    pass


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class LLMSettings(_Section):
    backend: Literal["ollama", "groq"] = "ollama"
    max_body_chars: int = Field(default=1500, ge=200, le=8000)


class OllamaSettings(_Section):
    base_url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5:3b"
    timeout_seconds: float = Field(default=180, gt=0, le=900)

    @field_validator("base_url")
    @classmethod
    def _local_only(cls, v: str) -> str:
        parts = urlsplit(v)
        if parts.scheme not in ("http", "https") or (parts.hostname or "").lower() not in LOCAL_HOSTS:
            raise ValueError("ollama.base_url must point at this machine (localhost/127.0.0.1)")
        return v


class GroqSettings(_Section):
    enabled: bool = False
    model: str = "llama-3.1-8b-instant"


class GmailSettings(_Section):
    full_sync_days: int = Field(default=7, ge=1, le=90)
    max_messages_per_run: int = Field(default=200, ge=1, le=2000)


class OutlookSettings(_Section):
    enabled: bool = False


class Settings(_Section):
    user_id: str = Field(default="local", pattern=SLUG_PATTERN)
    llm: LLMSettings = LLMSettings()
    ollama: OllamaSettings = OllamaSettings()
    groq: GroqSettings = GroqSettings()
    gmail: GmailSettings = GmailSettings()
    outlook: OutlookSettings = OutlookSettings()

    @model_validator(mode="after")
    def _groq_opt_in(self) -> Settings:
        if self.llm.backend == "groq" and not self.groq.enabled:
            raise ValueError("llm.backend = 'groq' requires groq.enabled = true")
        return self


def home_dir() -> Path:
    override = os.environ.get("MAILWARDEN_HOME")
    return Path(override) if override else platformdirs.user_config_path("mailwarden")


def _template(name: str) -> str:
    return resources.files("mailwarden.templates").joinpath(name).read_text("utf-8")


def init_home(home: Path, *, reset_rules: bool = False) -> list[Path]:
    """Create the home dir (0700) and copy missing config templates (0600).

    ``reset_rules`` replaces sender_rules.yaml with the shipped seed, keeping
    the old file as sender_rules.yaml.bak.
    """
    ensure_private_dir(home)
    created = []
    rules = home / RULES_FILE
    if reset_rules and rules.exists():
        write_private(home / (RULES_FILE + ".bak"), rules.read_text("utf-8"))
        rules.unlink()
    for name in TEMPLATE_FILES:
        target = home / name
        if target.exists():
            continue
        write_private(target, _template(name))
        created.append(target)
    return created


def load_settings(home: Path) -> Settings:
    path = home / CONFIG_FILE
    if not path.exists():
        raise ConfigError(f"{path} not found; run `mailwarden init` first")
    check_private(home)
    check_private(path)
    try:
        with path.open("rb") as f:
            raw = tomllib.load(f)
        return Settings.model_validate(raw)
    except (tomllib.TOMLDecodeError, ValueError) as e:
        raise ConfigError(f"invalid {path}: {e}") from None


def load_sender_rules(home: Path) -> SenderRules:
    path = home / RULES_FILE
    if not path.exists():
        raise ConfigError(f"{path} not found; run `mailwarden init`")
    check_private(path)
    try:
        return SenderRules.from_yaml(path.read_text("utf-8"))
    except RulesError as e:
        raise ConfigError(f"{path}: {e}") from None
