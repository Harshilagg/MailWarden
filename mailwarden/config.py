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
    # Local token bucket. Groq free tier: 8K tokens/min at ~1.1K tokens per email -> ~6/min.
    max_llm_calls_per_minute: int = Field(default=6, ge=1, le=600)
    # Anything beyond this stays pending for the next run.
    max_llm_calls_per_run: int = Field(default=150, ge=1, le=5000)
    # Estimated tokens per minute (prompt + answer). Groq free tier allows 8,000/min.
    max_llm_tokens_per_minute: int = Field(default=7000, ge=500, le=10_000_000)


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
    # Code default stays opt-in: a missing/partial config never sends data to the cloud.
    enabled: bool = False
    model: str = "openai/gpt-oss-20b"
    reasoning_effort: Literal["low", "medium", "high"] = "low"
    # Optional extra spacing between calls; pacing is done by [llm] max_llm_calls_per_minute.
    min_interval_seconds: float = Field(default=0, ge=0, le=60)
    timeout_seconds: float = Field(default=60, gt=0, le=300)


class GmailSettings(_Section):
    full_sync_days: int = Field(default=7, ge=1, le=90)
    max_messages_per_run: int = Field(default=200, ge=1, le=2000)


class OutlookSettings(_Section):
    enabled: bool = False


class DashboardSettings(_Section):
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1024, le=65535)

    @field_validator("host")
    @classmethod
    def _loopback_only(cls, v: str) -> str:
        if v != "127.0.0.1":
            raise ValueError("dashboard.host must be 127.0.0.1 (the dashboard never listens on other interfaces)")
        return v


class NotificationSettings(_Section):
    enabled: bool = True
    # auto: macOS -> the mailwarden app itself (after `mailwarden launcher`), else
    #       terminal-notifier if installed, else osascript; Linux/Windows -> desktop-notifier.
    backend: Literal["auto", "app", "terminal-notifier", "osascript", "desktop-notifier", "none"] = "auto"
    # desktop-notifier only: keep the process alive this long so a click can open the dashboard.
    click_wait_seconds: float = Field(default=0, ge=0, le=600)


class JobAlertSettings(_Section):
    # A job matches when its title contains a keyword AND (its location matches, or is unknown).
    target_keywords: list[str] = ["software engineer", "backend", "full stack", "sde"]
    target_locations: list[str] = ["Bengaluru", "Remote"]
    # At most one "N new jobs match your filters" notification per day (sent with the digest).
    daily_notification: bool = True
    # Automatically fetch job descriptions for candidates hosted on Greenhouse, Lever or Ashby,
    # through their public job-board APIs (fixed hosts, no cookies, cached 7 days).
    jd_auto_fetch: bool = True
    # The "Fetch job description" buttons (you click them). Allowlisted hiring systems only:
    # Greenhouse, Lever, Ashby, Workday, SmartRecruiters, SuccessFactors/jobs2web. Opt-in.
    jd_button_fetch: bool = False
    max_jd_fetches_per_run: int = Field(default=30, ge=0, le=500)
    # Fit scores computed per run (each is one LLM call; shares the LLM rate limit).
    max_scores_per_run: int = Field(default=40, ge=0, le=1000)


class DigestSettings(_Section):
    times: list[str] = ["08:00", "18:00"]
    # Optional folder for a Markdown copy of each digest (created 0700, files 0600). Empty = off.
    markdown_dir: str = ""

    @field_validator("times")
    @classmethod
    def _hhmm(cls, v: list[str]) -> list[str]:
        for t in v:
            h, _, m = t.partition(":")
            if not (h.isdigit() and m.isdigit() and 0 <= int(h) <= 23 and 0 <= int(m) <= 59 and len(m) == 2):
                raise ValueError(f"digest time {t!r} must be HH:MM")
        if not v:
            raise ValueError("at least one digest time is required")
        return v


class Settings(_Section):
    user_id: str = Field(default="local", pattern=SLUG_PATTERN)
    llm: LLMSettings = LLMSettings()
    ollama: OllamaSettings = OllamaSettings()
    groq: GroqSettings = GroqSettings()
    gmail: GmailSettings = GmailSettings()
    outlook: OutlookSettings = OutlookSettings()
    dashboard: DashboardSettings = DashboardSettings()
    notifications: NotificationSettings = NotificationSettings()
    digest: DigestSettings = DigestSettings()
    job_alerts: JobAlertSettings = JobAlertSettings()

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
