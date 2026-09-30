"""Domain models shared by every stage.

Two kinds of message model exist on purpose:

* ``FetchedMessage`` is transient. It carries the subject and body and must
  never be persisted or logged. Its repr hides both fields.
* ``EmailMeta`` is what gets stored. It has no body and no subject.
"""

from __future__ import annotations

import datetime as dt
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Identifiers end up in keyring keys and DB rows, so keep them boring.
SLUG_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,31}$"
SUMMARY_MAX_WORDS = 25


class _Frozen(BaseModel):
    # hide_input_in_errors: validation errors must never echo email content.
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class ProviderKind(StrEnum):
    GMAIL = "gmail"
    OUTLOOK = "outlook"


class Tier(StrEnum):
    PRIORITY = "priority"
    SENSITIVE = "sensitive"
    IGNORE = "ignore"
    DEFAULT = "default"


class GateDecision(StrEnum):
    SAFE = "safe"
    SENSITIVE = "sensitive"


class Category(StrEnum):
    JOB = "job"
    PERSONAL = "personal"
    NEWSLETTER = "newsletter"
    NOTIFICATION = "notification"
    OTHER = "other"


class Stage(StrEnum):
    APPLIED = "applied"
    ASSESSMENT = "assessment"
    INTERVIEW = "interview"
    OFFER = "offer"
    REJECTION = "rejection"
    OTHER = "other"


class Account(_Frozen):
    user_id: str = Field(pattern=SLUG_PATTERN)
    name: str = Field(pattern=SLUG_PATTERN)
    provider: ProviderKind
    address: str = Field(max_length=320)


class FetchedMessage(BaseModel):
    """A message as fetched from a provider. Transient: holds the body."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    user_id: str
    account: str
    message_id: str
    thread_id: str | None = None
    sender_address: str
    sender_name: str
    subject: str = Field(repr=False)
    body_text: str = Field(repr=False)
    received_at: dt.datetime
    label_ids: tuple[str, ...] = ()

    @field_validator("received_at")
    @classmethod
    def _aware(cls, v: dt.datetime) -> dt.datetime:
        if v.tzinfo is None:
            raise ValueError("received_at must be timezone-aware")
        return v

    @property
    def sender_domain(self) -> str:
        _, _, domain = self.sender_address.rpartition("@")
        return domain.lower()

    def discard_content(self) -> None:
        """Drop subject and body from memory once they are no longer needed."""
        self.subject = ""
        self.body_text = ""


class Classification(_Frozen):
    """The only shape of LLM output the code will ever accept."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)

    category: Category
    company: str | None = Field(default=None, max_length=200)
    role: str | None = Field(default=None, max_length=200)
    stage: Stage | None = None
    action_required: bool
    deadline: dt.date | None = None
    summary: str = Field(max_length=300)

    @field_validator("summary")
    @classmethod
    def _short(cls, v: str) -> str:
        if len(v.split()) > SUMMARY_MAX_WORDS:
            raise ValueError(f"summary exceeds {SUMMARY_MAX_WORDS} words")
        return v


class EmailMeta(_Frozen):
    """What is persisted about a message. Deliberately has no body or subject."""

    user_id: str
    account: str
    message_id: str
    sender_address: str
    sender_name: str
    received_at: dt.datetime
    tier: Tier
    gate: GateDecision
    classification: Classification | None = None


class Application(_Frozen):
    user_id: str
    company: str = Field(max_length=200)
    role: str | None = Field(default=None, max_length=200)
    current_stage: Stage
    last_update: dt.datetime
    source_message_ids: tuple[str, ...] = ()
