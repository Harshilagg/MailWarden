"""Domain models shared by every stage.

Two kinds of message model exist on purpose:

* ``FetchedMessage`` is transient. It carries the subject and body and must
  never be persisted or logged. Its repr hides both fields.
* ``EmailMeta`` is what gets stored. It has no body and no subject.
"""

from __future__ import annotations

import datetime as dt
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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
    JOB_ALERT = "job_alert"
    DEFAULT = "default"


class GateDecision(StrEnum):
    SAFE = "safe"
    SENSITIVE = "sensitive"


class MessageStatus(StrEnum):
    DONE = "done"  # fully processed (classified, or deliberately not classified)
    UNCLASSIFIED = "unclassified"  # LLM output invalid twice
    PENDING = "pending"  # not yet processed (backend down, fetch failed, over run cap)


class Category(StrEnum):
    JOB = "job"
    JOB_ALERT = "job_alert"
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
    #: False if any part of the content could not be parsed (gate fails closed).
    content_complete: bool = True
    #: True if the message carries List-Unsubscribe or Precedence: bulk/list/junk.
    is_bulk: bool = False
    #: Visible HTML anchors as (text, url). Transient, like the body.
    links: tuple[tuple[str, str], ...] = Field(default=(), repr=False)

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
        """Drop subject, body and links from memory once they are no longer needed."""
        self.subject = ""
        self.body_text = ""
        self.links = ()


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
    """What is persisted about a message. Deliberately has no body or subject.

    For SENSITIVE mail only the sender display name, received time and
    account are kept: sender_address and classification must be None.
    """

    user_id: str
    account: str
    message_id: str
    sender_address: str | None
    sender_name: str
    received_at: dt.datetime
    tier: Tier
    gate: GateDecision
    status: MessageStatus = MessageStatus.DONE
    classification: Classification | None = None
    #: How it was classified: "llm", "rule:<name>", or None.
    classified_by: str | None = None
    #: Friendly, content-free reason a SENSITIVE message was held back.
    held_reason: str | None = None
    #: Held-back job mail surfaced to the user (company/stage from local rules only).
    held_job: bool = False
    held_company: str | None = Field(default=None, max_length=200)
    held_stage: Stage | None = None
    held_deadline: dt.date | None = None
    dismissed: bool = False
    #: Set the first time the message counts as urgent. Pinned: only the user's "Done"
    #: (dismissed) removes it from Urgent, even if it is later reclassified.
    urgent_since: dt.datetime | None = None

    @model_validator(mode="after")
    def _sensitive_is_minimal(self) -> EmailMeta:
        if self.gate is GateDecision.SENSITIVE and (self.sender_address or self.classification):
            raise ValueError("SENSITIVE mail may only store sender name, time, account and local job metadata")
        if self.held_job and self.gate is not GateDecision.SENSITIVE:
            raise ValueError("held_job is only for SENSITIVE mail")
        return self


class Application(_Frozen):
    user_id: str
    company: str = Field(max_length=200)
    role: str | None = Field(default=None, max_length=200)
    current_stage: Stage
    last_update: dt.datetime
    source_message_ids: tuple[str, ...] = ()


class JobPost(BaseModel):
    """One job listed in a job-alert email."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    title: str = Field(min_length=2, max_length=200)
    company: str | None = Field(default=None, max_length=200)
    location: str | None = Field(default=None, max_length=200)
    #: http(s) only; validated before storing or rendering.
    link: str | None = Field(default=None, max_length=2000)
    #: Listing details shown in the alert (experience range, skill tags, stipend ...).
    details: str | None = Field(default=None, max_length=500)


class StoredJob(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    id: int
    user_id: str
    title: str
    company: str | None
    location: str | None
    link: str | None
    sender: str
    account: str
    message_id: str
    received_at: dt.datetime
    dismissed: bool = False
    details: str | None = None
    #: The latest time any alert showed this job (None: only the first sighting is known).
    last_seen_at: dt.datetime | None = None
    #: Your quick check of the experience level on the dashboard: "fresher" | "senior" | None.
    experience_check: str | None = None
    source_type: str | None = None
    source_name: str | None = None
    #: Other sources the same job was seen on (names), in order.
    also_on: tuple[str, ...] = ()
    # job description: status None (not tried) | "ok" | "unavailable" | "closed" (posting removed)
    jd_status: str | None = None
    jd_reason: str | None = None
    jd_source: str | None = None  # "api:greenhouse", "fetch:<host>", "paste"
    jd_text: str | None = None
    jd_fetched_at: dt.datetime | None = None
    # fit score (level "preliminary" from alert content, "full" from a job description)
    score: float | None = None
    score_level: str | None = None
    matched_skills: tuple[str, ...] = ()
    missing_skills: tuple[str, ...] = ()
    evidence: tuple[tuple[str, tuple[str, ...]], ...] = ()
    best_project: str | None = None
    why: str | None = None
    score_hash: str | None = None


class JobAudit(BaseModel):
    """One recall-audit answer: would you apply to a job that Apply today left out, and why it was left out."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    job_id: int
    answer: str  # "apply" | "no"
    findings: tuple[dict, ...] = ()  # core.recall.Finding.to_dict(), as shown at audit time
    score: float | None = None
    score_level: str | None = None
    audited_at: dt.datetime
