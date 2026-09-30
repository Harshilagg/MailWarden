"""What the user should see: urgent job items and the digest. Pure functions over stored metadata."""

from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from dataclasses import asdict, dataclass, field

from mailwarden.core.alerts import ALERT_STAGES
from mailwarden.core.models import Category, EmailMeta, GateDecision, Stage, Tier

CATEGORY_ORDER = (Category.JOB, Category.PERSONAL, Category.NOTIFICATION, Category.OTHER,
                  Category.NEWSLETTER, Category.JOB_ALERT)
CATEGORY_TITLES = {
    Category.JOB: "Job mail", Category.PERSONAL: "Personal", Category.NOTIFICATION: "Notifications",
    Category.OTHER: "Other", Category.NEWSLETTER: "Newsletters", Category.JOB_ALERT: "Job alerts",
}


@dataclass(frozen=True)
class UrgentItem:
    account: str
    message_id: str
    sender_name: str
    received_at: dt.datetime
    company: str | None
    stage: Stage | None
    deadline: dt.date | None
    #: One-line summary for classified mail; None for held-back mail.
    summary: str | None
    held: bool
    #: Friendly reason for held-back mail.
    held_reason: str | None


def is_urgent(m: EmailMeta) -> bool:
    if m.dismissed:
        return False
    if m.held_job:
        return True
    c = m.classification
    if c is None or c.category is not Category.JOB or c.stage is Stage.REJECTION:
        return False
    return c.action_required or c.stage in ALERT_STAGES


def urgent_items(metas: list[EmailMeta]) -> list[UrgentItem]:
    items = []
    for m in metas:
        if not is_urgent(m):
            continue
        c = m.classification
        items.append(
            UrgentItem(
                account=m.account, message_id=m.message_id, sender_name=m.sender_name, received_at=m.received_at,
                company=c.company if c else m.held_company, stage=c.stage if c else m.held_stage,
                deadline=c.deadline if c else None, summary=c.summary if c else None,
                held=m.held_job, held_reason=m.held_reason,
            )
        )
    far = dt.date.max
    return sorted(items, key=lambda i: (i.deadline or far, -i.received_at.timestamp()))


@dataclass
class DigestEntry:
    account: str
    message_id: str
    sender: str
    summary: str
    received_at: str  # ISO


@dataclass
class Digest:
    generated_at: str
    period_start: str
    urgent: int = 0
    sections: dict[str, list[DigestEntry]] = field(default_factory=dict)
    sensitive_by_sender: dict[str, int] = field(default_factory=dict)
    ignored: int = 0
    unclassified: int = 0

    @property
    def total(self) -> int:
        return (sum(len(v) for v in self.sections.values()) + sum(self.sensitive_by_sender.values())
                + self.ignored + self.unclassified)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, text: str) -> Digest:
        raw = json.loads(text)
        sections = {k: [DigestEntry(**e) for e in v] for k, v in raw.pop("sections").items()}
        return cls(sections=sections, **raw)


def build_digest(metas: list[EmailMeta], *, now: dt.datetime, period_start: dt.datetime) -> Digest:
    digest = Digest(generated_at=now.isoformat(), period_start=period_start.isoformat())
    sensitive: Counter[str] = Counter()
    sections: dict[Category, list[DigestEntry]] = {c: [] for c in CATEGORY_ORDER}
    for m in sorted(metas, key=lambda m: m.received_at, reverse=True):
        if not (period_start <= m.received_at <= now):
            continue
        if m.gate is GateDecision.SENSITIVE:
            sensitive[m.sender_name or "Unknown sender"] += 1
            if is_urgent(m):
                digest.urgent += 1
            continue
        if is_urgent(m):
            digest.urgent += 1
            continue  # urgent items live in the Urgent view, not the digest
        if m.tier is Tier.IGNORE:
            digest.ignored += 1
            continue
        if m.classification is None:
            digest.unclassified += 1
            continue
        sections[m.classification.category].append(
            DigestEntry(m.account, m.message_id, m.sender_name or "Unknown sender", m.classification.summary,
                        m.received_at.isoformat())
        )
    digest.sections = {c.value: entries for c, entries in sections.items() if entries}
    digest.sensitive_by_sender = dict(sensitive.most_common())
    return digest


def digest_markdown(d: Digest) -> str:
    """Markdown copy: summaries only, no links, no subjects, no sensitive content."""
    when = dt.datetime.fromisoformat(d.generated_at).astimezone()
    lines = [f"# mailwarden digest: {when:%a, %d %b %Y %H:%M}", ""]
    if d.urgent:
        lines += [f"**{d.urgent} job item(s) need your attention**: see the dashboard's Urgent view.", ""]
    for key, entries in d.sections.items():
        lines.append(f"## {CATEGORY_TITLES[Category(key)]} ({len(entries)})")
        lines += [f"- **{e.sender}**: {e.summary}" for e in entries]
        lines.append("")
    if d.sensitive_by_sender:
        total = sum(d.sensitive_by_sender.values())
        lines.append(f"## {total} sensitive email(s) (not processed)")
        lines += [f"- {name}: {count}" for name, count in d.sensitive_by_sender.items()]
        lines.append("")
    if d.ignored:
        lines += [f"{d.ignored} ignored email(s).", ""]
    if d.unclassified:
        lines += [f"{d.unclassified} email(s) could not be classified.", ""]
    return "\n".join(lines).rstrip() + "\n"
