"""Keep the applications table in step with classified job mail."""

from __future__ import annotations

import datetime as dt
import re

from mailwarden.core.models import Application, Category, Classification, Stage
from mailwarden.storage.base import Repository

# Progress order. Rejection and offer are terminal; "other" never moves a stage.
_RANK = {Stage.APPLIED: 1, Stage.ASSESSMENT: 2, Stage.INTERVIEW: 3, Stage.OFFER: 4, Stage.REJECTION: 4}
_SUFFIXES = re.compile(
    r"\b(?:inc|llc|ltd|limited|pvt|private|corp|corporation|co|company|gmbh|plc|technologies|labs)\b\.?"
)
FREEMAIL = frozenset(
    {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
     "yahoo.co.in", "icloud.com", "me.com", "proton.me", "protonmail.com", "rediffmail.com"}
)


def company_key(name: str) -> str:
    key = _SUFFIXES.sub(" ", name.lower())
    return re.sub(r"[^a-z0-9]+", " ", key).strip()


def role_key(role: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (role or "").lower()).strip()


def next_stage(current: Stage, new: Stage | None) -> Stage:
    if new is None or new is Stage.OTHER:
        return current
    if current in (Stage.OFFER, Stage.REJECTION):
        return current  # terminal: a late "thanks for applying" must not reopen it
    return new if _RANK.get(new, 0) >= _RANK.get(current, 0) else current


def is_known_company(repo: Repository, user_id: str, company: str | None) -> bool:
    key = company_key(company or "")
    return bool(key) and repo.find_application(user_id, key, "") is not None


def record_job_event(
    repo: Repository,
    user_id: str,
    *,
    company: str | None,
    role: str | None,
    stage: Stage | None,
    account: str,
    message_id: str,
    received_at: dt.datetime,
    domain: str | None,
) -> Application | None:
    """Create or advance an application from one job email's metadata."""
    if not company or stage is None:
        return None
    ckey = company_key(company)
    if not ckey:
        return None
    existing = repo.find_application(user_id, ckey, role_key(role))
    if existing is None and stage is Stage.OTHER:
        return None
    if existing is None:
        app = Application(
            user_id=user_id,
            company=company.strip()[:200],
            role=role or None,
            current_stage=stage,
            last_update=received_at,
            source_message_ids=(message_id,),
        )
    else:
        if message_id in existing.source_message_ids:
            return existing
        app = existing.model_copy(
            update={
                "role": existing.role or role,
                "current_stage": next_stage(existing.current_stage, stage),
                "last_update": max(existing.last_update, received_at),
                "source_message_ids": (*existing.source_message_ids, message_id),
            }
        )
    repo.upsert_application(app, event_stage=stage, account=account, message_id=message_id,
                            occurred_at=received_at, domain=domain)
    return app


def company_domain(sender_domain: str, *, via_ats: bool) -> str | None:
    """A company's own domain (not an ATS, job board or freemail) becomes a PRIORITY domain."""
    if via_ats or not sender_domain or sender_domain in FREEMAIL:
        return None
    return sender_domain


def update_applications(
    repo: Repository,
    user_id: str,
    c: Classification | None,
    *,
    account: str,
    message_id: str,
    received_at: dt.datetime,
    sender_domain: str,
    via_ats: bool,
) -> Application | None:
    if c is None or c.category is not Category.JOB:
        return None
    return record_job_event(
        repo, user_id, company=c.company, role=c.role, stage=c.stage, account=account,
        message_id=message_id, received_at=received_at, domain=company_domain(sender_domain, via_ats=via_ats),
    )
