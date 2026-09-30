"""Which mail deserves an immediate notification."""

from __future__ import annotations

from mailwarden.core.models import Category, Classification, Stage, Tier

ALERT_STAGES = frozenset({Stage.ASSESSMENT, Stage.INTERVIEW, Stage.OFFER})


def should_alert(c: Classification | None, *, known_company: bool, priority_sender: bool) -> bool:
    """category == job AND (stage in {assessment, interview, offer}
    OR (action_required AND (company already tracked OR sender is PRIORITY)))."""
    if c is None or c.category is not Category.JOB:
        return False
    if c.stage in ALERT_STAGES:
        return True
    return c.action_required and (known_company or priority_sender)


def priority_safety_net(c: Classification | None, *, tier: Tier, assessment_platform: bool) -> Classification | None:
    """Mail from a PRIORITY (job) sender that needs action or has a deadline is job mail.

    Guards against the model filing, say, a hiring-challenge registration as a job
    alert or newsletter, which would otherwise keep it out of Urgent.
    """
    if c is None or tier is not Tier.PRIORITY or c.category is Category.JOB:
        return c
    if not (c.action_required or c.deadline):
        return c
    stage = Stage.ASSESSMENT if assessment_platform else Stage.OTHER
    return c.model_copy(update={"category": Category.JOB, "stage": stage, "action_required": True})
