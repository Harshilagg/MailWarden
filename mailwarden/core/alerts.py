"""Which mail deserves an immediate notification."""

from __future__ import annotations

from mailwarden.core.models import Category, Classification, Stage

ALERT_STAGES = frozenset({Stage.ASSESSMENT, Stage.INTERVIEW, Stage.OFFER})


def should_alert(c: Classification | None, *, known_company: bool, priority_sender: bool) -> bool:
    """category == job AND (stage in {assessment, interview, offer}
    OR (action_required AND (company already tracked OR sender is PRIORITY)))."""
    if c is None or c.category is not Category.JOB:
        return False
    if c.stage in ALERT_STAGES:
        return True
    return c.action_required and (known_company or priority_sender)
