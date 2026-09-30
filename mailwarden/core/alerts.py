"""Which classified mail deserves an immediate notification."""

from __future__ import annotations

from mailwarden.core.models import Category, Classification, Stage

ALERT_STAGES = frozenset({Stage.ASSESSMENT, Stage.INTERVIEW, Stage.OFFER})


def should_alert(c: Classification | None) -> bool:
    if c is None or c.category is not Category.JOB:
        return False
    return c.action_required or c.stage in ALERT_STAGES
