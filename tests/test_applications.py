import datetime as dt

import pytest

from mailwarden.core.alerts import should_alert
from mailwarden.core.applications import company_key, next_stage
from mailwarden.core.models import Category, Classification, Stage


@pytest.mark.parametrize(
    "current, new, expected",
    [
        (Stage.APPLIED, Stage.INTERVIEW, Stage.INTERVIEW),
        (Stage.INTERVIEW, Stage.APPLIED, Stage.INTERVIEW),  # late confirmation doesn't regress
        (Stage.INTERVIEW, Stage.REJECTION, Stage.REJECTION),
        (Stage.REJECTION, Stage.APPLIED, Stage.REJECTION),  # terminal
        (Stage.OFFER, Stage.INTERVIEW, Stage.OFFER),
        (Stage.ASSESSMENT, Stage.OTHER, Stage.ASSESSMENT),
        (Stage.ASSESSMENT, None, Stage.ASSESSMENT),
    ],
)
def test_next_stage(current, new, expected):
    assert next_stage(current, new) is expected


def test_company_key_normalises():
    assert company_key("Acme Technologies Pvt. Ltd.") == company_key("ACME") == "acme"


def _c(**kw):
    base = dict(category=Category.JOB, company="Acme", role=None, stage=Stage.APPLIED,
                action_required=False, deadline=None, summary="s")
    return Classification(**{**base, **kw})


@pytest.mark.parametrize(
    "c, known, priority, expected",
    [
        (_c(), False, False, False),
        (_c(stage=Stage.ASSESSMENT), False, False, True),
        (_c(stage=Stage.INTERVIEW), False, False, True),
        (_c(stage=Stage.OFFER), False, False, True),
        (_c(stage=Stage.REJECTION), True, True, False),
        # action_required only counts for tracked companies or PRIORITY senders
        (_c(action_required=True), False, False, False),
        (_c(action_required=True), True, False, True),
        (_c(action_required=True), False, True, True),
        (_c(category=Category.JOB_ALERT, stage=None, action_required=True), True, True, False),
        (_c(category=Category.NEWSLETTER, stage=None, action_required=True), True, True, False),
        (None, True, True, False),
    ],
)
def test_should_alert(c, known, priority, expected):
    assert should_alert(c, known_company=known, priority_sender=priority) is expected
