"""Pipeline orchestration: rules -> gate -> (rule classification | redact) -> classify.

Depends only on interfaces. ``triage`` is shared by `run` and `dry-run`, so
dry-run shows exactly what a real run would do.

There is exactly one place an LLM is called for real mail
(``Pipeline.classify_safe``) and it refuses anything that did not pass the
gate as SAFE.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from mailwarden.core import redact, sensitivity_gate
from mailwarden.core.classify.base import LLMBackend, classify_with_retry
from mailwarden.core.models import Category, Classification, FetchedMessage, GateDecision, Stage, Tier
from mailwarden.core.recruiting import (
    SOCIAL_DOMAINS,
    company_from_sender,
    domain_matches,
    is_account_security,
    recruiting_name,
    recruiting_signal,
    recruiting_subdomain,
    stage_from_subject,
)
from mailwarden.core.sender_rules import RuleMatch, SenderRules
from mailwarden.core.sensitivity_gate import GateResult
from mailwarden.core.text import clean

log = logging.getLogger(__name__)


class GateViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class HeldJob:
    """Held-back job mail, described only by locally extracted metadata."""

    company: str | None
    stage: Stage | None


@dataclass(frozen=True)
class Triage:
    #: Effective tier after recruiting overrides.
    tier: Tier
    gate: GateResult
    #: Redacted text an LLM would receive. None means nothing is ever sent.
    llm_text: str | None
    #: Set when the message is classified by a local rule (no LLM call).
    rule_classification: Classification | None = None
    rule_name: str | None = None
    held_job: HeldJob | None = None
    #: The tier sender_rules.yaml gave, before overrides (for dry-run output).
    rule_tier: Tier = Tier.DEFAULT
    override: str | None = None


_RULE_LABELS = {
    Category.NOTIFICATION: "Notification",
    Category.JOB_ALERT: "Job alert",
    Category.NEWSLETTER: "Newsletter",
}


def _rule_classification(category: Category, msg: FetchedMessage) -> Classification:
    sender = clean(msg.sender_name).strip() or msg.sender_domain or "an unknown sender"
    sender = " ".join(sender.split()[:8])[:80]
    return Classification(
        category=category, company=None, role=None, stage=None, action_required=False, deadline=None,
        summary=f"{_RULE_LABELS[category]} from {sender}.",
    )


class Pipeline:
    def __init__(self, rules: SenderRules, *, max_body_chars: int, llm: LLMBackend | None = None) -> None:
        self._rules = rules
        self._max_body_chars = max_body_chars
        self._llm = llm

    @property
    def has_llm(self) -> bool:
        return self._llm is not None

    def _effective_tier(self, msg: FetchedMessage, match: RuleMatch) -> tuple[Tier, str | None]:
        """A recruiting subdomain or sender name overrides a SENSITIVE parent (sender rules only).

        Never for exact-address rules or account-security senders.
        """
        domain = msg.sender_domain
        if match.tier is not Tier.SENSITIVE or match.by_address or not match.entry or is_account_security(domain):
            return match.tier, None
        if recruiting_subdomain(domain, match.entry):
            return Tier.PRIORITY, "recruiting_subdomain"
        if recruiting_name(msg.sender_name):
            return Tier.DEFAULT, "recruiting_name"
        return match.tier, None

    def _held_job(self, msg: FetchedMessage, match: RuleMatch, tier: Tier) -> HeldJob | None:
        domain = msg.sender_domain
        if tier in (Tier.IGNORE, Tier.JOB_ALERT) or is_account_security(domain):
            return None
        eligible = tier is Tier.PRIORITY or (
            recruiting_signal(msg.sender_name, domain) and match.tier is not Tier.SENSITIVE
        )
        if not eligible:
            return None
        return HeldJob(company_from_sender(msg.sender_name, domain), None)

    def triage(self, msg: FetchedMessage) -> Triage:
        try:
            match = self._rules.match(msg.sender_address)
            tier, override = self._effective_tier(msg, match)
        except Exception:
            log.exception("sender rule lookup failed; failing closed")
            return Triage(Tier.DEFAULT, GateResult(GateDecision.SENSITIVE, ("rules_error",)), None)

        gate = sensitivity_gate.evaluate(msg, tier, sender_override=override is not None)
        if gate.sensitive:
            held = None
            try:
                held = self._held_job(msg, match, tier)
                if held is not None:
                    held = HeldJob(held.company, stage_from_subject(msg.subject))
            except Exception:
                log.exception("held-job extraction failed")
            return Triage(tier, gate, None, held_job=held, rule_tier=match.tier, override=override)
        if tier is Tier.IGNORE:
            return Triage(tier, gate, None, rule_tier=match.tier, override=override)

        rule: tuple[Category, str] | None = None
        if domain_matches(msg.sender_domain, SOCIAL_DOMAINS):
            rule = (Category.NOTIFICATION, "social")
        elif tier is Tier.JOB_ALERT:
            rule = (Category.JOB_ALERT, "job_alert_sender")
        elif msg.is_bulk and tier is not Tier.PRIORITY:
            rule = (Category.NEWSLETTER, "bulk_header")
        if rule is not None:
            return Triage(tier, gate, None, rule_classification=_rule_classification(rule[0], msg),
                          rule_name=rule[1], rule_tier=match.tier, override=override)

        try:
            text = redact.for_llm(msg, self._max_body_chars)
        except Exception:
            log.exception("redaction failed; failing closed")
            return Triage(tier, GateResult(GateDecision.SENSITIVE, ("redaction_error",)), None,
                          rule_tier=match.tier, override=override)
        return Triage(tier, gate, text, rule_tier=match.tier, override=override)

    def classify_safe(self, triage: Triage) -> Classification | None:
        """Classify (retrying once on invalid output). None = no LLM or unclassified.

        Raises BackendUnavailable / BackendError from the backend.
        """
        if triage.llm_text is None or self._llm is None:
            return None
        if triage.gate.decision is not GateDecision.SAFE or triage.tier is Tier.IGNORE:
            raise GateViolation("refusing to send non-SAFE mail to an LLM")
        return classify_with_retry(self._llm, triage.llm_text)
