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
from mailwarden.core.classify.base import InvalidOutput, LLMBackend, classify_with_retry, tidy_model_text
from mailwarden.core.job_alerts import extract_locally, link_listing, parse_llm_jobs
from mailwarden.core.models import Category, Classification, FetchedMessage, GateDecision, JobPost, Stage, Tier
from mailwarden.core.recruiting import (
    ATS_DOMAINS,
    JOB_BOARD_DOMAINS,
    RELAY_DOMAINS,
    company_from_local_part,
    SOCIAL_DOMAINS,
    company_from_sender,
    domain_matches,
    is_account_security,
    is_government,
    looks_like_job_alert,
    recruiting_markers,
    recruiting_name,
    recruiting_signal,
    recruiting_subdomain,
    sender_label,
    stage_from_subject,
    strong_recruiting,
)
from mailwarden.core.sender_rules import RuleMatch, SenderRules
from mailwarden.core.sensitivity_gate import GateResult, hard_reasons
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
    #: Human label for the sender (never "Unknown sender").
    sender: str = ""


_RULE_LABELS = {
    Category.NOTIFICATION: "Notification",
    Category.JOB_ALERT: "Job alert",
    Category.NEWSLETTER: "Newsletter",
}


def _rule_classification(category: Category, msg: FetchedMessage) -> Classification:
    sender = " ".join(sender_label(msg.sender_name, msg.sender_address).split()[:8])[:80]
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
        return HeldJob(company_from_sender(msg.sender_name, domain, msg.sender_address), None)

    def triage(self, msg: FetchedMessage) -> Triage:
        try:
            match = self._rules.match(msg.sender_address)
            tier, override = self._effective_tier(msg, match)
        except Exception:
            log.exception("sender rule lookup failed; failing closed")
            return Triage(Tier.DEFAULT, GateResult(GateDecision.SENSITIVE, ("rules_error",)), None)

        label = sender_label(msg.sender_name, msg.sender_address)
        base = {"rule_tier": match.tier, "override": override, "sender": label}
        gate = sensitivity_gate.evaluate(msg, tier, sender_override=override is not None)
        if gate.sensitive:
            gate, tier = self._maybe_waive(msg, gate, match, tier)
        if gate.sensitive:
            held = None
            try:
                held = self._held_job(msg, match, tier)
                if held is not None:
                    held = HeldJob(held.company, stage_from_subject(msg.subject))
            except Exception:
                log.exception("held-job extraction failed")
            return Triage(tier, gate, None, held_job=held, **base)
        if tier is Tier.IGNORE:
            return Triage(tier, gate, None, **base)

        rule: tuple[Category, str] | None = None
        domain = msg.sender_domain
        if domain_matches(domain, SOCIAL_DOMAINS):
            rule = (Category.NOTIFICATION, "social")
        elif tier is Tier.JOB_ALERT:
            rule = (Category.JOB_ALERT, "job_alert_sender")
        elif looks_like_job_alert(msg.subject, msg.body_text) and (
            tier is Tier.PRIORITY
            or domain_matches(domain, JOB_BOARD_DOMAINS | ATS_DOMAINS)
            or recruiting_signal(msg.sender_name, domain)
        ):
            rule = (Category.JOB_ALERT, "job_alert_phrase")
        elif msg.is_bulk and tier is not Tier.PRIORITY:
            rule = (Category.NEWSLETTER, "bulk_header")
        if rule is not None:
            return Triage(tier, gate, None, rule_classification=_rule_classification(rule[0], msg),
                          rule_name=rule[1], **base)

        try:
            text = redact.for_llm(msg, self._max_body_chars)
        except Exception:
            log.exception("redaction failed; failing closed")
            return Triage(tier, GateResult(GateDecision.SENSITIVE, ("redaction_error",)), None, **base)
        return Triage(tier, gate, text, **base)

    def _maybe_waive(self, msg: FetchedMessage, gate: GateResult, match: RuleMatch, tier: Tier) -> tuple[GateResult, Tier]:
        """Waive a hold made only of SOFT rules when the mail carries strong recruiting markers.

        Any HARD rule (codes, transactions, account/card numbers, ID numbers, errors,
        security alerts from account-security senders, government / account-security
        sender tiers) keeps it held.
        """
        try:
            domain = msg.sender_domain
            security = is_account_security(domain)
            hard_tier = match.tier is Tier.SENSITIVE and (security or is_government(domain))
            if hard_reasons(gate, security_sender=security, hard_sender_tier=hard_tier):
                return gate, tier
            # A bank/payments sender needs strong evidence: an ATS relay or a subject phrase.
            strict = match.tier is Tier.SENSITIVE
            markers = recruiting_markers(domain, msg.subject, msg.body_text)
            if not strong_recruiting(markers, strict=strict):
                return gate, tier
            new_tier = Tier.PRIORITY if tier in (Tier.SENSITIVE, Tier.DEFAULT) and match.tier is Tier.SENSITIVE else tier
            return GateResult(GateDecision.SAFE, (), waived=gate.reasons), new_tier
        except Exception:
            log.exception("soft-rule waiver failed; keeping the hold")
            return gate, tier

    def classify_safe(self, triage: Triage) -> Classification | None:
        """Classify (retrying once on invalid output). None = no LLM or unclassified.

        Raises BackendUnavailable / BackendError from the backend.
        """
        if triage.llm_text is None or self._llm is None:
            return None
        if triage.gate.decision is not GateDecision.SAFE or triage.tier is Tier.IGNORE:
            raise GateViolation("refusing to send non-SAFE mail to an LLM")
        return classify_with_retry(self._llm, triage.llm_text)

    def extract_jobs_safe(self, triage: Triage, msg: FetchedMessage) -> list[JobPost]:
        """Jobs listed in a SAFE job-alert email: local parsers, then (optionally) the LLM.

        Raises BackendUnavailable from the backend.
        """
        if triage.gate.decision is not GateDecision.SAFE or triage.tier is Tier.IGNORE:
            raise GateViolation("refusing to extract jobs from non-SAFE mail")
        default_company = None
        if domain_matches(msg.sender_domain, RELAY_DOMAINS):
            default_company = company_from_local_part(msg.sender_address)
        posts = extract_locally(msg.body_text, msg.links, default_company=default_company)
        if posts or self._llm is None:
            return posts
        body = redact.for_llm(msg, min(self._max_body_chars * 3, 6000))
        listing, mapping = link_listing(msg.links, redact.redact_text)
        text = f"{body}\n\nLinks:\n{listing}" if listing else body
        for _ in (1, 2):
            try:
                return parse_llm_jobs(self._llm.extract_jobs(text), mapping, tidy_model_text)
            except (InvalidOutput, ValueError):
                continue
            except NotImplementedError:
                return []
        return []
