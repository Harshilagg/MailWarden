"""Pipeline orchestration: rules -> gate -> redact -> (classify).

Depends only on interfaces. ``triage`` is shared by `run` and `dry-run`, so
dry-run shows exactly what a real run would send.

There is exactly one place an LLM is called (``Pipeline.classify``) and it
refuses anything that did not pass the gate as SAFE.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from mailwarden.core import redact, sensitivity_gate
from mailwarden.core.classify.base import LLMBackend
from mailwarden.core.models import Classification, FetchedMessage, GateDecision, Tier
from mailwarden.core.sender_rules import SenderRules
from mailwarden.core.sensitivity_gate import GateResult

log = logging.getLogger(__name__)


class GateViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class Triage:
    tier: Tier
    gate: GateResult
    #: Redacted text an LLM would receive. None means nothing is ever sent.
    llm_text: str | None


class Pipeline:
    def __init__(self, rules: SenderRules, *, max_body_chars: int, llm: LLMBackend | None = None) -> None:
        self._rules = rules
        self._max_body_chars = max_body_chars
        self._llm = llm

    def triage(self, msg: FetchedMessage) -> Triage:
        try:
            tier = self._rules.tier_for(msg.sender_address)
        except Exception:
            log.exception("sender rule lookup failed; failing closed")
            return Triage(Tier.DEFAULT, GateResult(GateDecision.SENSITIVE, ("rules_error",)), None)

        gate = sensitivity_gate.evaluate(msg, tier)
        if gate.sensitive or tier is Tier.IGNORE:
            return Triage(tier, gate, None)
        try:
            text = redact.for_llm(msg, self._max_body_chars)
        except Exception:
            log.exception("redaction failed; failing closed")
            return Triage(tier, GateResult(GateDecision.SENSITIVE, ("redaction_error",)), None)
        return Triage(tier, gate, text)

    def classify(self, triage: Triage) -> Classification | None:
        if triage.llm_text is None or self._llm is None:
            return None
        if triage.gate.decision is not GateDecision.SAFE or triage.tier is Tier.IGNORE:
            raise GateViolation("refusing to send non-SAFE mail to an LLM")
        return self._llm.classify(triage.llm_text)
