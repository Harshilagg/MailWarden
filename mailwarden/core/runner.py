"""One sync + classify pass over every account. Depends only on interfaces.

Idempotent: processed messages are skipped. Anything that cannot be finished
now (fetch failure, LLM unavailable, per-run LLM cap, per-run message cap) is
recorded as pending and retried next run, so the sync cursor can always advance.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from mailwarden.core.alerts import should_alert
from mailwarden.core.applications import company_domain, is_known_company, record_job_event
from mailwarden.core.classify.base import BackendUnavailable, LLMBackend
from mailwarden.core.models import Account, Category, EmailMeta, GateDecision, MessageStatus, Tier
from mailwarden.core.pipeline import Pipeline, Triage
from mailwarden.core.reasons import friendly_reason
from mailwarden.core.sender_rules import SenderRules
from mailwarden.delivery.base import JobAlert, Notifier
from mailwarden.providers.base import MailProvider, ProviderError
from mailwarden.storage.base import Repository

log = logging.getLogger(__name__)


@dataclass
class RunStats:
    accounts_failed: list[str] = field(default_factory=list)
    new: int = 0
    sensitive: int = 0
    held_jobs: int = 0
    ignored: int = 0
    rule_classified: int = 0
    classified: int = 0
    unclassified: int = 0
    pending: int = 0
    job: int = 0
    near_empty: int = 0
    alerts: list[JobAlert] = field(default_factory=list)


class Runner:
    def __init__(
        self,
        *,
        user_id: str,
        repo: Repository,
        rules: SenderRules,
        llm: LLMBackend,
        provider_for: Callable[[Account], MailProvider],
        max_body_chars: int,
        max_per_run: int,
        notifier: Notifier | None = None,
    ) -> None:
        self._user_id = user_id
        self._repo = repo
        self._rules = rules
        self._llm = llm
        self._provider_for = provider_for
        self._max_body_chars = max_body_chars
        self._max_per_run = max_per_run
        self._notifier = notifier
        self._llm_ok = True

    def run(self, accounts: list[Account]) -> RunStats:
        stats = RunStats()
        # Company domains from tracked applications count as PRIORITY senders.
        rules = self._rules.with_priority_domains(self._repo.application_domains(self._user_id))
        pipeline = Pipeline(rules, max_body_chars=self._max_body_chars, llm=self._llm)
        for account in accounts:
            try:
                self._run_account(account, pipeline, stats)
            except ProviderError as e:
                log.error("account %s failed: %s", account.name, e)
                stats.accounts_failed.append(account.name)
        if stats.near_empty:
            log.debug("%d messages had an empty or near-empty body after extraction", stats.near_empty)
        return stats

    def _run_account(self, account: Account, pipeline: Pipeline, stats: RunStats) -> None:
        provider = self._provider_for(account)
        uid, name = self._user_id, account.name
        result = provider.list_new(account, self._repo.get_sync_cursor(uid, name))
        queue = [
            mid
            for mid in dict.fromkeys([*self._repo.list_pending(uid, name, self._max_per_run), *result.message_ids])
            if not self._repo.is_processed(uid, name, mid)
        ]
        todo, overflow = queue[: self._max_per_run], queue[self._max_per_run :]
        self._repo.mark_pending(uid, name, overflow)
        stats.pending += len(overflow)

        log.info("account %s: %d messages to process", name, len(todo))
        for n, message_id in enumerate(todo, 1):
            self._process(account, provider, pipeline, message_id, stats)
            if n % 10 == 0:
                log.info("account %s: %d/%d done", name, n, len(todo))
        self._repo.set_sync_cursor(uid, name, result.cursor)

    def _defer(self, account: Account, message_id: str, stats: RunStats) -> None:
        self._repo.mark_pending(self._user_id, account.name, [message_id])
        stats.pending += 1

    def _process(self, account: Account, provider: MailProvider, pipeline: Pipeline, message_id: str, stats: RunStats) -> None:
        uid = self._user_id
        try:
            msg = provider.get_message(account, message_id)
        except ProviderError:
            self._defer(account, message_id, stats)
            return
        try:
            stats.new += 1
            if len(msg.body_text.strip()) < 20:
                stats.near_empty += 1
            triage = pipeline.triage(msg)
            if triage.gate.decision is GateDecision.SENSITIVE:
                self._save_sensitive(account, msg, triage, stats)
                return

            status, classified_by, classification = MessageStatus.DONE, None, triage.rule_classification
            if classification is not None:
                classified_by = f"rule:{triage.rule_name}"
                stats.rule_classified += 1
            elif triage.llm_text is not None:
                if not self._llm_ok:
                    self._defer(account, message_id, stats)
                    return
                try:
                    classification = pipeline.classify_safe(triage)
                except BackendUnavailable as e:
                    log.warning("LLM unavailable (%s); leaving remaining mail pending", e)
                    self._llm_ok = False
                    self._defer(account, message_id, stats)
                    return
                classified_by = "llm"
                if classification is None:
                    status = MessageStatus.UNCLASSIFIED
                    stats.unclassified += 1
                else:
                    stats.classified += 1
            elif triage.tier is Tier.IGNORE:
                stats.ignored += 1

            priority_sender = triage.tier is Tier.PRIORITY
            known = classification is not None and is_known_company(self._repo, uid, classification.company)
            self._repo.save_email_meta(
                EmailMeta(
                    user_id=uid, account=account.name, message_id=message_id,
                    sender_address=msg.sender_address, sender_name=msg.sender_name,
                    received_at=msg.received_at, tier=triage.tier, gate=triage.gate.decision,
                    status=status, classification=classification, classified_by=classified_by,
                )
            )
            if classification is not None and classification.category is Category.JOB:
                stats.job += 1
                via_ats = priority_sender and self._rules.tier_for(msg.sender_address) is Tier.PRIORITY
                record_job_event(
                    self._repo, uid, company=classification.company, role=classification.role,
                    stage=classification.stage, account=account.name, message_id=message_id,
                    received_at=msg.received_at, domain=company_domain(msg.sender_domain, via_ats=via_ats),
                )
            if should_alert(classification, known_company=known, priority_sender=priority_sender):
                assert classification is not None
                self._alert(JobAlert(uid, account.name, message_id, classification.company,
                                     classification.stage, classification.deadline), stats)
        finally:
            msg.discard_content()

    def _save_sensitive(self, account: Account, msg, triage: Triage, stats: RunStats) -> None:
        uid = self._user_id
        stats.sensitive += 1
        held = triage.held_job
        self._repo.save_email_meta(
            EmailMeta(
                user_id=uid, account=account.name, message_id=msg.message_id, sender_address=None,
                sender_name=msg.sender_name, received_at=msg.received_at, tier=triage.tier,
                gate=GateDecision.SENSITIVE, held_reason=friendly_reason(triage.gate.reasons),
                held_job=held is not None, held_company=held.company if held else None,
                held_stage=held.stage if held else None,
            )
        )
        if held is None:
            return
        stats.held_jobs += 1
        record_job_event(
            self._repo, uid, company=held.company, role=None, stage=held.stage, account=account.name,
            message_id=msg.message_id, received_at=msg.received_at, domain=None,
        )
        self._alert(JobAlert(uid, account.name, msg.message_id, held.company, held.stage, None, held=True), stats)

    def _alert(self, alert: JobAlert, stats: RunStats) -> None:
        stats.alerts.append(alert)
        if self._notifier is not None:
            self._notifier.notify(alert)
