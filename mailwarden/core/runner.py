"""One sync + classify pass over every account. Depends only on interfaces.

Idempotent: processed messages are skipped. Anything that cannot be finished
now (fetch failure, LLM unavailable, over the per-run cap) is recorded as
pending and retried next run, so the sync cursor can always advance.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from mailwarden.core.alerts import should_alert
from mailwarden.core.applications import update_applications
from mailwarden.core.classify.base import BackendUnavailable, LLMBackend
from mailwarden.core.models import Account, Category, EmailMeta, GateDecision, MessageStatus, Tier
from mailwarden.core.pipeline import Pipeline
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
    ignored: int = 0
    classified: int = 0
    unclassified: int = 0
    pending: int = 0
    job: int = 0
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

        for message_id in todo:
            self._process(account, provider, pipeline, message_id, stats)
        self._repo.set_sync_cursor(uid, name, result.cursor)
        log.info("account %s: %d new messages processed", name, len(todo))

    def _process(self, account: Account, provider: MailProvider, pipeline: Pipeline, message_id: str, stats: RunStats) -> None:
        uid = self._user_id
        try:
            msg = provider.get_message(account, message_id)
        except ProviderError:
            self._repo.mark_pending(uid, account.name, [message_id])
            stats.pending += 1
            return
        try:
            stats.new += 1
            triage = pipeline.triage(msg)
            status, classification = MessageStatus.DONE, None
            if triage.llm_text is not None:
                if not self._llm_ok:
                    self._repo.mark_pending(uid, account.name, [message_id])
                    stats.pending += 1
                    return
                try:
                    classification = pipeline.classify_safe(triage)
                except BackendUnavailable as e:
                    log.warning("LLM unavailable (%s); leaving remaining mail pending", e)
                    self._llm_ok = False
                    self._repo.mark_pending(uid, account.name, [message_id])
                    stats.pending += 1
                    return
                if classification is None:
                    status = MessageStatus.UNCLASSIFIED
                    stats.unclassified += 1
                else:
                    stats.classified += 1

            sensitive = triage.gate.decision is GateDecision.SENSITIVE
            if sensitive:
                stats.sensitive += 1
            elif triage.tier is Tier.IGNORE:
                stats.ignored += 1

            self._repo.save_email_meta(
                EmailMeta(
                    user_id=uid,
                    account=account.name,
                    message_id=message_id,
                    sender_address=None if sensitive else msg.sender_address,
                    sender_name=msg.sender_name,
                    received_at=msg.received_at,
                    tier=triage.tier,
                    gate=triage.gate.decision,
                    status=status,
                    classification=classification,
                )
            )
            if classification is not None and classification.category is Category.JOB:
                stats.job += 1
                update_applications(
                    self._repo,
                    uid,
                    classification,
                    account=account.name,
                    message_id=message_id,
                    received_at=msg.received_at,
                    sender_domain=msg.sender_domain,
                    via_ats=triage.tier is Tier.PRIORITY and self._rules.tier_for(msg.sender_address) is Tier.PRIORITY,
                )
            if should_alert(classification):
                assert classification is not None
                alert = JobAlert(uid, message_id, classification.company, classification.stage, classification.deadline)
                stats.alerts.append(alert)
                if self._notifier is not None:
                    self._notifier.notify(alert)
        finally:
            msg.discard_content()
