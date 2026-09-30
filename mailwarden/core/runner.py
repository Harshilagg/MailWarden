"""One sync + classify pass over every account. Depends only on interfaces.

Idempotent: processed messages are skipped. Anything that cannot be finished
now (fetch failure, LLM unavailable, per-run LLM cap, per-run message cap) is
recorded as pending and retried next run, so the sync cursor can always advance.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

import datetime as dt

from mailwarden.core.alerts import ALERT_STAGES, priority_safety_net, should_alert
from mailwarden.core.dates import find_deadline
from mailwarden.core.overview import urgent_by_rules
from mailwarden.core.recruiting import ASSESSMENT_DOMAINS, domain_matches
from mailwarden.core.applications import company_domain, is_known_company, record_job_event
from mailwarden.core.job_alerts import dedup_key
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
    jobs_found: int = 0
    jobs_new: int = 0
    waived: int = 0
    safety_net: int = 0
    #: Reprocessed messages kept in Urgent although the new classification alone would not.
    urgent_kept: int = 0
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

    def _pipeline(self) -> Pipeline:
        # Company domains from tracked applications count as PRIORITY senders.
        rules = self._rules.with_priority_domains(self._repo.application_domains(self._user_id))
        return Pipeline(rules, max_body_chars=self._max_body_chars, llm=self._llm)

    def reprocess(self, account: Account, message_ids: list[str]) -> RunStats:
        """Forget and re-run specific messages (used by `regate --apply`)."""
        stats = RunStats()
        provider, pipeline = self._provider_for(account), self._pipeline()
        for message_id in message_ids:
            previous = self._repo.get_email_meta(self._user_id, account.name, message_id)
            self._repo.delete_message(self._user_id, account.name, message_id)
            self._process(account, provider, pipeline, message_id, stats, previous=previous)
        return stats

    def run(self, accounts: list[Account]) -> RunStats:
        stats = RunStats()
        pipeline = self._pipeline()
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

    def _carry(self, meta: EmailMeta, previous: EmailMeta | None, stats: RunStats) -> EmailMeta:
        """Pin urgency and keep the user's Done across (re)processing: nothing leaves Urgent silently."""
        now = dt.datetime.now(dt.UTC)
        urgent_since = previous.urgent_since if previous else None
        if previous is not None and urgent_since is None and not previous.dismissed and urgent_by_rules(previous):
            urgent_since = previous.received_at  # was urgent before pins existed
        if urgent_since is None and urgent_by_rules(meta):
            urgent_since = now
        if previous is not None and urgent_since is not None and not urgent_by_rules(meta) and not previous.dismissed:
            stats.urgent_kept += 1
            log.info("message kept in Urgent after reclassification (pinned until Done)")
        return meta.model_copy(update={"urgent_since": urgent_since,
                                       "dismissed": bool(previous and previous.dismissed)})

    def _process(self, account: Account, provider: MailProvider, pipeline: Pipeline, message_id: str,
                 stats: RunStats, *, previous: EmailMeta | None = None) -> None:
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
            if triage.gate.waived:
                stats.waived += 1
            if triage.gate.decision is GateDecision.SENSITIVE:
                self._save_sensitive(account, msg, triage, stats, previous)
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
                    netted = priority_safety_net(
                        classification, tier=triage.tier,
                        assessment_platform=domain_matches(msg.sender_domain, ASSESSMENT_DOMAINS))
                    if netted is not classification:
                        classification, classified_by = netted, "llm+priority_rule"
                        stats.safety_net += 1
                    classification = self._local_deadline(classification, msg)
            elif triage.tier is Tier.IGNORE:
                stats.ignored += 1

            priority_sender = triage.tier is Tier.PRIORITY
            known = classification is not None and is_known_company(self._repo, uid, classification.company)
            self._repo.save_email_meta(self._carry(
                EmailMeta(
                    user_id=uid, account=account.name, message_id=message_id,
                    sender_address=msg.sender_address, sender_name=triage.sender or msg.sender_name,
                    received_at=msg.received_at, tier=triage.tier, gate=triage.gate.decision,
                    status=status, classification=classification, classified_by=classified_by,
                ), previous, stats))
            if classification is not None and classification.category is Category.JOB_ALERT:
                self._save_jobs(account, msg, triage, pipeline, stats)
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

    def _local_deadline(self, c, msg):
        """If job mail needs action but the model gave no deadline, look for one locally."""
        if c is None or c.category is not Category.JOB or c.deadline is not None:
            return c
        if not (c.action_required or c.stage in ALERT_STAGES):
            return c
        found = find_deadline(f"{msg.subject}\n{msg.body_text}", msg.received_at.astimezone().date())
        return c.model_copy(update={"deadline": found}) if found else c

    def _save_sensitive(self, account: Account, msg, triage: Triage, stats: RunStats,
                        previous: EmailMeta | None = None) -> None:
        uid = self._user_id
        stats.sensitive += 1
        held = triage.held_job
        deadline = find_deadline(f"{msg.subject}\n{msg.body_text}", msg.received_at.astimezone().date()) if held else None
        self._repo.save_email_meta(self._carry(
            EmailMeta(
                user_id=uid, account=account.name, message_id=msg.message_id, sender_address=None,
                sender_name=triage.sender or msg.sender_name, received_at=msg.received_at, tier=triage.tier,
                gate=GateDecision.SENSITIVE, held_reason=friendly_reason(triage.gate.reasons),
                held_job=held is not None, held_company=held.company if held else None,
                held_stage=held.stage if held else None, held_deadline=deadline,
            ), previous, stats))
        if held is None:
            return
        stats.held_jobs += 1
        record_job_event(
            self._repo, uid, company=held.company, role=None, stage=held.stage, account=account.name,
            message_id=msg.message_id, received_at=msg.received_at, domain=None,
        )
        self._alert(JobAlert(uid, account.name, msg.message_id, held.company, held.stage, deadline, held=True), stats)

    def _save_jobs(self, account: Account, msg, triage: Triage, pipeline: Pipeline, stats: RunStats) -> None:
        if not self._llm_ok:
            pipeline = Pipeline(self._rules, max_body_chars=self._max_body_chars)  # local parsers only
        try:
            posts = pipeline.extract_jobs_safe(triage, msg)
        except BackendUnavailable as e:
            log.warning("job extraction skipped (%s)", e)
            self._llm_ok = False
            return
        if not posts:
            return
        sender = triage.sender or msg.sender_name
        stats.jobs_found += len(posts)
        stats.jobs_new += self._repo.save_jobs(
            self._user_id, account=account.name, message_id=msg.message_id, sender=sender,
            received_at=msg.received_at, posts=posts, keys=[dedup_key(p, sender) for p in posts],
        )

    def _alert(self, alert: JobAlert, stats: RunStats) -> None:
        stats.alerts.append(alert)
        if self._notifier is not None:
            self._notifier.notify(alert)
