"""`mailwarden dry-run`: show what a run WOULD do, without doing any of it.

Never calls an LLM unless --with-llm is given, never notifies, writes
nothing (no DB, no sync cursor). For SENSITIVE mail it prints only the
sender name, sender domain, time and the names of the rules that fired,
plus the locally extracted company/stage for held-back job mail.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TextIO

from mailwarden.core.alerts import should_alert
from mailwarden.core.classify.base import BackendUnavailable
from mailwarden.core.models import Account, Classification, Tier
from mailwarden.core.pipeline import Pipeline, Triage
from mailwarden.core.recruiting import JOB_BOARD_DOMAINS, domain_matches, recruiting_signal
from mailwarden.core.text import clean
from mailwarden.delivery.base import JobAlert
from mailwarden.providers.base import MailProvider, ProviderError


@dataclass
class DryRunReport:
    total: int = 0
    fetch_errors: int = 0
    sensitive: int = 0
    held_jobs: int = 0
    ignored: int = 0
    rule_classified: int = 0
    would_classify: int = 0
    priority_safe: int = 0
    classified: int = 0
    unclassified: int = 0
    would_notify: int = 0
    near_empty: int = 0
    reasons: Counter[str] = field(default_factory=Counter)
    rules_used: Counter[str] = field(default_factory=Counter)
    sensitive_by_sender: Counter[str] = field(default_factory=Counter)
    #: (sender, domain, rules, surfaced-as) for held mail from job boards / recruiters.
    held_job_board: list[tuple[str, str, str, str]] = field(default_factory=list)


def _safe_label(text: str, limit: int = 60) -> str:
    return clean(text).replace("\n", " ").strip()[:limit] or "(no name)"


def _alert_text(a: JobAlert) -> str:
    return a.title()


def _jobish(triage: Triage, name: str, domain: str) -> bool:
    return (
        triage.held_job is not None
        or triage.tier in (Tier.PRIORITY, Tier.JOB_ALERT)
        or triage.rule_tier in (Tier.PRIORITY, Tier.JOB_ALERT)
        or recruiting_signal(name, domain)
        or domain_matches(domain, JOB_BOARD_DOMAINS)
    )


def run_dry_run(
    accounts: list[Account],
    provider_for: Callable[[Account], MailProvider],
    pipeline: Pipeline,
    *,
    last: int,
    out: TextIO,
    summary_only: bool = False,
) -> DryRunReport:
    report = DryRunReport()
    llm_ok = pipeline.has_llm

    def say(*lines: str) -> None:
        if not summary_only:
            for line in lines:
                print(line, file=out)

    for account in accounts:
        provider = provider_for(account)
        try:
            ids = provider.list_recent(account, last)
        except ProviderError as e:
            print(f"account {account.name}: listing failed: {e}", file=out)
            continue
        say(f"\n=== account {account.name}: last {len(ids)} messages ===")
        for n, message_id in enumerate(ids, 1):
            report.total += 1
            try:
                msg = provider.get_message(account, message_id)
            except ProviderError as e:
                report.fetch_errors += 1
                say(f"[{n}] fetch failed: {e}")
                continue
            if len(msg.body_text.strip()) < 20:
                report.near_empty += 1
            triage = pipeline.triage(msg)
            name = _safe_label(msg.sender_name or msg.sender_domain)
            domain = _safe_label(msg.sender_domain)
            when = msg.received_at.astimezone().strftime("%Y-%m-%d %H:%M")
            tier_text = f"{triage.tier}" + (f" (rules: {triage.rule_tier}, override: {triage.override})" if triage.override else "")
            header = f"[{n}] {when}  {name}  <…@{domain}>"

            if triage.gate.sensitive:
                report.sensitive += 1
                report.reasons.update(triage.gate.reasons)
                report.sensitive_by_sender[f"{name}  <…@{domain}>"] += 1
                rules = ", ".join(triage.gate.reasons)
                held = triage.held_job
                surfaced = "no"
                if held is not None:
                    report.held_jobs += 1
                    alert = JobAlert(account.user_id, account.name, message_id, held.company, held.stage, None, held=True)
                    surfaced = f'yes: "{alert.title()}"'
                if _jobish(triage, msg.sender_name, msg.sender_domain):
                    report.held_job_board.append((name, domain, rules, surfaced))
                say(header, f"    tier: {tier_text}   gate: SENSITIVE ({rules})", "    would send to LLM: nothing")
                say(f"    held job mail: {surfaced}" if held else "    notification: none")
            elif triage.tier is Tier.IGNORE:
                report.ignored += 1
                say(header, "    tier: ignore   gate: SAFE   (counted only, never classified)")
            elif triage.rule_classification is not None:
                report.rule_classified += 1
                report.rules_used[triage.rule_name or "?"] += 1
                say(header, f"    tier: {tier_text}   gate: SAFE",
                    f"    classified by rule ({triage.rule_name}): {triage.rule_classification.category}; no LLM call",
                    "    notification: none (digest only)")
            else:
                report.would_classify += 1
                if triage.tier is Tier.PRIORITY:
                    report.priority_safe += 1
                assert triage.llm_text is not None
                say(header, f"    tier: {tier_text}   gate: SAFE", f"    would send to LLM ({len(triage.llm_text)} chars):")
                say(*[f"    │ {line}" for line in triage.llm_text.splitlines()])
                if not llm_ok:
                    say("    notification: decided after classification (use --with-llm)")
                else:
                    c: Classification | None = None
                    try:
                        c = pipeline.classify_safe(triage)
                    except BackendUnavailable as e:
                        llm_ok = False
                        say(f"    LLM unavailable ({e}); skipping classification for the rest")
                    if llm_ok:
                        if c is None:
                            report.unclassified += 1
                            say("    classification: UNCLASSIFIED (invalid output twice)")
                        else:
                            report.classified += 1
                            say(f"    classification: {c.model_dump_json()}")
                            # dry-run cannot see the applications table: assume the company is not tracked yet.
                            if should_alert(c, known_company=False, priority_sender=triage.tier is Tier.PRIORITY):
                                report.would_notify += 1
                                alert = JobAlert(account.user_id, account.name, message_id, c.company, c.stage, c.deadline)
                                say(f"    notification: WOULD FIRE: {_alert_text(alert)}")
                            else:
                                say("    notification: none (or only if the company is already tracked)")
            msg.discard_content()

    _print_summary(report, out)
    return report


def _print_summary(r: DryRunReport, out: TextIO) -> None:
    p = lambda text="": print(text, file=out)  # noqa: E731
    p("\n=== summary (nothing was stored or notified) ===")
    p(f"messages:              {r.total}")
    p(f"sensitive (held):      {r.sensitive}  (surfaced as job mail: {r.held_jobs})")
    p(f"ignored:               {r.ignored}")
    p(f"classified by rule:    {r.rule_classified}" + (f"  ({', '.join(f'{k} ×{v}' for k, v in r.rules_used.most_common())})" if r.rules_used else ""))
    p(f"would go to the LLM:   {r.would_classify}  (priority: {r.priority_safe})")
    if r.classified or r.unclassified:
        p(f"LLM classified:        {r.classified}  unclassified: {r.unclassified}  would notify: {r.would_notify}")
    if r.fetch_errors:
        p(f"fetch errors:          {r.fetch_errors}")
    if r.near_empty:
        p(f"near-empty bodies:     {r.near_empty}")
    if r.reasons:
        p("gate rules fired:      " + ", ".join(f"{k} ×{v}" for k, v in r.reasons.most_common()))
    if r.sensitive_by_sender:
        p("sensitive by sender:")
        for name, count in r.sensitive_by_sender.most_common():
            p(f"    {count:>3}  {name}")
    if r.held_job_board:
        p("held mail from job boards / recruiters (rules that fired; no content):")
        for name, domain, rules, surfaced in r.held_job_board:
            p(f"    {name} <…@{domain}>")
            p(f"        rules: {rules}")
            p(f"        surfaced as job mail: {surfaced}")
