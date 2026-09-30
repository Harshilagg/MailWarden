"""`mailwarden dry-run`: show what a run WOULD do, without doing any of it.

Never calls an LLM (unless --with-llm, phase 3), never notifies, writes
nothing (no DB, no sync cursor). For SENSITIVE mail it prints only the
sender name, sender domain, time and the names of the rules that fired.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TextIO

from mailwarden.core.models import Account, Tier
from mailwarden.core.pipeline import Pipeline, Triage
from mailwarden.core.text import clean
from mailwarden.providers.base import MailProvider, ProviderError


@dataclass
class DryRunReport:
    total: int = 0
    fetch_errors: int = 0
    sensitive: int = 0
    ignored: int = 0
    would_classify: int = 0
    priority_safe: int = 0
    reasons: Counter[str] = field(default_factory=Counter)
    sensitive_by_sender: Counter[str] = field(default_factory=Counter)
    priority_held_back: Counter[str] = field(default_factory=Counter)


def _safe_label(text: str, limit: int = 60) -> str:
    return clean(text).replace("\n", " ").strip()[:limit] or "(no name)"


def _notification_line(t: Triage) -> str:
    if t.llm_text is None:
        return "none"
    if t.tier is Tier.PRIORITY:
        return "possible: fires if classified as job with action required / assessment / interview / offer"
    return "only if classified as job mail needing action (needs --with-llm)"


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
    for account in accounts:
        provider = provider_for(account)
        try:
            ids = provider.list_recent(account, last)
        except ProviderError as e:
            print(f"account {account.name}: listing failed: {e}", file=out)
            continue
        print(f"\n=== account {account.name}: last {len(ids)} messages ===", file=out)
        for n, message_id in enumerate(ids, 1):
            report.total += 1
            try:
                msg = provider.get_message(account, message_id)
            except ProviderError as e:
                report.fetch_errors += 1
                print(f"[{n}] fetch failed: {e}", file=out)
                continue
            triage = pipeline.triage(msg)
            name = _safe_label(msg.sender_name or msg.sender_domain)
            when = msg.received_at.astimezone().strftime("%Y-%m-%d %H:%M")
            header = f"[{n}] {when}  {name}  <…@{_safe_label(msg.sender_domain)}>"

            if triage.gate.sensitive:
                report.sensitive += 1
                report.reasons.update(triage.gate.reasons)
                report.sensitive_by_sender[name] += 1
                if triage.tier is Tier.PRIORITY:
                    report.priority_held_back[name] += 1
                if not summary_only:
                    print(header, file=out)
                    print(f"    tier: {triage.tier}   gate: SENSITIVE ({', '.join(triage.gate.reasons)})", file=out)
                    print("    would send to LLM: nothing", file=out)
                    print("    notification: none", file=out)
            elif triage.tier is Tier.IGNORE:
                report.ignored += 1
                if not summary_only:
                    print(header, file=out)
                    print("    tier: ignore   gate: SAFE   (counted only, never classified)", file=out)
            else:
                report.would_classify += 1
                if triage.tier is Tier.PRIORITY:
                    report.priority_safe += 1
                if not summary_only:
                    assert triage.llm_text is not None
                    print(header, file=out)
                    print(f"    tier: {triage.tier}   gate: SAFE", file=out)
                    print(f"    would send to LLM ({len(triage.llm_text)} chars):", file=out)
                    for line in triage.llm_text.splitlines():
                        print(f"    │ {line}", file=out)
                    print(f"    notification: {_notification_line(triage)}", file=out)
            msg.discard_content()

    _print_summary(report, out)
    return report


def _print_summary(r: DryRunReport, out: TextIO) -> None:
    print("\n=== summary (nothing was sent, stored or notified) ===", file=out)
    print(f"messages:            {r.total}", file=out)
    print(f"sensitive (held):    {r.sensitive}", file=out)
    print(f"ignored:             {r.ignored}", file=out)
    print(f"would be classified: {r.would_classify}  (priority: {r.priority_safe})", file=out)
    if r.fetch_errors:
        print(f"fetch errors:        {r.fetch_errors}", file=out)
    if r.reasons:
        print("gate rules fired:    " + ", ".join(f"{k} ×{v}" for k, v in r.reasons.most_common()), file=out)
    if r.sensitive_by_sender:
        print("sensitive by sender:", file=out)
        for name, count in r.sensitive_by_sender.most_common():
            print(f"    {count:>3}  {name}", file=out)
    if r.priority_held_back:
        print("PRIORITY senders held back as sensitive (job mail you might miss):", file=out)
        for name, count in r.priority_held_back.most_common():
            print(f"    {count:>3}  {name}", file=out)
