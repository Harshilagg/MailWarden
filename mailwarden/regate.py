"""`mailwarden regate`: re-run the current gate and rules over stored mail.

Re-fetches messages already in the database (bodies are never stored), triages
them again with today's rules (no LLM), and prints a per-sender breakdown of
old vs new outcomes. With --apply, messages whose outcome changed (or that were
processed by an older version) are forgotten and processed again.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TextIO

from mailwarden.core.models import Account, EmailMeta, GateDecision, Tier
from mailwarden.core.pipeline import Pipeline, Triage
from mailwarden.core.text import clean
from mailwarden.providers.base import MailProvider, ProviderError
from mailwarden.storage.base import Repository


def _old_outcome(m: EmailMeta) -> str:
    if m.gate is GateDecision.SENSITIVE:
        return "held (job)" if m.held_job else "held"
    if m.tier is Tier.IGNORE:
        return "ignored"
    c = m.classification
    if c is None:
        return "unclassified"
    how = "rule" if (m.classified_by or "").startswith("rule:") else "llm" if m.classified_by else "old"
    return f"{c.category} ({how})"


def _new_outcome(t: Triage) -> str:
    if t.gate.sensitive:
        return "held (job)" if t.held_job else "held"
    if t.tier is Tier.IGNORE:
        return "ignored"
    if t.rule_classification is not None:
        return f"{t.rule_classification.category} (rule)"
    return "to LLM"


def _changed(old: str, new: str) -> bool:
    if old.endswith("(old)") or old == "unclassified":
        return True  # processed by an older version: redo
    if old.startswith("held") != new.startswith("held"):
        return True
    if old.startswith("held"):
        return old != new
    if new.endswith("(rule)") or old.endswith("(rule)"):
        return old != new
    return False  # was classified by the LLM and would still go to the LLM


@dataclass
class SenderBreakdown:
    domain: str
    total: int = 0
    held_now: int = 0
    released: int = 0
    newly_held: int = 0
    changed: int = 0
    rules: defaultdict[str, int] = field(default_factory=lambda: defaultdict(int))
    waived: defaultdict[str, int] = field(default_factory=lambda: defaultdict(int))
    outcomes: defaultdict[str, int] = field(default_factory=lambda: defaultdict(int))


@dataclass
class RegateReport:
    total: int = 0
    held_before: int = 0
    held_after: int = 0
    fetch_errors: int = 0
    senders: dict[str, SenderBreakdown] = field(default_factory=dict)
    to_reprocess: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))


def run_regate(
    repo: Repository,
    user_id: str,
    accounts: list[Account],
    provider_for: Callable[[Account], MailProvider],
    pipeline: Pipeline,
    *,
    days: int,
    now: dt.datetime,
) -> RegateReport:
    report = RegateReport()
    by_account = {a.name: a for a in accounts}
    for meta in repo.list_email_meta(user_id, since=now - dt.timedelta(days=days)):
        account = by_account.get(meta.account)
        if account is None:
            continue
        try:
            msg = provider_for(account).get_message(account, meta.message_id)
        except ProviderError:
            report.fetch_errors += 1
            continue
        try:
            t = pipeline.triage(msg)
            old, new = _old_outcome(meta), _new_outcome(t)
            label = clean(t.sender or meta.sender_name)[:60]
            row = report.senders.setdefault(label, SenderBreakdown(domain=msg.sender_domain))
            row.total += 1
            report.total += 1
            report.held_before += old.startswith("held")
            report.held_after += new.startswith("held")
            row.outcomes[f"{old} -> {new}" if old != new else new] += 1
            if new.startswith("held"):
                row.held_now += 1
                for r in t.gate.reasons:
                    row.rules[r] += 1
                if not old.startswith("held"):
                    row.newly_held += 1
            elif old.startswith("held"):
                row.released += 1
            for r in t.gate.waived:
                row.waived[r] += 1
            if _changed(old, new):
                row.changed += 1
                report.to_reprocess[account.name].append(meta.message_id)
        finally:
            msg.discard_content()
    return report


def print_regate(report: RegateReport, out: TextIO, *, applied: bool) -> None:
    p = lambda text="": print(text, file=out)  # noqa: E731
    changed = sum(len(v) for v in report.to_reprocess.values())
    p(f"=== regate: {report.total} stored emails re-checked (no LLM calls) ===")
    p(f"held before: {report.held_before}   held now: {report.held_after}   outcome changed: {changed}")
    if report.fetch_errors:
        p(f"could not re-fetch: {report.fetch_errors}")
    p("\nper sender:")
    for label, s in sorted(report.senders.items(), key=lambda kv: (-kv[1].total, kv[0].lower())):
        p(f"  {label}  <…@{s.domain}>  ×{s.total}")
        for outcome, n in sorted(s.outcomes.items(), key=lambda kv: -kv[1]):
            p(f"      {n:>3}  {outcome}")
        if s.rules:
            p("           held by: " + ", ".join(f"{k} ×{v}" for k, v in sorted(s.rules.items(), key=lambda kv: -kv[1])))
        if s.waived:
            p("           soft rules waived (recruiting markers): " + ", ".join(f"{k} ×{v}" for k, v in s.waived.items()))
    if not applied and changed:
        p(f"\nRun `mailwarden regate --apply` to reprocess the {changed} changed email(s).")
