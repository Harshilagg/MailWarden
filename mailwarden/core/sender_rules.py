"""Sender tiers (PRIORITY / SENSITIVE / IGNORE). Pure lookup, no LLM.

Matching is case-insensitive. An exact sender address beats a domain rule,
and a more specific domain beats a parent domain (``alerts.hdfcbank.net``
matches a ``hdfcbank.net`` rule). An entry may appear in only one tier.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

from mailwarden.core.models import Tier

RULE_TIERS = (Tier.PRIORITY, Tier.SENSITIVE, Tier.IGNORE)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
ADDRESS_RE = re.compile(r"^[a-z0-9._%+'-]{1,64}@(?:[a-z0-9-]+\.)+[a-z0-9-]{2,63}$")


class RulesError(ValueError):
    pass


def normalise_entry(entry: str) -> str:
    entry = entry.strip().lower()
    if "@" in entry:
        if not ADDRESS_RE.match(entry):
            raise RulesError(f"not a valid sender address: {entry!r}")
    elif not DOMAIN_RE.match(entry):
        raise RulesError(f"not a valid domain: {entry!r}")
    return entry


class _TierLists(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domains: list[str] = []
    senders: list[str] = []

    @field_validator("domains", "senders", mode="before")
    @classmethod
    def _none_is_empty(cls, v: object) -> object:
        return [] if v is None else v


class _RulesFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    priority: _TierLists = _TierLists()
    sensitive: _TierLists = _TierLists()
    ignore: _TierLists = _TierLists()


@dataclass(frozen=True)
class SenderRules:
    addresses: dict[str, Tier] = field(default_factory=dict)
    domains: dict[str, Tier] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, text: str) -> SenderRules:
        try:
            parsed = _RulesFile.model_validate(yaml.safe_load(text) or {})
        except (yaml.YAMLError, ValueError) as e:
            raise RulesError(f"invalid sender rules: {e}") from None
        addresses: dict[str, Tier] = {}
        domains: dict[str, Tier] = {}
        for tier in RULE_TIERS:
            lists: _TierLists = getattr(parsed, tier.value)
            for raw in [*lists.domains, *lists.senders]:
                entry = normalise_entry(raw)
                target = addresses if "@" in entry else domains
                if target.get(entry, tier) != tier:
                    raise RulesError(f"{entry!r} is listed in both {target[entry]} and {tier}")
                target[entry] = tier
        return cls(addresses, domains)

    def tier_for(self, sender_address: str) -> Tier:
        address = sender_address.strip().lower()
        if address in self.addresses:
            return self.addresses[address]
        _, at, domain = address.rpartition("@")
        if not at or not domain:
            return Tier.DEFAULT
        labels = domain.split(".")
        for i in range(len(labels) - 1):  # most specific first; never a bare TLD
            tier = self.domains.get(".".join(labels[i:]))
            if tier is not None:
                return tier
        return Tier.DEFAULT

    def tier_of_entry(self, entry: str) -> Tier:
        entry = normalise_entry(entry)
        table = self.addresses if "@" in entry else self.domains
        return table.get(entry, Tier.DEFAULT)

    def with_priority_domains(self, domains: Iterable[str]) -> SenderRules:
        """Add company domains (e.g. from the applications table) without overriding rules."""
        merged = dict(self.domains)
        for d in domains:
            try:
                merged.setdefault(normalise_entry(d), Tier.PRIORITY)
            except RulesError:
                continue
        return SenderRules(dict(self.addresses), merged)


# ---------------------------------------------------------------------------
# In-place editing for `mailwarden promote` (keeps the user's comments).
# ---------------------------------------------------------------------------

_TOP = re.compile(r"^(priority|sensitive|ignore):\s*(#.*)?$")
_SUB = re.compile(r"^(\s+)(domains|senders):\s*(\[\s*\])?\s*(#.*)?$")


def _item_value(line: str) -> str | None:
    m = re.match(r"^\s*-\s*['\"]?([^'\"#\s]+)['\"]?\s*(#.*)?$", line)
    return m.group(1).lower() if m else None


def set_entry_tier(text: str, entry: str, tier: Tier) -> str:
    """Return ``text`` with ``entry`` moved to ``tier`` (DEFAULT removes it everywhere)."""
    entry = normalise_entry(entry)
    sub_key = "senders" if "@" in entry else "domains"
    lines = text.splitlines()
    out: list[str] = []
    top = sub = None
    insert_at: int | None = None
    item_indent = None
    for line in lines:
        if m := _TOP.match(line):
            top, sub = m.group(1), None
        elif m := _SUB.match(line):
            sub = m.group(2)
            if top == tier.value and sub == sub_key:
                indent = m.group(1)
                item_indent = indent + "  "
                if m.group(3):  # "domains: []" -> block list
                    line = f"{indent}{sub}:" + (f"  {m.group(4)}" if m.group(4) else "")
                out.append(line)
                insert_at = len(out)
                continue
        elif top and sub and _item_value(line) == entry:
            continue  # drop from wherever it currently is
        out.append(line)
    if tier != Tier.DEFAULT:
        if insert_at is None:
            raise RulesError(f"sender_rules.yaml has no '{tier.value}: {sub_key}:' section")
        out.insert(insert_at, f"{item_indent}- {entry}")
    result = "\n".join(out) + "\n"
    if SenderRules.from_yaml(result).tier_of_entry(entry) != tier:
        raise RulesError("edit did not produce the expected tier; file left unchanged")
    return result
