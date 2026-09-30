"""Deterministic, local recruiting heuristics. No LLM, no network.

Used to (a) let a recruiting subdomain of a SENSITIVE company override its
parent's sender tier, and (b) surface held-back job mail with a company and
stage extracted from the sender and subject, without storing the subject.
"""

from __future__ import annotations

import re

from mailwarden.core.models import Stage
from mailwarden.core.text import clean

RECRUITING_TERMS = ("career", "recruit", "talent", "hiring", "campus", "jobs")
_RECRUITING_NAME = re.compile(r"\b(?:careers?|recruit\w*|talent|hiring|campus|jobs?)\b", re.IGNORECASE)

# Senders whose mail is about account security: never overridden by recruiting heuristics.
ACCOUNT_SECURITY_DOMAINS = frozenset(
    {"accounts.google.com", "accountprotection.microsoft.com", "id.apple.com", "facebookmail.com",
     "mail.instagram.com"}
)
_ACCOUNT_SECURITY_LABELS = frozenset({"account", "accounts", "accountprotection", "security", "id", "login", "auth", "signin"})

SOCIAL_DOMAINS = frozenset(
    {"instagram.com", "facebookmail.com", "facebook.com", "whatsapp.com", "x.com", "twitter.com", "threads.net"}
)
JOB_BOARD_DOMAINS = frozenset(
    {"linkedin.com", "indeed.com", "naukri.com", "foundit.in", "internshala.com", "glassdoor.com",
     "monster.com", "shine.com", "apna.co", "wellfound.com", "instahyre.com", "cutshort.io"}
)
# Platforms whose domain says nothing about the hiring company.
PLATFORM_DOMAINS = JOB_BOARD_DOMAINS | frozenset(
    {"greenhouse.io", "greenhouse-mail.io", "lever.co", "ashbyhq.com", "myworkdayjobs.com", "myworkday.com",
     "jobs2web.com", "smartrecruiters.com", "workable.com", "icims.com", "hackerrank.com", "hackerearth.com",
     "codesignal.com", "mettl.com", "successfactors.com", "taleo.net", "unstop.com", "superset.com",
     "joinsuperset.com", "darwinbox.in", "zohorecruit.com", "gmail.com", "outlook.com", "yahoo.com"}
)
_TWO_LEVEL_SUFFIXES = frozenset({"co.in", "co.uk", "com.au", "co.jp", "com.sg", "org.in", "net.in", "ac.in", "gov.in"})


def domain_matches(domain: str, suffixes: frozenset[str]) -> bool:
    labels = domain.lower().split(".")
    return any(".".join(labels[i:]) in suffixes for i in range(len(labels)))


def registrable_domain(domain: str) -> str:
    labels = domain.lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_account_security(domain: str) -> bool:
    if domain_matches(domain, ACCOUNT_SECURITY_DOMAINS):
        return True
    labels = domain.lower().split(".")[:-2]
    return any(label in _ACCOUNT_SECURITY_LABELS for label in labels)


def recruiting_subdomain(domain: str, parent: str) -> bool:
    """True if a label to the LEFT of ``parent`` in ``domain`` is a recruiting term."""
    domain, parent = domain.lower(), parent.lower()
    if domain == parent or not domain.endswith("." + parent):
        return False
    left = domain[: -len(parent) - 1].split(".")
    return any(term in label for label in left for term in RECRUITING_TERMS)


def recruiting_name(display_name: str) -> bool:
    return bool(_RECRUITING_NAME.search(clean(display_name)))


def recruiting_signal(display_name: str, domain: str) -> bool:
    labels = domain.lower().split(".")[:-1]
    return recruiting_name(display_name) or any(t in label for label in labels for t in RECRUITING_TERMS)


# --- company and stage extraction (held-back mail only) ---------------------

_VIA = re.compile(r"^(.*?)\s+via\s+\S.*$", re.IGNORECASE)
_FROM = re.compile(r"^\s*\S+(?:\s+\S+)?\s+from\s+(.+)$", re.IGNORECASE)
_NOISE = re.compile(
    r"\b(?:early\s+careers?|careers?|recruit\w*|talent(?:\s+acquisition)?|hiring|campus(?:\s+to)?|jobs?|"
    r"team|hr|people|university|notifications?|no-?reply|donotreply|alerts?|updates?|the)\b",
    re.IGNORECASE,
)


def company_from_sender(display_name: str, domain: str) -> str | None:
    name = clean(display_name).strip().strip('"')
    if m := _VIA.match(name):
        name = m.group(1)
    elif m := _FROM.match(name):
        name = m.group(1)
    if "@" in name or re.fullmatch(r"[\w.-]+\.[a-z]{2,}", name, re.IGNORECASE):
        name = ""  # the display name is just an address or domain
    name = _NOISE.sub(" ", name)
    name = re.sub(r"[\s\-|:·,/]+", " ", name).strip()
    if re.search(r"[A-Za-z]{2,}", name):
        return name[:80]
    if domain and not domain_matches(domain, PLATFORM_DOMAINS):
        label = registrable_domain(domain).split(".")[0]
        return label.replace("-", " ").title() if label else None
    return None


_STAGE_RULES: tuple[tuple[Stage, re.Pattern[str]], ...] = (
    (Stage.REJECTION, re.compile(r"\bunfortunately\b|\bnot\s+(?:be\s+)?moving\s+forward\b|\bregret\b", re.IGNORECASE)),
    (Stage.OFFER, re.compile(r"\boffer\b", re.IGNORECASE)),
    (Stage.INTERVIEW, re.compile(r"\binterview\w*|\bschedul\w*|\bavailability\b", re.IGNORECASE)),
    (Stage.ASSESSMENT, re.compile(r"\bassessment\w*|\btests?\b|\bchallenge\w*", re.IGNORECASE)),
)


def stage_from_subject(subject: str) -> Stage | None:
    text = clean(subject)
    for stage, pattern in _STAGE_RULES:
        if pattern.search(text):
            return stage
    return None
