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
    {"linkedin.com", "indeed.com", "naukri.com", "foundit.in", "monsterindia.com", "internshala.com", "glassdoor.com",
     "monster.com", "shine.com", "apna.co", "wellfound.com", "instahyre.com", "cutshort.io"}
)
ASSESSMENT_DOMAINS = frozenset({
    "hackerrank.com", "hackerrankforwork.com", "hackerearth.com", "codesignal.com", "codility.com", "mettl.com",
    "testgorilla.com", "hirevue.com", "hirepro.in", "imocha.io", "karat.io", "coderbyte.com", "interviewbit.com",
    "myamcat.com", "cocubes.com", "talview.com", "glider.ai", "unstop.com",
})
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


def company_from_sender(display_name: str, domain: str, address: str = "") -> str | None:
    name = clean(display_name).strip().strip('"')
    if address and domain and domain_matches(domain, RELAY_DOMAINS) and not _meaningful_name(display_name):
        return company_from_local_part(address)
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


# --- recruiting markers (used to waive SOFT gate rules) ------------------------------

ATS_DOMAINS = frozenset({
    "smartrecruiters.com", "greenhouse.io", "greenhouse-mail.io", "lever.co", "ashbyhq.com",
    "myworkdayjobs.com", "myworkday.com", "jobs2web.com", "successfactors.com", "successfactors.eu",
    "icims.com",
})
# ATS names as they appear in relay footers ("Sent via SmartRecruiters", "Powered by Workday").
_ATS_FOOTER = re.compile(
    r"smartrecruiters|greenhouse(?:\.io|-mail)|\bjobs\.lever\.co|\blever\.co\b|ashbyhq|myworkday(?:jobs)?|"
    r"powered\s+by\s+workday|jobs2web|successfactors|\bicims\b",
    re.IGNORECASE,
)
_RECRUITING_PHRASES = re.compile(
    r"application\s+for\s+the\s+(?:position|role)|application\s+(?:has\s+been\s+)?received|"
    r"thanks?\s+(?:you\s+)?for\s+(?:applying|your\s+application)|recruitment\s+team|hiring\s+team|"
    r"job\s+agent|job\s+alerts?|career\s+opportunit(?:y|ies)",
    re.IGNORECASE,
)
_JOB_ALERT_PHRASES = re.compile(
    r"job\s+alerts?|job\s+agent|jobs?\s+(?:you\s+may|for\s+you|matching|recommendations?)|"
    r"recommended\s+jobs|matching\s+jobs|new\s+jobs|new\s+(?:job\s+)?opportunities|"
    r"\d+\+?\s+(?:new\s+)?(?:jobs|internships|openings)|internships?\s+for\s+you|companies\s+are\s+hiring",
    re.IGNORECASE,
)

GOVERNMENT_SUFFIXES = frozenset({"gov.in", "nic.in", "gov", "irs.gov", "uidai.gov.in", "incometax.gov.in",
                                 "protean-tinpan.com", "tin-nsdl.com", "utiitsl.com", "epfindia.gov.in"})


def is_government(domain: str) -> bool:
    return domain_matches(domain, GOVERNMENT_SUFFIXES)


def recruiting_markers(sender_domain: str, subject: str, body: str) -> set[str]:
    """Names of recruiting markers present. 'ats' and 'subject_phrase' are the strong ones."""
    markers: set[str] = set()
    subject, head = clean(subject), clean(body)[:20000]
    if domain_matches(sender_domain, ATS_DOMAINS):
        markers.add("ats")
    if _ATS_FOOTER.search(head):
        markers.add("ats")
    if _RECRUITING_PHRASES.search(subject):
        markers.add("subject_phrase")
    if _RECRUITING_PHRASES.search(head):
        markers.add("body_phrase")
    return markers


def strong_recruiting(markers: set[str], *, strict: bool) -> bool:
    """strict (a bank/payments sender): needs an ATS relay or a subject phrase."""
    if strict:
        return bool(markers & {"ats", "subject_phrase"})
    return bool(markers)


def looks_like_job_alert(subject: str, body: str) -> bool:
    return bool(_JOB_ALERT_PHRASES.search(clean(subject)) or _JOB_ALERT_PHRASES.search(clean(body)[:600]))


# --- sender labels (never "Unknown sender") ------------------------------------------

RELAY_DOMAINS = frozenset({"jobs2web.com", "successfactors.com", "successfactors.eu", "myworkday.com",
                           "myworkdayjobs.com", "smartrecruiters.com", "icims.com"})
_LOCAL_NOISE = re.compile(
    r"job\s*alerts?|jobs?|careers?|recruit\w*|talent|no-?reply|donotreply|do-not-reply|hiring|alerts?|"
    r"notifications?|mailer|info|hr|team|\d+",
    re.IGNORECASE,
)


def company_from_local_part(address: str) -> str | None:
    local = address.partition("@")[0]
    local = _LOCAL_NOISE.sub(" ", local)
    local = re.sub(r"[^A-Za-z]+", " ", local).strip()
    if len(local) < 2:
        return None
    return local.capitalize() if local.islower() else local


def _meaningful_name(name: str) -> bool:
    name = clean(name).strip().strip('"')
    return bool(re.search(r"[A-Za-z]{2,}", name)) and "@" not in name and not re.fullmatch(
        r"[\w.-]+\.[a-z]{2,}", name, re.IGNORECASE)


def sender_label(display_name: str, address: str) -> str:
    """A human label: display name, else a relay's company from the local part, else the domain."""
    if _meaningful_name(display_name):
        return clean(display_name).strip().strip('"')[:200]
    domain = address.rpartition("@")[2].lower()
    if domain and domain_matches(domain, RELAY_DOMAINS):
        company = company_from_local_part(address)
        if company:
            return company
    return registrable_domain(domain) if domain else "Unknown address"
