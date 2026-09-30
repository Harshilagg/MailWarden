"""The sensitivity gate: 100% local, runs before any LLM is involved.

SENSITIVE if the sender is in the SENSITIVE tier, or the sender name,
subject or body match any pattern below. Fail closed: any error, a failed
parse, or an unparseable sender means SENSITIVE.

Reasons returned are rule names only, never matched text, so they are
safe to print and log.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from mailwarden.core.models import FetchedMessage, GateDecision, Tier
from mailwarden.core.text import fold

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class GateResult:
    decision: GateDecision
    reasons: tuple[str, ...] = ()
    #: SOFT reasons that were waived because of strong recruiting markers (dry-run/regate display).
    waived: tuple[str, ...] = ()

    @property
    def sensitive(self) -> bool:
        return self.decision is GateDecision.SENSITIVE


# HARD rules always hold, whatever else is true. Everything not listed as SOFT is HARD
# (fail closed), including every error/uncertainty reason.
SOFT_RULES = frozenset({
    "password", "do_not_share", "statement", "upi", "ifsc", "kyc", "pan_phrase", "aadhaar",
    "banking", "tax", "government_id", "sender_name",
})
# Security-alert rules are HARD for account-security senders and SOFT for everyone else.
SECURITY_ALERT_RULES = frozenset({"login_alert", "new_device", "two_factor"})


def is_hard(reason: str, *, security_sender: bool, hard_sender_tier: bool) -> bool:
    if reason in SECURITY_ALERT_RULES:
        return security_sender
    if reason == "sender_tier":
        return hard_sender_tier  # government / account-security tier; financial tier is SOFT
    return reason not in SOFT_RULES


def hard_reasons(result: GateResult, *, security_sender: bool, hard_sender_tier: bool) -> tuple[str, ...]:
    return tuple(r for r in result.reasons
                 if is_hard(r, security_sender=security_sender, hard_sender_tier=hard_sender_tier))


def _ci(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Matched case-insensitively against folded sender name + subject + body.
PATTERNS: dict[str, re.Pattern[str]] = {
    "otp": _ci(r"\b[o0][\W_]{0,2}t[\W_]{0,2}p\b|\bone[\s-]*time[\s-]*(?:password|passcode|pin|code)\b"),
    "verification_code": _ci(
        r"\b(?:verification|verify|security|confirmation|authentication|auth|login|log[\s-]?in|"
        r"sign[\s-]?in|access|activation|one[\s-]?time|2fa|mfa)\s+(?:code|pin|number|key)s?\b"
        r"|\b(?:your|the)\s+(?:code|pin)\s*(?:is|:)"
    ),
    "passcode": _ci(r"\bpass[\s-]?codes?\b"),
    "two_factor": _ci(
        r"\b(?:2fa|mfa|two[\s-]*factor|2[\s-]*step|two[\s-]*step|multi[\s-]*factor)\b"
    ),
    # share/forward/disclose within ~6 words of a secret word, either order.
    # Generic footers ("do not forward this email") do not fire.
    "do_not_share": _ci(
        r"\b(?:share|sharing|forward|disclose|reveal)\b(?:\W+\w+){0,6}?\W+"
        r"(?:[o0]tp|codes?|passwords?|pass\s?codes?|pins?|m-?pin|cvv)\b"
        r"|\b(?:[o0]tp|codes?|passwords?|pass\s?codes?|pins?|m-?pin|cvv)\b(?:\W+\w+){0,6}?\W+"
        r"(?:share|sharing|forward|disclose|reveal)\b"
    ),
    "password": _ci(
        r"\b(?:password|passcode|pin)\s+(?:reset|change[ds]?|recovery|expir\w*)\b"
        r"|\breset\s+(?:your\s+|the\s+)?(?:password|pin)\b|\bforgot\s+(?:your\s+)?password\b"
        r"|\b(?:temporary|temp|new|your|login|one[\s-]*time)\s+password\b|\bpassword\s*(?:is|:|=)"
    ),
    "login_alert": _ci(
        r"\b(?:sign[\s-]?in|log[\s-]?in|logon)\s+(?:alert|attempts?|activity|notification|detected|from|to\s+your)\b"
        r"|\bnew\s+(?:sign[\s-]?in|log[\s-]?in)\b|\bsecurity\s+(?:alert|notification|warning)\b"
        r"|\bsuspicious\s+(?:activity|sign|log|attempt)|\bsomeone\s+(?:tried|signed|logged)\b"
    ),
    "new_device": _ci(r"\bnew\s+(?:device|browser|location)\b|\bunrecogni[sz]ed\s+(?:device|sign|login)\b"),
    "transaction": _ci(r"\btransactions?\b|\btxn\b|\btrxn\b"),
    "debited_credited": _ci(
        r"\b(?:debited|credited)\b|\b(?:debit|credit)\s+(?:card|alert|notification|advice)\b"
    ),
    "statement": _ci(r"\b(?:e-?)?statements?\b"),
    "upi": _ci(
        r"\bupi\b|\bvpa\b|\bbhim\b|(?<![\w.-])[\w.-]+@(?:ok(?:axis|hdfcbank|icici|sbi)|ybl|ibl|axl|paytm|apl|"
        r"upi|axisbank|icici|sbi|hdfcbank|kotak|yapl|pt(?:yes|axis|hdfc|sbi))\b"
    ),
    "ifsc": _ci(r"\bifsc\b"),
    "account_number": _ci(r"\b(?:a/c|acct|account)\s*(?:no\b\.?|number|num\b|#)|\ba/c\b"),
    "card_ending": _ci(
        r"\bcard\s+(?:ending|no\b\.?|number)|\bending\s+(?:in|with)\s+[x*•\d]|(?<![x*•])[x*•]{2,}[\s-]?\d{4}\b"
    ),
    "kyc": _ci(r"\b(?:e-?|c-?|re-?|v-?)?kyc\b"),
    "pan_phrase": _ci(r"\bpan\s+(?:card|number|no\b|details|verification)|\bpermanent\s+account\s+number\b"),
    "aadhaar": _ci(r"\baa?dh?aa?r\b|\buidai\b|\bvirtual\s+id\b"),
    "banking": _ci(
        r"\bcvv\b|\bm-?pin\b|\bt-?pin\b|\b(?:upi|atm)\s+pin\b|\b(?:net|internet|mobile)\s*banking\b"
        r"|\bneft\b|\brtgs\b|\bimps\b|\bbeneficiary\b|\bavailable\s+balance\b|\bavl\.?\s*bal\b"
        r"|\be-?mandate\b|\bautopay\b|\bemi\b|\bdemat\b|\bwallet\b"
    ),
    "crypto_secret": _ci(r"\b(?:seed|recovery|secret)\s+(?:phrase|words)\b|\bprivate\s+key\b"),
    "tax": _ci(
        r"\bincome[\s-]*tax\b|\bitr(?:-?\d)?\b|\btds\b|\bform[\s-]*16\b|\b26\s?as\b|\bgstin?\b"
        r"|\btax\s+(?:return|refund|notice|demand|filing|invoice|credit)\b|\bassessment\s+year\b"
    ),
    "government_id": _ci(
        r"\bpassport\s+(?:number|no\b|application|appointment|renewal)|\bvoter\s+id\b"
        r"|\bdriving\s+licen[cs]e\b|\bdigilocker\b|\bssn\b|\bsocial\s+security\s+number\b"
    ),
    "hindi": re.compile(r"ओटीपी|पासवर्ड|सत्यापन\s*कोड|खाता\s*संख्या|लेन\s*-?\s*देन|डेबिट|क्रेडिट|आधार"),
}

# Case-sensitive formats, matched against folded text without lowercasing.
FORMAT_PATTERNS: dict[str, re.Pattern[str]] = {
    "ifsc_code": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
}

_PAN_NUMBER = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_PAN_WORD = re.compile(r"\bPAN\b|\bpermanent\s+account\s+number\b", re.IGNORECASE)
_AADHAAR_CANDIDATE = re.compile(r"(?<![\d.,])([2-9]\d{3})[\s-]?(\d{4})[\s-]?(\d{4})(?![\d.,])")
_AADHAAR_WORD = re.compile(r"\baa?dh?aa?r\b|\buidai?\b", re.IGNORECASE)
_NEAR = 50

# Verhoeff checksum tables (Aadhaar numbers carry a Verhoeff check digit).
_VD = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5), (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7), (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3), (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VP = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4), (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7), (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_valid(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VD[c][_VP[i % 8][int(ch)]]
    return c == 0


def _word_near(text: str, start: int, end: int, word: re.Pattern[str]) -> bool:
    return bool(word.search(text[max(0, start - _NEAR) : end + _NEAR]))


def _aadhaar_number(text: str) -> bool:
    for m in _AADHAAR_CANDIDATE.finditer(text):
        if verhoeff_valid("".join(m.groups())) and _word_near(text, m.start(), m.end(), _AADHAAR_WORD):
            return True
    return False


def _pan_number(text: str) -> bool:
    return any(_word_near(text, m.start(), m.end(), _PAN_WORD) for m in _PAN_NUMBER.finditer(text))

# A sender display name that names a bank/payment brand. Skipped when the
# user has explicitly put the sender in PRIORITY (e.g. a fintech's recruiter).
SENDER_NAME = _ci(
    r"\bbank\b|\bhdfc\b|\bicici\b|\bsbi\b|\baxis\b|\bkotak\b|\bpaytm\b|\bphonepe\b|\bg\s?pay\b|"
    r"\bgoogle\s+pay\b|\brazorpay\b|\bzerodha\b|\bgroww\b|\bupstox\b|\bcred\b|\bamex\b|"
    r"\bamerican\s+express\b|\bvisa\b|\bmastercard\b|\brupay\b|\bnpci\b|\buidai\b|\bincome\s+tax\b|"
    r"\bnsdl\b|\bcdsl\b|\bprotean\b|\bindusind\b|\bidfc\b|\bpaypal\b|\bsecurities\b|\bmutual\s+fund\b"
)

_STANDALONE_NUMBER = re.compile(r"(?<![\d.,/])(?:\d{3}[\s-]\d{3}|\d{4,8})(?![\d.,/])")
_CODE_WORDS = _ci(r"\bcodes?\b|\b[o0]tp\b|\bverif\w*|\bpass[\s-]?code\b|\bpin\b|\bauthenticat\w*")
_MONTH = _ci(r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b")
_WINDOW = 60


def _looks_like_year(text: str, m: re.Match[str]) -> bool:
    value = m.group(0)
    if len(value) != 4 or not value.isdigit() or not 1900 <= int(value) <= 2099:
        return False
    after = text[m.end() : m.end() + 4]
    near = text[max(0, m.start() - 20) : m.end() + 20]
    return bool(re.match(r"-\d\d-", after) or _MONTH.search(near))


def _code_near_number(text: str) -> bool:
    for m in _STANDALONE_NUMBER.finditer(text):
        if _looks_like_year(text, m):
            continue
        window = text[max(0, m.start() - _WINDOW) : m.end() + _WINDOW]
        if _CODE_WORDS.search(window):
            return True
    return False


def scan_text(text: str) -> tuple[str, ...]:
    """Names of every sensitive pattern found in ``text``."""
    folded = fold(text)
    hits = [name for name, p in PATTERNS.items() if p.search(folded)]
    hits += [name for name, p in FORMAT_PATTERNS.items() if p.search(folded)]
    if _pan_number(folded):
        hits.append("pan")
    if _aadhaar_number(folded):
        hits.append("aadhaar_number")
    if _code_near_number(folded):
        hits.append("code_near_number")
    return tuple(hits)


def evaluate(msg: FetchedMessage, tier: Tier, *, sender_override: bool = False) -> GateResult:
    """``sender_override``: a recruiting override applies, so skip sender-based heuristics.

    Content rules always apply.
    """
    try:
        reasons: list[str] = []
        if tier is Tier.SENSITIVE:
            reasons.append("sender_tier")
        if not msg.content_complete:
            reasons.append("unparsed_content")
        if "@" not in msg.sender_address:
            reasons.append("unknown_sender")
        if tier is not Tier.PRIORITY and not sender_override and SENDER_NAME.search(fold(msg.sender_name)):
            reasons.append("sender_name")
        reasons.extend(scan_text(f"{msg.sender_name}\n{msg.subject}\n{msg.body_text}"))
        if reasons:
            return GateResult(GateDecision.SENSITIVE, tuple(dict.fromkeys(reasons)))
        return GateResult(GateDecision.SAFE)
    except Exception:
        log.exception("sensitivity gate error; failing closed")
        return GateResult(GateDecision.SENSITIVE, ("gate_error",))
