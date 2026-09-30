"""Friendly, content-free explanations for why mail was held back.

Rule names are for dry-run and debugging only; the dashboard and
notifications use these labels.
"""

from __future__ import annotations

_LABELS: tuple[tuple[frozenset[str], str], ...] = (
    (frozenset({"otp", "verification_code", "passcode", "code_near_number", "two_factor", "hindi"}),
     "Contains a verification code"),
    (frozenset({"password"}), "About an account password"),
    (frozenset({"login_alert", "new_device"}), "Account security alert"),
    (frozenset({"aadhaar", "aadhaar_number", "pan", "pan_phrase", "kyc", "government_id"}), "Contains ID details"),
    (frozenset({"banking", "transaction", "card_ending", "debited_credited", "statement", "upi", "ifsc",
                "ifsc_code", "account_number", "do_not_share"}), "Banking or payment details"),
    (frozenset({"tax"}), "Tax or government mail"),
    (frozenset({"crypto_secret"}), "Contains a secret key or recovery phrase"),
    (frozenset({"sender_tier", "sender_name"}), "From a bank, payment or account-security sender"),
    (frozenset({"gate_error", "rules_error", "redaction_error", "unparsed_content", "unknown_sender"}),
     "Couldn't be checked safely, so it was held back"),
)


def friendly_reason(reasons: tuple[str, ...] | list[str]) -> str:
    found = set(reasons)
    for names, label in _LABELS:
        if found & names:
            return label
    return "Held back as sensitive"
