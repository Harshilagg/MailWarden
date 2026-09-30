from importlib import resources

import pytest

from mailwarden.core.models import GateDecision, Tier
from mailwarden.core.sender_rules import SenderRules
from mailwarden.core.sensitivity_gate import evaluate, scan_text
from tests.fixtures.emails import SAFE, make

RULES = SenderRules.from_yaml(
    resources.files("mailwarden.templates").joinpath("sender_rules.yaml").read_text()
)


@pytest.mark.parametrize("case", SAFE, ids=[c[0] for c in SAFE])
def test_ordinary_mail_passes(case):
    _, sender, name, subject, body = case
    msg = make(sender, name, subject, body)
    result = evaluate(msg, RULES.tier_for(sender))
    assert result.decision is GateDecision.SAFE, result.reasons


@pytest.mark.parametrize(
    "text",
    [
        "Interview scheduled for Oct 3, 2026",
        "Round 2 on 2026-10-03, please confirm",
        "Complete the assessment by 15 October 2026",
        "The coding round lasts 90 minutes",
        "Offer letter attached, CTC 18 LPA",
        "Pan-India hiring drive",
        "Test ID 919876543210 for your HackerEarth challenge",
        "Call us at 1800 1234 5678",
    ],
)
def test_job_phrasing_does_not_trip(text):
    assert scan_text(text) == ()


@pytest.mark.parametrize(
    "text, rule",
    [
        ("Your OTP is 123456", "otp"),
        ("one-time passcode inside", "otp"),
        ("Enter the security code", "verification_code"),
        ("2-step verification is on", "two_factor"),
        ("Please DO NOT SHARE this", "do_not_share"),
        ("Reset your password", "password"),
        ("New sign-in from Chrome", "login_alert"),
        ("Unrecognised device", "new_device"),
        ("Amount credited to your a/c", "debited_credited"),
        ("Send to name@okhdfcbank", "upi"),
        ("IFSC: HDFC0001234", "ifsc"),
        ("Account No. ending", "account_number"),
        ("Card ending 1234", "card_ending"),
        ("Re-KYC due", "kyc"),
        ("PAN ABCDE1234F", "pan"),
        ("Aadhar linked", "aadhaar"),
        ("2345 6789 0123", "aadhaar_number"),
        ("Form 16 for FY", "tax"),
        ("Your seed phrase", "crypto_secret"),
        ("verify with 5521", "code_near_number"),
    ],
)
def test_individual_rules(text, rule):
    assert rule in scan_text(text)


def test_sender_tier_alone_is_sensitive():
    msg = make("alerts@hdfcbank.net", "Alerts", "Hello", "Nothing special here")
    r = evaluate(msg, Tier.SENSITIVE)
    assert r.decision is GateDecision.SENSITIVE and "sender_tier" in r.reasons


def test_priority_skips_display_name_heuristic_but_not_content():
    msg = make("talent@razorpay.com", "Razorpay Talent", "Interview", "Let's schedule a chat")
    assert evaluate(msg, Tier.PRIORITY).decision is GateDecision.SAFE
    assert evaluate(msg, Tier.DEFAULT).decision is GateDecision.SENSITIVE
    otp = make("talent@razorpay.com", "Razorpay Talent", "Login", "Your OTP is 123456")
    assert evaluate(otp, Tier.PRIORITY).decision is GateDecision.SENSITIVE


def test_reasons_never_contain_message_text():
    msg = make("a@x.com", "A", "Your OTP 918273", "code 918273")
    r = evaluate(msg, Tier.DEFAULT)
    assert all("918273" not in reason for reason in r.reasons)
