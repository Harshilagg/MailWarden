from importlib import resources

import pytest

from mailwarden.core.models import Tier
from mailwarden.core.sender_rules import RulesError, SenderRules, set_entry_tier

SEED = resources.files("mailwarden.templates").joinpath("sender_rules.yaml").read_text()


def test_seed_loads_and_has_all_tiers():
    rules = SenderRules.from_yaml(SEED)
    assert rules.tier_for("no-reply@greenhouse.io") is Tier.PRIORITY
    assert rules.tier_for("alerts@hdfcbank.net") is Tier.SENSITIVE
    assert rules.tier_for("x@gmail.com") is Tier.DEFAULT


@pytest.mark.parametrize(
    "addr, tier",
    [
        ("ALERTS@HDFCBANK.NET", Tier.SENSITIVE),
        ("a@alerts.hdfcbank.net", Tier.SENSITIVE),
        ("a@x.hdfc.bank.in", Tier.SENSITIVE),
        ("a@incometax.gov.in", Tier.SENSITIVE),
        ("a@us.greenhouse-mail.io", Tier.PRIORITY),
        ("a@nothdfcbank.net", Tier.DEFAULT),
        ("a@hdfcbank.net.evil.com", Tier.DEFAULT),
        ("not-an-address", Tier.DEFAULT),
    ],
)
def test_matching(addr, tier):
    assert SenderRules.from_yaml(SEED).tier_for(addr) is tier


def test_address_beats_domain_and_specific_beats_parent():
    rules = SenderRules.from_yaml(
        "priority:\n  domains: [careers.bank.example]\n  senders: [talent@bank.example]\n"
        "sensitive:\n  domains: [bank.example]\n"
    )
    assert rules.tier_for("talent@bank.example") is Tier.PRIORITY
    assert rules.tier_for("x@careers.bank.example") is Tier.PRIORITY
    assert rules.tier_for("x@bank.example") is Tier.SENSITIVE


def test_duplicate_across_tiers_rejected():
    with pytest.raises(RulesError):
        SenderRules.from_yaml("priority:\n  domains: [a.com]\nsensitive:\n  domains: [A.com]\n")


@pytest.mark.parametrize("bad", ["priority: {domains: ['not a domain']}", "priority: {nope: []}", "- a\n- b", ": :"])
def test_invalid_files_rejected(bad):
    with pytest.raises(RulesError):
        SenderRules.from_yaml(bad)


def test_with_priority_domains_does_not_override():
    rules = SenderRules.from_yaml(SEED).with_priority_domains(["acme.com", "hdfcbank.net", "bad domain"])
    assert rules.tier_for("hr@acme.com") is Tier.PRIORITY
    assert rules.tier_for("x@hdfcbank.net") is Tier.SENSITIVE


def test_promote_moves_entry_and_keeps_comments():
    out = set_entry_tier(SEED, "hackerrank.com", Tier.IGNORE)
    rules = SenderRules.from_yaml(out)
    assert rules.tier_of_entry("hackerrank.com") is Tier.IGNORE
    assert "# Applicant tracking systems" in out and "# Indian banks" in out
    assert out.count("- hackerrank.com") == 1


def test_promote_address_into_empty_list_and_back_to_default():
    out = set_entry_tier(SEED, "Talent@Razorpay.com", Tier.PRIORITY)
    rules = SenderRules.from_yaml(out)
    assert rules.tier_for("talent@razorpay.com") is Tier.PRIORITY
    assert rules.tier_for("noreply@razorpay.com") is Tier.SENSITIVE
    back = set_entry_tier(out, "talent@razorpay.com", Tier.DEFAULT)
    assert SenderRules.from_yaml(back).tier_of_entry("talent@razorpay.com") is Tier.DEFAULT


def test_promote_rejects_garbage():
    with pytest.raises(RulesError):
        set_entry_tier(SEED, "not a sender", Tier.PRIORITY)
