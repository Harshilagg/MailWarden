"""Matching policies for tests: the shipped template with sections overridden."""

import yaml

from mailwarden import matching
from mailwarden.core.policy import MatchingPolicy, parse


def policy(**sections) -> MatchingPolicy:
    """The template, with each given section merged over it (dicts) or replaced (lists)."""
    data = yaml.safe_load(matching.template_text())
    for name, value in sections.items():
        base = data.get(name)
        data[name] = {**base, **value} if isinstance(base, dict) and isinstance(value, dict) else value
    return parse(data)


# Bengaluru / Delhi NCR / remote, like a typical profile.
POLICY = policy(location={"allowed": ["Bengaluru", "Delhi NCR"], "remote_ok": True})
