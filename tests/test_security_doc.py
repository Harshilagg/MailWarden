"""SECURITY.md must list exactly the hosts the code can ever talk to."""

import re
from pathlib import Path

from mailwarden.config import Settings
from mailwarden.security.net import allowed_hosts

DOC = Path(__file__).resolve().parents[1] / "SECURITY.md"


def _documented_hosts() -> set[str]:
    text = DOC.read_text()
    block = text.split("<!-- allowlist:start -->")[1].split("<!-- allowlist:end -->")[0]
    return set(re.findall(r"^\| `([^`]+)` \|", block, re.MULTILINE))


def test_security_md_matches_maximal_allowlist():
    everything_on = Settings.model_validate({"groq": {"enabled": True}, "outlook": {"enabled": True}})
    assert _documented_hosts() == set(allowed_hosts(everything_on))
