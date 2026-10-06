"""matching.yaml in the private mailwarden home: load, create from the template, check.

The file lives at <home>/config/matching.yaml (mode 600, in mode-700 folders), next to
profile.yaml. It holds preferences, not secrets, but it is personal, so it is kept out of
the repository like the profile.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import yaml

from mailwarden.core.policy import MatchingPolicy, PolicyError, parse
from mailwarden.security.fs import check_private, ensure_private_dir, write_private

MATCHING_FILE = Path("config") / "matching.yaml"
MAX_BYTES = 64 * 1024


def policy_path(home: Path) -> Path:
    return home / MATCHING_FILE


def template_text() -> str:
    return resources.files("mailwarden.templates").joinpath("matching.yaml").read_text("utf-8")


def init(home: Path) -> tuple[Path, bool]:
    """Create matching.yaml from the template if it doesn't exist. Returns (path, created)."""
    path = policy_path(home)
    if path.exists():
        return path, False
    ensure_private_dir(home)
    ensure_private_dir(path.parent)
    write_private(path, template_text())
    return path, True


def load(home: Path) -> MatchingPolicy | None:
    """The policy, or None when there is no matching.yaml yet. Raises PolicyError if it is invalid."""
    path = policy_path(home)
    if not path.exists():
        return None
    check_private(path.parent)
    check_private(path)
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES:
        raise PolicyError(f"{path} is larger than {MAX_BYTES // 1024} KB")
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as e:
        raise PolicyError(f"{path} is not valid YAML: {e}") from None
    return parse(data)
