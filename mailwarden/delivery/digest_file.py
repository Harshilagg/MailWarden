"""Optional Markdown copy of each digest in a local folder (opt-in; plaintext, 0600 files)."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from mailwarden.delivery.base import DigestSink
from mailwarden.security.fs import ensure_private_dir, write_private


class MarkdownDigestSink(DigestSink):
    def __init__(self, folder: Path) -> None:
        self._folder = folder

    def write(self, user_id: str, digest_markdown: str, generated_at: dt.datetime) -> None:
        ensure_private_dir(self._folder)
        name = f"digest-{generated_at.astimezone():%Y-%m-%d-%H%M}.md"
        write_private(self._folder / name, digest_markdown)
