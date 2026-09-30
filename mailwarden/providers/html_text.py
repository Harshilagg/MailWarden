"""HTML -> plain text using only the stdlib.

Drops scripts/styles and visually hidden elements (display:none,
font-size:0, etc.), which are a common carrier for prompt injection.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

_BLOCK = frozenset(
    "p div br li tr td th h1 h2 h3 h4 h5 h6 table section article header footer "
    "blockquote hr ul ol pre".split()
)
_SKIP = frozenset("script style head title noscript template svg object iframe".split())
_VOID = frozenset("area base br col embed hr img input link meta source track wbr".split())
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|"
    r"(?:font-size|max-height|height|opacity)\s*:\s*0(?![.\d])",
    re.IGNORECASE,
)


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._stack: list[tuple[str, bool]] = []

    def _hidden(self) -> bool:
        return any(h for _, h in self._stack)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _BLOCK and not self._hidden():
            self.parts.append("\n")
        if tag in _VOID:
            return
        a = dict(attrs)
        hides = (
            tag in _SKIP
            or "hidden" in a
            or bool(_HIDDEN_STYLE.search(a.get("style") or ""))
        )
        self._stack.append((tag, hides))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _BLOCK and not self._hidden():
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break
        if tag in _BLOCK and not self._hidden():
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._hidden():
            self.parts.append(data)


def _normalise(text: str) -> str:
    lines = [re.sub(r"[ \t ]+", " ", line).strip() for line in text.splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def html_to_text(html: str) -> str:
    parser = _Extractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return ""  # fail closed: no text rather than half-parsed markup
    return _normalise("".join(parser.parts))
