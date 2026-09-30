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
    r"(?:max-height|height|opacity|line-height)\s*:\s*0(?![.\d])|"
    r"font-size\s*:\s*(?:0(?:\.\d+)?|1)(?:px|pt)?(?![.\d])",
    re.IGNORECASE,
)


_MAX_DEPTH = 2000  # deeper nesting is treated as unparseable (the gate then fails closed)
_END_TAG_SEARCH = 200  # how far back a closing tag looks for its opener


class _TooDeep(ValueError):
    pass


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._stack: list[tuple[str, bool]] = []
        self._hidden_count = 0  # O(1) "inside a hidden element?" instead of scanning the stack

    def _hidden(self) -> bool:
        return self._hidden_count > 0

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
        if len(self._stack) >= _MAX_DEPTH:
            raise _TooDeep("HTML nesting too deep")
        self._stack.append((tag, hides))
        self._hidden_count += hides

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _BLOCK and not self._hidden():
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        lowest = max(0, len(self._stack) - _END_TAG_SEARCH)
        for i in range(len(self._stack) - 1, lowest - 1, -1):
            if self._stack[i][0] == tag:
                self._hidden_count -= sum(h for _, h in self._stack[i:])
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


class HtmlParseError(ValueError):
    pass


def html_to_text(html: str) -> str:
    parser = _Extractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception as e:
        raise HtmlParseError("could not parse HTML body") from e
    return _normalise("".join(parser.parts))


_LOOKS_LIKE_HTML = re.compile(r"<\s*(?:html|body|div|table|p|br|span|img)\b[^>]*>", re.IGNORECASE)


def looks_like_html(text: str) -> bool:
    return len(_LOOKS_LIKE_HTML.findall(text[:5000])) >= 2


class _LinkExtractor(_Extractor):
    """Also collects visible anchors as (text, href)."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._anchor: list[str] | None = None
        self._href = ""

    def handle_starttag(self, tag, attrs):
        if tag == "a" and not self._hidden():
            self._href = dict(attrs).get("href") or ""
            self._anchor = []
        super().handle_starttag(tag, attrs)

    def handle_data(self, data):
        if self._anchor is not None and not self._hidden():
            self._anchor.append(data)
        super().handle_data(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._anchor is not None:
            text = re.sub(r"\s+", " ", "".join(self._anchor)).strip()
            href = self._href.strip()
            if href.lower().startswith(("http://", "https://")) and len(href) <= 2000:
                self.links.append((text[:200], href))
            self._anchor = None
        super().handle_endtag(tag)


def html_links(html: str, limit: int = 200) -> list[tuple[str, str]]:
    parser = _LinkExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return []
    return parser.links[:limit]
