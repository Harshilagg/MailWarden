"""Local, deterministic deadline extraction (runs on the original text; nothing is sent anywhere)."""

from __future__ import annotations

import datetime as dt
import re

from mailwarden.core.text import clean

_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1)}
_MON = r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?"
_DAY_MONTH = re.compile(rf"\b(\d{{1,2}})(?:st|nd|rd|th)?\s+(?:of\s+)?{_MON}(?:,?\s+(\d{{4}}))?", re.IGNORECASE)
_MONTH_DAY = re.compile(rf"\b{_MON}\s+(\d{{1,2}})(?:st|nd|rd|th)?(?:,?\s+(\d{{4}}))?", re.IGNORECASE)
_NUMERIC = re.compile(r"(?<![\d/.-])(\d{1,2})[/.-](\d{1,2})[/.-](\d{4}|\d{2})(?![\d/.-])")
_ISO = re.compile(r"(?<![\d-])(\d{4})-(\d{2})-(\d{2})(?![\d-])")
_KEYWORD = re.compile(
    r"\b(?:by|before|deadline|last\s+date|closes?|closing|ends?|ending|till|until|due|register|registration|"
    r"submit|submission|apply\s+by|expires?|on)\b",
    re.IGNORECASE,
)
_WINDOW = 40
_HORIZON = dt.timedelta(days=365)


def _make(year: int | None, month: int, day: int, today: dt.date) -> dt.date | None:
    try:
        if year is None:
            d = dt.date(today.year, month, day)
            if d >= today:
                return d
            # A recent past date ("was on 5 Sep") is in the past, not next year.
            return None if (today - d).days <= 180 else dt.date(today.year + 1, month, day)
        if year < 100:
            year += 2000
        return dt.date(year, month, day)
    except ValueError:
        return None


def _candidates(text: str, today: dt.date):
    for m in _DAY_MONTH.finditer(text):
        yield m.start(), _make(int(m.group(3)) if m.group(3) else None, _MONTHS[m.group(2).lower()[:3]], int(m.group(1)), today)
    for m in _MONTH_DAY.finditer(text):
        yield m.start(), _make(int(m.group(3)) if m.group(3) else None, _MONTHS[m.group(1).lower()[:3]], int(m.group(2)), today)
    for m in _NUMERIC.finditer(text):  # day-first, as used in India
        yield m.start(), _make(int(m.group(3)), int(m.group(2)), int(m.group(1)), today)
    for m in _ISO.finditer(text):
        yield m.start(), _make(int(m.group(1)), int(m.group(2)), int(m.group(3)), today)


def find_deadline(text: str, today: dt.date) -> dt.date | None:
    """Earliest upcoming date (within a year) that has deadline wording just before it."""
    text = clean(text)[:20000]
    best = None
    for start, d in _candidates(text, today):
        if d is None or not (today <= d <= today + _HORIZON):
            continue
        if not _KEYWORD.search(text[max(0, start - _WINDOW) : start]):
            continue
        best = d if best is None or d < best else best
    return best
