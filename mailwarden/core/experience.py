"""Experience level of a job, from the matching policy's experience section. Local only.

Status: verified_fresher / stretch / too_senior / unknown, decided in this order:
1. your own quick check on the dashboard ("Fresher OK" / "Too senior");
2. years stated in the title or listing details ("(0-2 yrs)", "salary-1 year(s)");
3. years stated in the job description, only where they are about required experience
   (not "preferred"/"nice to have", not "our 20+ years serving clients"); with several
   requirements, the highest minimum counts;
4. a senior signal in the title or details ("Senior", "Lead", "SDE II" ...);
5. a fresher signal in the title or details ("SDE 1", "fresher", "2026 batch" ...);
6. a fresher-only source (e.g. Naukri Campus);
otherwise unknown. Ranges use the minimum: "2-5 years" means 2.
Signals are read from the title and details only: a description that mentions "senior
engineers" on the team or a "graduate degree" says nothing about this role's level.

minimum <= pass_max_min_years -> verified_fresher; <= stretch_min_years -> stretch; above -> too_senior.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mailwarden.core.policy import MatchingPolicy
from mailwarden.core.text import clean

VERIFIED_FRESHER = "verified_fresher"
STRETCH = "stretch"
TOO_SENIOR = "too_senior"
UNKNOWN = "unknown"
READY = (VERIFIED_FRESHER, STRETCH)  # may go into Apply today

_UNIT = r"(?:years?|yrs?|y)(?:\s*\(s\))?"
_END = r"(?![a-z])"
_RANGE = re.compile(rf"(?<![\d.])(\d{{1,2}})\s*(?:-|–|—|to)\s*(\d{{1,2}})\s*\+?\s*{_UNIT}{_END}", re.IGNORECASE)
_PLUS = re.compile(rf"(?<![\d.])(\d{{1,2}})\s*\+\s*{_UNIT}{_END}", re.IGNORECASE)
_MIN = re.compile(rf"\b(?:minimum|min\.?|at\s*least|atleast)\s*(?:of\s+)?(\d{{1,2}})\s*\+?\s*{_UNIT}{_END}",
                  re.IGNORECASE)
_PLAIN = re.compile(rf"(?<![\d.])(\d{{1,2}})\s*{_UNIT}{_END}", re.IGNORECASE)
_CONTEXT = re.compile(r"\b(?:experience|exp|work(?:ing)?|industry|professional|relevant|hands[\s-]?on|"
                      r"requires?|required|requirements?|must|need(?:s|ed)?|looking\s+for)\b",
                      re.IGNORECASE)
_SOFT = re.compile(r"\b(?:preferred|nice[\s-]to[\s-]have|good[\s-]to[\s-]have|plus|bonus|ideally|desirable|"
                   r"advantage(?:ous)?|optional)\b", re.IGNORECASE)
_NOT_A_REQUIREMENT = re.compile(r"\b(?:founded|history|in\s+business|serving|legacy|established|track\s+record|"
                                r"old|warranty|tenure|bond|anniversary)\b", re.IGNORECASE)
_NOT_EXPERIENCE_AFTER = re.compile(r"\s*(?:program(?:me)?|course|degree|integrated|old|warranty|bond)\b",
                                   re.IGNORECASE)
_SENTENCE_END = re.compile(r"[.!?;\n•]")
MAX_PLAUSIBLE = 15  # "20+ years" is about a company, not a job requirement


@dataclass(frozen=True)
class ExperienceResult:
    status: str
    min_years: int | None = None
    evidence: str = ""  # why, in plain words ("title says 0-2 yrs", "title has 'senior'")

    @property
    def ready(self) -> bool:
        return self.status in READY


def _mentions(text: str, *, need_context: bool) -> list[tuple[int, str]]:
    """(minimum years, the phrase) for each experience statement in ``text``."""
    text = clean(text)[:20_000]
    found: list[tuple[int, str, int, int]] = []  # years, phrase, start, end
    taken: list[tuple[int, int]] = []

    def free(a: int, b: int) -> bool:
        return all(b <= s or a >= e for s, e in taken)

    for rx, group in ((_RANGE, 1), (_MIN, 1), (_PLUS, 1), (_PLAIN, 1)):
        for m in rx.finditer(text):
            if not free(m.start(), m.end()):
                continue
            if rx is _RANGE and int(m.group(1)) > int(m.group(2)):
                continue
            taken.append((m.start(), m.end()))
            found.append((int(m.group(group)), m.group(0).strip(), m.start(), m.end()))
    out = []
    for years, phrase, a, b in sorted(found, key=lambda f: f[2]):
        if years > MAX_PLAUSIBLE or _NOT_EXPERIENCE_AFTER.match(text, b):
            continue
        if need_context:  # judge the statement by its own sentence only
            start = max((m.end() for m in _SENTENCE_END.finditer(text, max(0, a - 160), a)), default=max(0, a - 160))
            stop = _SENTENCE_END.search(text, b, b + 160)
            sentence = text[start: stop.start() if stop else b + 160]
            if not _CONTEXT.search(sentence) or _SOFT.search(sentence) or _NOT_A_REQUIREMENT.search(sentence):
                continue
        out.append((years, phrase))
    return out


def _by_years(years: int, policy: MatchingPolicy) -> str:
    e = policy.experience
    if years <= e.pass_max_min_years:
        return VERIFIED_FRESHER
    if years <= e.stretch_min_years:
        return STRETCH
    return TOO_SENIOR


def classify(policy: MatchingPolicy, *, title: str, details: str | None = None, jd_text: str | None = None,
             sources: tuple[str, ...] = (), check: str | None = None) -> ExperienceResult:
    if check == "fresher":
        return ExperienceResult(VERIFIED_FRESHER, None, "you checked it: fresher OK")
    if check == "senior":
        return ExperienceResult(TOO_SENIOR, None, "you checked it: too senior")
    short = clean(f"{title} · {details or ''}")
    if stated := _mentions(short, need_context=False):
        years, phrase = min(stated)
        return ExperienceResult(_by_years(years, policy), years, f"listing says {phrase}")
    if jd_text and (stated := _mentions(jd_text, need_context=True)):
        years, phrase = max(stated)
        return ExperienceResult(_by_years(years, policy), years, f"job description says {phrase}")
    if word := policy.senior.find(short):
        return ExperienceResult(TOO_SENIOR, None, f"title has '{word}'")
    if word := policy.fresher.find(short):
        return ExperienceResult(VERIFIED_FRESHER, None, f"title has '{word}'")
    wanted = set(policy.experience.fresher_sources)
    if src := next((s for s in sources if s and s.lower() in wanted), None):
        return ExperienceResult(VERIFIED_FRESHER, None, f"{src} lists fresher jobs only")
    return ExperienceResult(UNKNOWN, None, "no experience level in the alert")


def required_years(jd_text: str | None) -> int | None:
    """The highest required minimum stated in a job description (None if it states none)."""
    stated = _mentions(jd_text or "", need_context=True)
    return max(y for y, _ in stated) if stated else None
