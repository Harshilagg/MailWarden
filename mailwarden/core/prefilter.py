"""Local job prefilter (no LLM, no network).

Marks jobs that are clearly not for a new grad or not wanted. It never deletes
anything: filtered jobs stay visible under "All" as "Filtered: <reason>".
Evaluated on demand from the current profile.yaml, so edits apply immediately.

Rules, from the title (and the job description, when one is available):
1. seniority words: senior, sr, lead, manager, architect, director, principal,
   staff, head, VP, chief ...
2. a level above new grad (SDE II, Engineer 2, SWE III, L4 ...), unless the job
   description says 0-2 years / fresher / new grad;
3. "N+ years" (or "N-M years", "minimum N years") with N > 2;
4. avoid_roles (entries may use "/" alternatives; "security-only", "sales",
   "support" and "non-engineering" are understood as categories);
5. a known location outside profile.locations, unless the job is remote and
   remote_ok is true.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mailwarden.core.text import clean

_SENIORITY = re.compile(
    r"\b(senior|sr|snr|lead|leader|manager|mgr|architect|director|principal|staff|head|vp|"
    r"vice\s+president|chief|avp|distinguished|fellow)\b",
    re.IGNORECASE,
)
_ROLE_NOUN = r"(?:engineer|developer|sde|swe|programmer|analyst|consultant|scientist|member\s+of\s+technical\s+staff)"
_LEVEL = re.compile(
    rf"\b{_ROLE_NOUN}\s*[-–]?\s*(ii|iii|iv|v|2|3|4|5)\b|\b(?:sde|swe)(2|3|4)\b|\b(l[4-9]|level\s*[2-9]|e[4-9])\b",
    re.IGNORECASE,
)
_ENTRY_LEVEL = re.compile(
    r"\b0\s*(?:-|–|to)\s*[12]\s*(?:\+\s*)?(?:years?|yrs?)\b|\bfreshers?\b|\bnew\s+grad(?:uate)?s?\b|"
    r"\bentry[\s-]level\b|\bno\s+(?:prior\s+)?experience\s+required\b|\b20(?:2[4-7])\s+(?:batch|graduates?|pass-?outs?)\b",
    re.IGNORECASE,
)
_YEARS_PLUS = re.compile(r"\b(\d{1,2})\s*\+\s*(?:years?|yrs?)\b", re.IGNORECASE)
_YEARS_RANGE = re.compile(r"\b(\d{1,2})\s*(?:-|–|to)\s*(\d{1,2})\s*(?:years?|yrs?)\b", re.IGNORECASE)
_YEARS_MIN = re.compile(r"\b(?:minimum|min\.?|at\s+least)\s+(?:of\s+)?(\d{1,2})\s*(?:years?|yrs?)\b", re.IGNORECASE)

_ENGINEERING = re.compile(
    r"\b(engineer(?:ing)?|developer|dev|sde|swe|programmer|software|backend|back-end|frontend|front-end|"
    r"full[\s-]?stack|devops|sre|platform|infrastructure|cloud|data|ml|ai|machine\s+learning|mobile|android|ios|"
    r"web|embedded|firmware|qa|test|automation|technical|tech|it|coding|intern(?:ship)?|trainee|graduate)\b",
    re.IGNORECASE,
)
_SECURITY = re.compile(
    r"\b(security|cyber\s*security|cybersecurity|soc|infosec|appsec|penetration|pentest(?:er|ing)?|vapt|grc|"
    r"threat|incident\s+response|forensics?|red\s+team|blue\s+team)\b",
    re.IGNORECASE,
)
_SOFTWARE_BUILDER = re.compile(
    r"\b(software|sde|swe|backend|back-end|full[\s-]?stack|developer|programmer|platform|sre|devops|"
    r"product\s+security\s+engineer)\b",
    re.IGNORECASE,
)
_CATEGORIES: dict[str, re.Pattern[str]] = {
    "sales": re.compile(r"\b(sales|pre-?sales|business\s+development|bde|bdr|sdr|account\s+(?:executive|manager)|"
                        r"inside\s+sales|telecaller|tele-?sales)\b", re.IGNORECASE),
    "support": re.compile(r"\b(support|help\s*desk|service\s+desk|customer\s+(?:success|service|care)|"
                          r"call\s+cent(?:er|re)|l1|l2)\b", re.IGNORECASE),
    "non-engineering": re.compile(
        r"\b(marketing|hr|human\s+resources?|recruit(?:er|ment|ing)|talent\s+acquisition|finance|financial|"
        r"accountant|accounts|accounting|legal|lawyer|content\s+writer|copywriter|writer|graphic\s+designer|"
        r"ui/?ux\s+designer|operations\s+executive|business\s+analyst|teacher|tutor|faculty|nurse|"
        r"civil\s+(?:site\s+)?engineer|site\s+engineer|mechanical\s+engineer|electrical\s+engineer)\b",
        re.IGNORECASE),
}
_REMOTE = re.compile(r"\b(remote|work\s+from\s+home|wfh|anywhere|distributed)\b", re.IGNORECASE)
_COUNTRY_ONLY = re.compile(r"^\s*(?:pan[\s-]*)?india\s*$|^\s*multiple\s+locations?\s*$", re.IGNORECASE)
_LOCATION_ALIASES = {
    "bengaluru": ("bengaluru", "bangalore", "blr"),
    "bangalore": ("bengaluru", "bangalore", "blr"),
    "gurugram": ("gurugram", "gurgaon"),
    "gurgaon": ("gurugram", "gurgaon"),
    "mumbai": ("mumbai", "bombay", "navi mumbai"),
    "delhi": ("delhi", "new delhi", "ncr", "delhi ncr"),
    "chennai": ("chennai", "madras"),
    "remote": ("remote", "work from home", "wfh", "anywhere"),
}


@dataclass(frozen=True)
class FilterResult:
    reasons: tuple[str, ...] = ()

    @property
    def excluded(self) -> bool:
        return bool(self.reasons)

    @property
    def label(self) -> str:
        return "Filtered: " + "; ".join(self.reasons) if self.reasons else ""


def _norm(text: str) -> str:
    return " " + re.sub(r"[^a-z0-9+#]+", " ", clean(text).lower()).strip() + " "


def _role_alternatives(entry: str) -> list[str]:
    return [a for a in (_norm(p).strip() for p in str(entry).split("/")) if a]


def _required_years(text: str) -> int | None:
    """The smallest experience requirement stated as N+ / N-M / minimum N years."""
    found = [int(m.group(1)) for m in _YEARS_PLUS.finditer(text)]
    found += [int(m.group(1)) for m in _YEARS_RANGE.finditer(text) if int(m.group(1)) <= int(m.group(2))]
    found += [int(m.group(1)) for m in _YEARS_MIN.finditer(text)]
    found = [n for n in found if n <= 30]
    return min(found) if found else None


def _avoid_reason(title: str, entry: str) -> str | None:
    key = _norm(entry).strip()
    if key in ("security only", "security"):
        if _SECURITY.search(title) and not _SOFTWARE_BUILDER.search(title):
            return "security-only role"
        return None
    if key in _CATEGORIES:
        if _CATEGORIES[key].search(title) and (key != "support" or not _SOFTWARE_BUILDER.search(title)):
            return f"{entry} role"
        return None
    if key == "non engineering":
        if _CATEGORIES["non-engineering"].search(title) or not _ENGINEERING.search(title):
            return "non-engineering role"
        return None
    t = _norm(title)
    if any(f" {alt} " in t for alt in _role_alternatives(entry)):
        return f"avoid role: {entry}"
    return None


def _location_ok(location: str, wanted: list[str], remote_ok: bool) -> bool:
    loc = clean(location).lower()
    if not loc.strip() or _COUNTRY_ONLY.match(loc):
        return True  # unknown / country-wide: can't tell, keep it
    if remote_ok and _REMOTE.search(loc):
        return True
    for want in wanted:
        variants = _LOCATION_ALIASES.get(want.strip().lower(), (want.strip().lower(),))
        if want.strip().lower() == "remote" and not remote_ok:
            continue
        if any(v and v in loc for v in variants):
            return True
    return False


def prefilter(title: str, location: str | None, profile: dict, jd_text: str | None = None) -> FilterResult:
    title = clean(title or "")
    jd = clean(jd_text or "")
    reasons: list[str] = []

    if m := _SENIORITY.search(title):
        reasons.append(f"seniority ({m.group(1)})")

    if m := _LEVEL.search(title):
        level = next(g for g in m.groups() if g)
        if not (jd and _ENTRY_LEVEL.search(jd)):
            reasons.append(f"level above new grad ({level.upper()})")

    years = _required_years(f"{title}\n{jd}")
    if years is not None and years > 2:
        reasons.append(f"needs {years}+ years")

    for entry in profile.get("avoid_roles") or []:
        if reason := _avoid_reason(title, entry):
            reasons.append(reason)
            break

    wanted = [str(x) for x in (profile.get("locations") or [])]
    remote_ok = bool(profile.get("remote_ok", True))
    if location and wanted and not _location_ok(location, wanted, remote_ok):
        reasons.append(f"location ({clean(location)[:40]})")

    return FilterResult(tuple(reasons))
