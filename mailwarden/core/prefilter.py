"""Local job prefilter, driven by matching.yaml (no LLM, no network).

A job is filtered only for things you can't or won't do:
1. hard_exclusions.role_types, matched as whole words in the title. Two have a built-in
   meaning: "internship" also catches "Intern" titles, Internshala internship links (even
   inside click-tracking links), listings that say "internship" and stipends ("Unpaid",
   up to ₹40,000 a month); "non-engineering" catches titles with no engineering word and
   no stack keyword;
2. hard_exclusions.conditions ("unpaid", "service bond" ...) in the title, details or JD;
3. experience: too_senior (see core.experience);
4. location: a known place outside location.allowed, unless remote and remote_ok.

The stack never filters: soft_penalties only lower the rank (``penalty``). An unknown
experience level passes the filter but is flagged "needs a quick check".
Nothing is deleted: filtered jobs stay visible with the reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

from mailwarden.core.experience import TOO_SENIOR, UNKNOWN, ExperienceResult, classify
from mailwarden.core.policy import MatchingPolicy
from mailwarden.core.text import clean

_INTERN_TITLE = re.compile(r"\binterns?(?:hips?)?\b", re.IGNORECASE)
_INTERNSHIP_WORD = re.compile(r"\binternships?\b", re.IGNORECASE)
_INTERNSHIP_LINK = re.compile(r"internshala\.com/internships?/", re.IGNORECASE)
_UNPAID = re.compile(r"\b(?:unpaid|stipend)\b", re.IGNORECASE)
_PER_MONTH = re.compile(r"/\s*(?:month|mo)\b|\bper\s+month\b|\bp\.?\s?m\.?(?=\s|$)", re.IGNORECASE)
_AMOUNT = re.compile(r"(?<![\d,])\d{1,3}(?:,\d{2,3})*(?![\d,])")
STIPEND_MAX = 40_000  # a monthly figure at or below this is an internship stipend, not a salary

_ENGINEERING = re.compile(
    r"\b(engineer(?:ing)?|developer|development|dev|sde|swe|sdet|programmer|programming|software|backend|"
    r"back-end|frontend|front-end|full[\s-]?stack|devops|sre|platform|infrastructure|cloud|data|ml|ai|"
    r"machine\s+learning|mobile|android|ios|web|embedded|firmware|qa|test|automation|technical|tech|it|coding|"
    r"intern(?:ship)?|trainee|graduate|security|systems?|application|solutions?|product)\b",
    re.IGNORECASE,
)

_REMOTE = re.compile(r"\b(remote|work\s+from\s+home|wfh|anywhere)\b", re.IGNORECASE)
_COUNTRY_ONLY = re.compile(r"^\s*(?:pan[\s-]*)?india\s*$|^\s*multiple\s+locations?\s*$", re.IGNORECASE)
_NCR = ("delhi", "new delhi", "ncr", "delhi ncr", "gurugram", "gurgaon", "noida", "greater noida", "ghaziabad",
        "faridabad")
_ALIASES = {
    "bengaluru": ("bengaluru", "bangalore", "blr"), "bangalore": ("bengaluru", "bangalore", "blr"),
    "gurugram": ("gurugram", "gurgaon"), "gurgaon": ("gurugram", "gurgaon"),
    "mumbai": ("mumbai", "bombay", "navi mumbai", "thane"), "delhi ncr": _NCR, "ncr": _NCR,
    "delhi": ("delhi", "new delhi"), "new delhi": ("delhi", "new delhi"), "noida": ("noida", "greater noida"),
    "chennai": ("chennai", "madras"), "hyderabad": ("hyderabad", "secunderabad"),
    "pune": ("pune", "pimpri", "chinchwad"), "kolkata": ("kolkata", "calcutta"),
    "remote": ("remote", "work from home", "wfh", "anywhere"),
}
# PIN code prefixes -> the city they belong to (alerts sometimes give only "Noida, 201301").
_PIN_CITY = (("560", "bengaluru"), ("110", "delhi"), ("2013", "noida"), ("2010", "ghaziabad"),
             ("1220", "gurugram"), ("1210", "faridabad"), ("400", "mumbai"), ("411", "pune"),
             ("500", "hyderabad"), ("600", "chennai"), ("700", "kolkata"))
_PIN = re.compile(r"(?<!\d)(\d{6})(?!\d)")
# A location that is only a state can't be judged: pass it when the state has a city you allow.
_STATE_CITIES = {
    "karnataka": ("bengaluru",), "haryana": ("gurugram", "faridabad"), "uttar pradesh": ("noida", "ghaziabad"),
    "telangana": ("hyderabad",), "maharashtra": ("mumbai", "pune"), "tamil nadu": ("chennai",),
    "west bengal": ("kolkata",), "delhi": ("delhi",),
}


@dataclass(frozen=True)
class FilterResult:
    reasons: tuple[str, ...] = ()
    experience: ExperienceResult | None = None

    @property
    def excluded(self) -> bool:
        return bool(self.reasons)

    @property
    def needs_check(self) -> bool:
        """Passes the filter, but the experience level is unknown: verify before Apply today."""
        return not self.reasons and self.experience is not None and self.experience.status == UNKNOWN

    @property
    def label(self) -> str:
        return "Filtered: " + "; ".join(self.reasons) if self.reasons else ""


def is_stipend(details: str | None) -> bool:
    """Listing details that describe an internship stipend rather than a salary."""
    text = clean(details or "")[:300]
    if not text:
        return False
    if _UNPAID.search(text):
        return True
    if not _PER_MONTH.search(text):
        return False
    amounts = [int(a.replace(",", "")) for a in _AMOUNT.findall(text)]
    return bool(amounts) and max(amounts) <= STIPEND_MAX


def internship_hint(details: str | None, link: str | None) -> str | None:
    """Why a listing is an internship though its title doesn't say so, or None."""
    if link and _INTERNSHIP_LINK.search(unquote(unquote(link[:2000]))):
        return "Internshala internship"
    text = clean(details or "")[:300]
    if _INTERNSHIP_WORD.search(text):
        return "listing says internship"
    if is_stipend(text):
        return f"stipend: {text[:40]}"
    return None


def _places(allowed: list[str]) -> set[str]:
    out: set[str] = set()
    for entry in allowed:
        for want in (w.strip().lower() for w in entry.split("/")):
            if want:
                out.update(_ALIASES.get(want, (want,)))
    return out


def location_ok(location: str, allowed: list[str], remote_ok: bool) -> bool:
    loc = clean(location).lower()
    if not loc.strip() or _COUNTRY_ONLY.match(loc):
        return True  # unknown / country-wide: can't tell, keep it
    if _REMOTE.search(loc):
        return remote_ok
    places = _places(allowed) - ({"remote", "work from home", "wfh", "anywhere"} if not remote_ok else set())
    if any(re.search(rf"\b{re.escape(p)}\b", loc) for p in places):
        return True
    for pin in _PIN.findall(loc):
        city = next((c for prefix, c in _PIN_CITY if pin.startswith(prefix)), None)
        if city and city in places:
            return True
    bare = " ".join(re.sub(r"\b(?:india|in)\b|[^a-z ]", " ", loc).split())
    if bare in _STATE_CITIES:
        return any(c in places for c in _STATE_CITIES[bare])
    return False


def _role_exclusion(policy: MatchingPolicy, title: str, details: str | None, link: str | None) -> str | None:
    types = policy.hard_exclusions.role_types
    if "internship" in types:
        if m := _INTERN_TITLE.search(title):
            return f"excluded role: internship (title has '{m.group(0)}')"
        if hint := internship_hint(details, link):
            return f"excluded role: internship ({hint})"
    if term := policy.excluded_roles.find(title):
        return f"excluded role: {term}"
    if "non-engineering" in types and not _ENGINEERING.search(title) and not policy.any_stack.find(title):
        return "excluded role: non-engineering (no engineering word in the title)"
    return None


def prefilter(policy: MatchingPolicy, *, title: str, location: str | None = None, details: str | None = None,
              jd_text: str | None = None, link: str | None = None, sources: tuple[str, ...] = (),
              check: str | None = None) -> FilterResult:
    title = clean(title or "")
    reasons: list[str] = []
    if reason := _role_exclusion(policy, title, details, link):
        reasons.append(reason)
    if term := policy.excluded_conditions.find(" · ".join(filter(None, (title, details, jd_text)))):
        reasons.append(f"excluded condition: {term}")
    experience = classify(policy, title=title, details=details, jd_text=jd_text, sources=sources, check=check)
    if experience.status == TOO_SENIOR:
        reasons.append(f"too senior: {experience.evidence}")
    rule = policy.location
    if location and rule.allowed and not location_ok(location, rule.allowed, rule.remote_ok):
        reasons.append(f"location ({clean(location)[:40]})")
    return FilterResult(tuple(reasons), experience)


def prefilter_job(job, policy: MatchingPolicy) -> FilterResult:
    """``prefilter`` for a stored job (title, location, listing details, JD, sources, your quick check)."""
    return prefilter(policy, title=job.title, location=job.location, details=job.details, jd_text=job.jd_text,
                     link=job.link, sources=(job.source_name or "", *job.also_on),
                     check=getattr(job, "experience_check", None))


def penalty(job, policy: MatchingPolicy) -> tuple[str, ...]:
    """Soft-penalty stacks in the title or details (they lower the rank, never filter)."""
    return tuple(policy.penalised_stacks.find_all(" · ".join(filter(None, (job.title, job.details)))))
