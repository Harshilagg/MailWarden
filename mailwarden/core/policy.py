"""The matching policy (matching.yaml): the single source of job-matching rules.

profile.yaml says who you are (skills, projects, education, highlights). The policy
says which jobs you want and how to rank them:

- experience: what counts as fresher / stretch / too senior, and what to do when unknown;
- hard_exclusions: role types and conditions that always filter a job;
- soft_penalties: stacks that lower the rank but never filter;
- stack_families: keyword families used for ranking, diversity and the best project;
- best_project_rule: skills to ignore when comparing projects;
- scoring_rubric: given verbatim to the scoring model.

Parsing is strict (unknown keys are errors, so a typo can't silently change matching).
``check`` returns warnings for things that parse but look wrong.
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import cached_property
from importlib import resources
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

GENERAL_FAMILY = "general_swe"  # generic titles: never diversity-capped
MAX_RUBRIC_LINE = 300
MAX_RUBRIC_LINES = 20


class PolicyError(ValueError):
    pass


def _terms(values: list[str]) -> list[str]:
    """Lower-cased, trimmed, de-duplicated keywords ("sr " -> "sr")."""
    out: list[str] = []
    for v in values:
        term = " ".join(str(v).lower().split())
        if term and term not in out:
            out.append(term)
    return out


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TermMatcher:
    """Whole-word matching of policy terms ("sde i" doesn't match "SDE II", "lead" doesn't match
    "leadership"). A space in a term also matches a hyphen or nothing ("sde 3" ~ "SDE-3" ~ "SDE3"); a term that
    starts or ends with punctuation (".net", "c++", "c#", "sr.") isn't boundary-checked on that side,
    so "ASP.NET" matches ".net". Linear time: one alternation of escaped literals."""

    def __init__(self, terms: list[str]) -> None:
        self.terms = [t for t in terms if t]
        self._by_key = {re.sub(r"[\s\-]+", "", t): t for t in self.terms}
        parts = []
        for term in sorted(self.terms, key=len, reverse=True):
            body = r"[\s\-]*".join(re.escape(w) for w in term.split(" "))
            left = r"(?<![a-z0-9])" if term[0].isalnum() else ""
            right = r"(?![a-z0-9+#])" if term[-1].isalnum() else ""
            parts.append(f"{left}{body}{right}")
        self._rx = re.compile("|".join(parts), re.IGNORECASE) if parts else None

    def find(self, text: str) -> str | None:
        """The first term found in ``text`` (as written in the policy), or None."""
        if self._rx is None or not text:
            return None
        m = self._rx.search(text[:20_000])
        return self._term(m.group(0)) if m else None

    def find_all(self, text: str) -> list[str]:
        if self._rx is None or not text:
            return []
        out: list[str] = []
        for m in self._rx.finditer(text[:20_000]):
            if (term := self._term(m.group(0))) not in out:
                out.append(term)
        return out

    def _term(self, matched: str) -> str:
        key = re.sub(r"[\s\-]+", "", matched.lower())
        return self._by_key.get(key, matched.lower())


class Experience(_Strict):
    pass_max_min_years: int = Field(default=1, ge=0, le=10)
    stretch_min_years: int = Field(default=2, ge=0, le=10)
    max_stretch_in_apply_today: int = Field(default=3, ge=0, le=50)
    fresher_signals: list[str] = []
    senior_signals: list[str] = []
    # Sources that only list fresher jobs (e.g. campus hiring): their jobs count as verified fresher.
    fresher_sources: list[str] = []
    # needs_check: never in Apply today until verified; allow: treat unknown like fresher.
    unknown_policy: Literal["needs_check", "allow"] = "needs_check"

    _norm = field_validator("fresher_signals", "senior_signals", "fresher_sources")(lambda cls, v: _terms(v))

    @model_validator(mode="after")
    def _ordered(self) -> Experience:
        if self.stretch_min_years < self.pass_max_min_years:
            raise ValueError("experience.stretch_min_years must be >= pass_max_min_years")
        return self


class HardExclusions(_Strict):
    role_types: list[str] = []
    conditions: list[str] = []

    _norm = field_validator("role_types", "conditions")(lambda cls, v: _terms(v))


class SoftPenalties(_Strict):
    stacks: list[str] = []
    rank_penalty: float = Field(default=1.0, ge=0, le=10)

    _norm = field_validator("stacks")(lambda cls, v: _terms(v))


class LocationRule(_Strict):
    # Cities you'd work in ("Delhi NCR" covers its cities). Empty = no location filter.
    allowed: list[str] = []
    remote_ok: bool = True

    _norm = field_validator("allowed")(lambda cls, v: _terms(v))


class StackFamily(_Strict):
    keywords: list[str] = Field(min_length=1)
    evidence_project: str | None = None

    _norm = field_validator("keywords")(lambda cls, v: _terms(v))


class BestProjectRule(_Strict):
    generic_skills: list[str] = []

    _norm = field_validator("generic_skills")(lambda cls, v: _terms(v))


class MatchingPolicy(_Strict):
    experience: Experience = Experience()
    hard_exclusions: HardExclusions = HardExclusions()
    location: LocationRule = LocationRule()
    soft_penalties: SoftPenalties = SoftPenalties()
    stack_families: dict[str, StackFamily] = Field(min_length=1)
    best_project_rule: BestProjectRule = BestProjectRule()
    scoring_rubric: list[str] = Field(min_length=1, max_length=MAX_RUBRIC_LINES)

    @field_validator("stack_families")
    @classmethod
    def _names(cls, v: dict[str, StackFamily]) -> dict[str, StackFamily]:
        for name in v:
            if not name.replace("_", "").isalnum() or name != name.lower():
                raise ValueError(f"stack family names are lower_snake_case: {name!r}")
        return v

    @field_validator("scoring_rubric")
    @classmethod
    def _rubric(cls, v: list[str]) -> list[str]:
        lines = [" ".join(str(line).split()) for line in v]
        if any(not line or len(line) > MAX_RUBRIC_LINE for line in lines):
            raise ValueError(f"scoring_rubric lines must be non-empty and at most {MAX_RUBRIC_LINE} characters")
        return lines

    model_config = ConfigDict(extra="forbid", frozen=True, ignored_types=(cached_property,))

    @cached_property
    def fresher(self) -> TermMatcher:
        return TermMatcher(self.experience.fresher_signals)

    @cached_property
    def senior(self) -> TermMatcher:
        return TermMatcher(self.experience.senior_signals)

    @cached_property
    def excluded_roles(self) -> TermMatcher:
        return TermMatcher([t for t in self.hard_exclusions.role_types if t not in _SPECIAL_ROLE_TYPES])

    @cached_property
    def excluded_conditions(self) -> TermMatcher:
        return TermMatcher(self.hard_exclusions.conditions)

    @cached_property
    def any_stack(self) -> TermMatcher:
        return TermMatcher([kw for fam in self.stack_families.values() for kw in fam.keywords])

    @cached_property
    def penalised_stacks(self) -> TermMatcher:
        return TermMatcher(self.soft_penalties.stacks)

    def fingerprint(self) -> str:
        """Changes whenever anything in the policy changes (part of the fit-score cache key)."""
        return hashlib.sha256(json.dumps(self.model_dump(), sort_keys=True).encode()).hexdigest()[:16]

    def check(self, project_names: list[str] | None = None) -> list[str]:
        """Warnings for a policy that parses but is probably not what you meant."""
        warnings: list[str] = []
        if GENERAL_FAMILY not in self.stack_families:
            warnings.append(f"no '{GENERAL_FAMILY}' family: generic titles (Software Engineer, SDE) will have no family")
        owner: dict[str, str] = {}
        for name, fam in self.stack_families.items():
            for kw in fam.keywords:
                if kw in owner and owner[kw] != name:
                    warnings.append(f"keyword '{kw}' is in both {owner[kw]} and {name}: the first family wins ties")
                owner.setdefault(kw, name)
        if project_names is not None:
            known = {p.lower(): p for p in project_names}
            for name, fam in self.stack_families.items():
                if fam.evidence_project and fam.evidence_project.lower() not in known:
                    warnings.append(f"{name}.evidence_project '{fam.evidence_project}' is not a project in "
                                    "profile.yaml")
        for kw in self.soft_penalties.stacks:
            if kw in owner:
                warnings.append(f"soft-penalty stack '{kw}' is also a keyword of {owner[kw]}")
        for term in self.hard_exclusions.role_types:
            if term in owner:
                warnings.append(f"hard-exclusion role type '{term}' is also a keyword of {owner[term]}: "
                                "matching jobs will always be filtered")
        both = set(self.experience.fresher_signals) & set(self.experience.senior_signals)
        if both:
            warnings.append(f"in both fresher_signals and senior_signals: {', '.join(sorted(both))}")
        return warnings


# Role types with a built-in meaning (see core.prefilter): "internship" also catches "intern"
# titles, Internshala internship links and stipends; "non-engineering" catches titles with no
# engineering word and no stack keyword.
_SPECIAL_ROLE_TYPES = ("internship", "non-engineering")


def default_policy() -> MatchingPolicy:
    """The shipped template, used until you create matching.yaml."""
    import yaml

    return parse(yaml.safe_load(resources.files("mailwarden.templates").joinpath("matching.yaml").read_text("utf-8")))


def parse(data: object) -> MatchingPolicy:
    if not isinstance(data, dict):
        raise PolicyError("matching.yaml must be a mapping of sections (experience, hard_exclusions, ...)")
    try:
        return MatchingPolicy.model_validate(data)
    except ValidationError as e:
        problems = "; ".join(f"{'.'.join(str(p) for p in err['loc']) or 'policy'}: {err['msg']}" for err in e.errors())
        raise PolicyError(f"matching.yaml is invalid: {problems}") from None
