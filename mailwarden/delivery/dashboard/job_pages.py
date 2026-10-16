"""Today / Review / Browse for the Job alerts pages: filtering, sidebar facets and tiers. No I/O.

Rows are the dicts built by the dashboard (job, verdict, rank, expired, needs_check ...).
Every Browse filter is a URL query parameter, so a filtered view can be bookmarked.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from urllib.parse import urlencode

from mailwarden.core.ranking import role_family, sort_key
from mailwarden.core.sources import SOURCE_TYPE_LABELS, location_key

STATUSES = (("candidates", "Candidates"), ("filtered", "Filtered"), ("expired", "Expired"), ("all", "All"))
EXPERIENCE = (("verified_fresher", "Fresher"), ("stretch", "Stretch"), ("unknown", "Not stated"),
              ("too_senior", "Too senior"))
SCORES = (("full", "Full score"), ("preliminary", "Preliminary"), ("none", "Not scored"))
SORTS = ("score", "newest")
PARAMS = ("status", "type", "source", "family", "exp", "score", "loc", "sort", "q", "page")
TOP_SOURCES = 5
PAGE_SIZE = 50


def row_status(row: dict) -> str:
    if row["expired"]:
        return "expired"
    if row["verdict"] is not None and row["verdict"].excluded:
        return "filtered"
    return "candidates"


def experience_status(row: dict) -> str | None:
    exp = row.get("experience")
    return exp.status if exp is not None else None


def score_type(row: dict) -> str:
    job = row["job"]
    return "none" if job.score is None else (job.score_level or "preliminary")


def family(row: dict) -> str:
    return role_family(row["job"].title) or "General"


def city(row: dict) -> str:
    return location_key(row["job"].location) or "unknown"


def sources(row: dict) -> set[str]:
    job = row["job"]
    return {job.source_name or "Unknown", *job.also_on}


@dataclass
class Filters:
    status: str = "candidates"
    type: str = ""  # noqa: A003
    source: str = ""
    family: str = ""
    exp: str = ""
    score: str = ""
    loc: str = ""
    sort: str = "score"
    q: str = ""  # narrows the source list in the sidebar
    page: int = 1

    @classmethod
    def parse(cls, params) -> Filters:
        get = lambda k: str(params.get(k, "") or "")[:80]  # noqa: E731
        try:
            page = max(1, min(int(get("page") or 1), 10_000))
        except ValueError:
            page = 1
        f = cls(status=get("status") or "candidates", type=get("type"), source=get("source"), family=get("family"),
                exp=get("exp"), score=get("score"), loc=get("loc"), sort=get("sort") or "score", q=get("q"),
                page=page)
        if f.status not in dict(STATUSES):
            f.status = "candidates"
        if f.sort not in SORTS:
            f.sort = "score"
        if f.type and f.type not in SOURCE_TYPE_LABELS:
            f.type = ""
        if f.exp and f.exp not in dict(EXPERIENCE):
            f.exp = ""
        if f.score and f.score not in dict(SCORES):
            f.score = ""
        return f

    def url(self, **change) -> str:
        """This view's URL with some filters changed ('' removes one). Changing a filter goes back to page 1."""
        values = {k: getattr(self, k) for k in PARAMS}
        values.update(change)
        if "page" not in change:
            values["page"] = 1
        query = {k: v for k, v in values.items() if v and not (k == "status" and v == "candidates")
                 and not (k == "sort" and v == "score") and not (k == "page" and v == 1)}
        return "/jobs/browse" + (f"?{urlencode(query)}" if query else "")

    @property
    def active(self) -> bool:
        return any((self.type, self.source, self.family, self.exp, self.score, self.loc))


def page_of(rows: list, f: Filters) -> tuple[list, int, int]:
    """(this page's rows, first index shown (1-based), number of pages)."""
    pages = max(1, -(-len(rows) // PAGE_SIZE))
    f.page = min(f.page, pages)
    start = (f.page - 1) * PAGE_SIZE
    return rows[start:start + PAGE_SIZE], (start + 1 if rows else 0), pages


def _matches(row: dict, f: Filters, skip: str = "") -> bool:
    checks = {
        "status": lambda: f.status == "all" or row_status(row) == f.status,
        "type": lambda: not f.type or (row["job"].source_type or "other") == f.type,
        "source": lambda: not f.source or f.source in sources(row),
        "family": lambda: not f.family or family(row) == f.family,
        "exp": lambda: not f.exp or experience_status(row) == f.exp,
        "score": lambda: not f.score or score_type(row) == f.score,
        "loc": lambda: not f.loc or city(row) == f.loc,
    }
    return all(check() for name, check in checks.items() if name != skip)


@dataclass
class Facet:
    name: str
    title: str
    options: list[tuple[str, str, int, bool]] = field(default_factory=list)  # value, label, count, selected
    more: list[tuple[str, str, int, bool]] = field(default_factory=list)  # sources beyond the top 5


def browse(rows: list[dict], f: Filters) -> tuple[list[dict], dict[str, int], list[Facet]]:
    """(rows to show, counts per status, sidebar facets). Each facet counts rows matching every
    *other* filter, so the numbers say what you'd get by clicking."""
    status_counts = {key: sum(1 for r in rows if _matches(r, f, skip="status") and
                              (key == "all" or row_status(r) == key)) for key, _ in STATUSES}
    shown = [r for r in rows if _matches(r, f)]
    if f.sort == "newest":
        shown.sort(key=lambda r: -r["job"].received_at.timestamp())
    else:
        shown.sort(key=lambda r: sort_key(r["job"], r["rank"]))

    def counted(name: str, key) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in rows:
            if _matches(r, f, skip=name):
                for value in (key(r) if name == "source" else [key(r)]):
                    out[value] = out.get(value, 0) + 1
        return out

    facets = []
    types = counted("type", lambda r: r["job"].source_type or "other")
    facets.append(Facet("type", "Source type", [(k, SOURCE_TYPE_LABELS.get(k, k), n, f.type == k)
                                                 for k, n in sorted(types.items(), key=lambda kv: -kv[1])]))
    by_source = sorted(counted("source", sources).items(), key=lambda kv: (-kv[1], kv[0].lower()))
    opts = [(k, k, n, f.source == k) for k, n in by_source]
    if f.q:
        opts = [o for o in opts if f.q.lower() in o[0].lower()]
    facets.append(Facet("source", "Source", opts[:TOP_SOURCES], opts[TOP_SOURCES:]))
    fams = counted("family", family)
    facets.append(Facet("family", "Stack family", [(k, k, n, f.family == k)
                                                    for k, n in sorted(fams.items(), key=lambda kv: -kv[1])]))
    exps = counted("exp", lambda r: experience_status(r) or "")
    facets.append(Facet("exp", "Experience", [(k, label, exps[k], f.exp == k) for k, label in EXPERIENCE if k in exps]))
    scores = counted("score", score_type)
    facets.append(Facet("score", "Score", [(k, label, scores[k], f.score == k) for k, label in SCORES if k in scores]))
    locs = counted("loc", city)
    facets.append(Facet("loc", "Location", [(k, k.title() if k != "unknown" else "Not stated", n, f.loc == k)
                                             for k, n in sorted(locs.items(), key=lambda kv: -kv[1])[:12]]))
    return shown, status_counts, facets


# --- Today --------------------------------------------------------------------------------------

TIER_A_SCORE = 7.0


@dataclass
class Tiers:
    a: list = field(default_factory=list)  # full score >= 7: tailor the CV, ask for a referral
    b: list = field(default_factory=list)  # solid fit: quick apply
    more: list = field(default_factory=list)
    fill_a: list = field(default_factory=list)  # Tier A is short: preliminary jobs worth a JD fetch/paste


def tiers(picks: list, *, a_count: int, b_count: int) -> Tiers:
    """Split Apply today. Tier A needs a full score of 7+; a preliminary score can't qualify."""
    t = Tiers()
    for pick in picks:
        job = pick[0]
        if len(t.a) < a_count and job.score_level == "full" and (job.score or 0) >= TIER_A_SCORE:
            t.a.append(pick)
        elif len(t.b) < b_count:
            t.b.append(pick)
        else:
            t.more.append(pick)
    if len(t.a) < a_count:
        t.fill_a = [p for p in picks if p[0].score_level != "full" and (p[0].score or 0) >= 5.5][: a_count - len(t.a)]
    return t


def applied_today(jobs, now: dt.datetime) -> list:
    today = now.astimezone().date()
    return [j for j in jobs if j.applied_at is not None and j.applied_at.astimezone().date() == today]
