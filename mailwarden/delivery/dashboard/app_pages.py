"""The Applications page: summary, what needs action, and a filterable list with timelines. No I/O.

The dashboard looks up what this needs (history, the emails behind each event, the jobs
behind "Applied" clicks) and passes it in.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlencode

from mailwarden.core.applications import company_key
from mailwarden.core.models import Application, EmailMeta, Stage, StoredJob
from mailwarden.core.sources import tidy_requisition_title
from mailwarden.storage.base import ApplicationEvent

ACTIVE = (Stage.ASSESSMENT, Stage.INTERVIEW, Stage.OFFER)
FILTER_STAGES = (Stage.APPLIED, Stage.ASSESSMENT, Stage.INTERVIEW, Stage.OFFER, Stage.REJECTION, Stage.OTHER)
NO_REPLY_AFTER = dt.timedelta(days=21)
SORTS = (("updated", "Recently updated"), ("deadline", "Deadline"), ("company", "Company"))
# Job boards and assessment platforms: when one of these is the "company", the employer wasn't named.
_PLATFORMS = re.compile(
    r"^(?:indeed|linkedin|naukri|hirist(?:\s*tech)?|codility|hackerearth|hackerrank|mettl|glassdoor|internshala|"
    r"foundit|unstop|wellfound|cutshort|instahyre|iimjobs|shine|apna|greenhouse|lever|workday|smartrecruiters|"
    r"testgorilla|imocha|codesignal|hirevue)\b", re.IGNORECASE)


@dataclass
class EventView:
    stage: Stage
    when: dt.datetime
    link: str | None  # "Open in Gmail", or the job posting for an "Applied" click
    label: str  # "email" | "you marked it applied"
    deadline: dt.date | None = None


@dataclass
class AppView:
    app: Application
    role: str | None
    events: list[EventView] = field(default_factory=list)
    deadline: dt.date | None = None  # the next one still ahead
    applied_at: dt.datetime | None = None
    platform: bool = False  # the "company" is a job board / assessment platform
    no_reply_days: int | None = None  # applied, and nothing since for 3+ weeks

    @property
    def stage(self) -> Stage:
        return self.app.current_stage


def build(apps: list[Application], history: dict, *, email: Callable[[str, str], EmailMeta | None],
          job: Callable[[int], StoredJob | None], gmail: Callable[[str, str], str | None],
          safe_link: Callable[[str | None], str | None], now: dt.datetime) -> list[AppView]:
    today = now.astimezone().date()
    views = []
    for a in apps:
        events: list[ApplicationEvent] = history.get((a.company, a.role), [])
        out = []
        for e in events:
            if e.message_id.startswith("job-") and e.message_id[4:].isdigit():
                j = job(int(e.message_id[4:]))
                out.append(EventView(e.stage, e.occurred_at, safe_link(j.link) if j else None, "you marked it applied"))
                continue
            meta = email(e.account, e.message_id) if e.account else None
            deadline = meta.classification.deadline if meta and meta.classification else None
            out.append(EventView(e.stage, e.occurred_at, gmail(e.account, e.message_id) if e.account else None,
                                 "email", deadline))
        upcoming = sorted(ev.deadline for ev in out if ev.deadline and ev.deadline >= today)
        applied = next((ev.when for ev in out if ev.stage is Stage.APPLIED), None)
        v = AppView(a, tidy_requisition_title(a.role)[0] if a.role else None, out,
                    upcoming[0] if upcoming and a.current_stage in ACTIVE else None, applied,
                    bool(_PLATFORMS.match(a.company.strip())))
        if a.current_stage is Stage.APPLIED and now - a.last_update >= NO_REPLY_AFTER:
            v.no_reply_days = (now - a.last_update).days
        views.append(v)
    return views


@dataclass
class Summary:
    total: int
    by_stage: dict[Stage, int]
    active: int
    replied: int  # heard back at all (any stage after applied)
    no_reply: int

    @property
    def reply_rate(self) -> int | None:
        return round(100 * self.replied / self.total) if self.total else None


def summarise(views: list[AppView]) -> Summary:
    by_stage = {s: sum(1 for v in views if v.stage is s) for s in FILTER_STAGES}
    replied = sum(1 for v in views if v.stage not in (Stage.APPLIED, Stage.OTHER))
    return Summary(len(views), by_stage, sum(by_stage[s] for s in ACTIVE), replied,
                   sum(1 for v in views if v.no_reply_days is not None))


def needs_action(views: list[AppView]) -> list[AppView]:
    """Assessments, interviews and offers: soonest deadline first, then the most recent."""
    active = [v for v in views if v.stage in ACTIVE]
    return sorted(active, key=lambda v: (v.deadline is None, v.deadline or dt.date.max,
                                         -v.app.last_update.timestamp()))


@dataclass
class Filters:
    stage: str = ""
    q: str = ""
    sort: str = "updated"

    @classmethod
    def parse(cls, params) -> Filters:
        stage = str(params.get("stage", "") or "")
        sort = str(params.get("sort", "") or "updated")
        return cls(stage if stage in {s.value for s in FILTER_STAGES} | {"active", "no_reply"} else "",
                   str(params.get("q", "") or "")[:80].strip(), sort if sort in dict(SORTS) else "updated")

    def url(self, **change) -> str:
        values = {"stage": self.stage, "q": self.q, "sort": self.sort, **change}
        query = {k: v for k, v in values.items() if v and not (k == "sort" and v == "updated")}
        return "/applications" + (f"?{urlencode(query)}" if query else "")


def select(views: list[AppView], f: Filters) -> list[AppView]:
    out = views
    if f.stage == "active":
        out = [v for v in out if v.stage in ACTIVE]
    elif f.stage == "no_reply":
        out = [v for v in out if v.no_reply_days is not None]
    elif f.stage:
        out = [v for v in out if v.stage.value == f.stage]
    if f.q:
        q = company_key(f.q) or f.q.lower()
        out = [v for v in out if q in company_key(v.app.company) or q in (v.role or "").lower()]
    if f.sort == "company":
        return sorted(out, key=lambda v: v.app.company.lower())
    if f.sort == "deadline":
        return sorted(out, key=lambda v: (v.deadline is None, v.deadline or dt.date.max))
    return sorted(out, key=lambda v: -v.app.last_update.timestamp())
