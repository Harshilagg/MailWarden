"""Job descriptions (JDs): where they can come from, and turning pages/API replies into text.

- Automatic: jobs hosted on Greenhouse, Lever or Ashby are fetched through those
  companies' public job-board JSON APIs (fixed hosts, no cookies, no tracking links).
- Button (opt-in): the job's own page, only on an allowlist of hiring systems
  (Greenhouse, Lever, Ashby, Workday, SmartRecruiters, SuccessFactors/jobs2web);
  Workday and SmartRecruiters also via their public JSON endpoints.
- Everything else (LinkedIn, Naukri, Indeed, Internshala, click-trackers, other sites)
  is never fetched: the card says why and offers a "Paste JD" box.

JD text is untrusted: it is cleaned, length-capped and later wrapped as data in the
scoring prompt. No network code lives here; callers pass a fetch function.
"""

from __future__ import annotations

import html as html_lib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from mailwarden.core.text import clean
from mailwarden.core.html_text import html_to_text

MAX_JD_CHARS = 20_000
MIN_JD_CHARS = 200

# Fixed API hosts used for automatic fetching: security.net.JD_API_HOSTS (main allowlisted session).
# Sites the "Fetch job description" button may contact (host == suffix or ends with "." + suffix).
BUTTON_FETCH_SUFFIXES = (
    "greenhouse.io", "lever.co", "ashbyhq.com", "myworkdayjobs.com", "myworkdaysite.com",
    "smartrecruiters.com", "successfactors.com", "successfactors.eu", "sapsf.com", "sapsf.eu", "jobs2web.com",
)
_BOARDS = {
    "linkedin.com": "LinkedIn", "lnkd.in": "LinkedIn", "naukri.com": "Naukri", "indeed.com": "Indeed",
    "internshala.com": "Internshala", "foundit.in": "foundit", "monsterindia.com": "foundit",
    "cutshort.io": "Cutshort", "wellfound.com": "Wellfound", "glassdoor.com": "Glassdoor",
    "glassdoor.co.in": "Glassdoor", "instahyre.com": "Instahyre", "unstop.com": "Unstop", "shine.com": "Shine",
}
_TRACKER_HOST = re.compile(
    r"^(?:click|clicks|links?|email|e|em|t|track|tracking|trk|go|url\d*|r|redirect|cts|ablink|postoffice|mailer|mail)\.|"
    r"(?:^|\.)(?:sendgrid\.net|list-manage\.com|mandrillapp\.com|mailchimp\.com|hubspotlinks\.com|"
    r"mailgun\.org|sparkpostmail\.com|exacttarget\.com|bit\.ly|t\.co|tinyurl\.com|lnkd\.in)$",
    re.IGNORECASE,
)
_NEVER_FOLLOW = re.compile(
    r"unsubscribe|opt[-_]?out|preferences?|email[-_]?settings|notification[-_]?settings|manage[-_]?(?:alerts?|"
    r"subscriptions?|emails?)|feedback|survey|report[-_]?(?:spam|abuse)",
    re.IGNORECASE,
)
_TRACKING_PARAMS = re.compile(
    r"^(?:utm_\w+|trk\w*|tracking_?id|ref(?:id)?|refid|lipi|midtoken|midsig|eid|otptoken|mc_[ce]id|gclid|fbclid|"
    r"gh_src|lever-source|lever-via|source|src|ccuid|campaign\w*|email\w*|_hs\w+|mkt_tok|sid)$",
    re.IGNORECASE,
)
_JD_WORDS = re.compile(r"responsibilit|requirement|qualification|experience|what you|you will|about the role|"
                       r"skills|we are looking", re.IGNORECASE)


@dataclass(frozen=True)
class JDResult:
    status: str  # "ok" | "unavailable" | "closed" (the hiring system says the posting is gone)
    text: str | None = None
    source: str | None = None
    reason: str | None = None

    @classmethod
    def ok(cls, text: str, source: str) -> JDResult:
        return cls("ok", normalise_jd(text), source)

    @classmethod
    def unavailable(cls, reason: str) -> JDResult:
        return cls("unavailable", None, None, reason)

    @classmethod
    def closed(cls, reason: str) -> JDResult:
        return cls("closed", None, None, reason)


def normalise_jd(text: str) -> str:
    text = clean(text)
    text = re.sub(r"https?://\S+", "", text)  # links add nothing to scoring
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()[:MAX_JD_CHARS]


def _host_matches(host: str, suffixes) -> bool:
    host = host.lower()
    return any(host == s or host.endswith("." + s) for s in suffixes)


def strip_tracking(url: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if not _TRACKING_PARAMS.match(k)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


# --- where a job's JD can come from ------------------------------------------------------

@dataclass(frozen=True)
class Plan:
    kind: str  # "greenhouse" | "lever" | "ashby" | "workday" | "smartrecruiters" | "page" | "none"
    url: str | None = None  # API or page URL to fetch
    key: str | None = None  # Ashby: job id to pick from the board
    why_not: str | None = None  # for kind == "none": what to tell the user

    @property
    def automatic(self) -> bool:
        return self.kind in ("greenhouse", "lever", "ashby")


def plan(link: str | None) -> Plan:
    if not link:
        return Plan("none", why_not="No link to the job: paste the job description")
    parts = urlsplit(link)
    host = (parts.hostname or "").lower()
    path = [p for p in parts.path.split("/") if p]
    query = dict(parse_qsl(parts.query))
    if _NEVER_FOLLOW.search(parts.path) or _NEVER_FOLLOW.search(parts.query):
        return Plan("none", why_not="That link is an email-settings/unsubscribe link and is never followed")
    if parts.scheme not in ("https", "http"):
        return Plan("none", why_not="Not a web link: paste the job description")

    # Greenhouse: boards.greenhouse.io/<board>/jobs/<id>, job-boards(.eu).greenhouse.io/..., embed?for=&token=
    if _host_matches(host, ("greenhouse.io",)):
        if "for" in query and "token" in query and query["token"].isdigit():
            return Plan("greenhouse", f"https://boards-api.greenhouse.io/v1/boards/{query['for']}/jobs/{query['token']}")
        if len(path) >= 3 and path[-2] == "jobs" and path[-1].isdigit():
            return Plan("greenhouse", f"https://boards-api.greenhouse.io/v1/boards/{path[-3]}/jobs/{path[-1]}")
    # Lever: jobs(.eu).lever.co/<company>/<uuid>[/apply]
    if _host_matches(host, ("lever.co",)) and len(path) >= 2 and re.fullmatch(r"[0-9a-f-]{36}", path[1]):
        api = "api.eu.lever.co" if ".eu." in f".{host}" else "api.lever.co"
        return Plan("lever", f"https://{api}/v0/postings/{path[0]}/{path[1]}")
    # Ashby: jobs.ashbyhq.com/<org>/<uuid>
    if _host_matches(host, ("ashbyhq.com",)) and len(path) >= 2 and re.fullmatch(r"[0-9a-f-]{36}", path[1]):
        return Plan("ashby", f"https://api.ashbyhq.com/posting-api/job-board/{path[0]}", key=path[1])
    # Workday: <tenant>.wd<N>.myworkdayjobs.com/[<lang>/]<site>/job/<...>
    if _host_matches(host, ("myworkdayjobs.com", "myworkdaysite.com")) and "job" in path:
        tenant = host.split(".")[0]
        i = path.index("job")
        site = path[i - 1] if i >= 1 else None
        if site and len(path) > i + 1:
            rest = "/".join(path[i:])
            return Plan("workday", f"https://{host}/wday/cxs/{tenant}/{site}/{rest}")
    # SmartRecruiters: jobs.smartrecruiters.com/<company>/<id>-<slug>
    if _host_matches(host, ("smartrecruiters.com",)) and len(path) >= 2:
        m = re.match(r"(\d{6,})", path[1])
        if m:
            return Plan("smartrecruiters", f"https://api.smartrecruiters.com/v1/companies/{path[0]}/postings/{m.group(1)}")
    if _host_matches(host, BUTTON_FETCH_SUFFIXES):
        return Plan("page", strip_tracking(link.replace("http://", "https://", 1)))

    board = next((name for dom, name in _BOARDS.items() if _host_matches(host, (dom,))), None)
    if board:
        return Plan("none", why_not=f"{board} pages can't be fetched: open the job in your browser and paste the JD")
    if _TRACKER_HOST.search(host):
        return Plan("none", why_not="This is a click-tracking link: open in browser, then paste the JD")
    return Plan("none", why_not=f"{host} isn't on the fetch list: open in browser, then paste the JD")


# --- turning API replies / pages into JD text --------------------------------------------

def _html_text(fragment: str) -> str:
    try:
        return html_to_text(html_lib.unescape(fragment))
    except Exception:
        return ""


def from_greenhouse(data: dict) -> str:
    return _html_text(data.get("content") or "")


def from_lever(data: dict) -> str:
    parts = [data.get("descriptionPlain") or ""]
    for lst in data.get("lists") or []:
        parts.append(str(lst.get("text", "")))
        parts.append(_html_text(str(lst.get("content", ""))))
    parts.append(data.get("additionalPlain") or "")
    return "\n".join(p for p in parts if p)


def on_ashby_board(board: dict, job_id: str) -> bool:
    return any(str(job.get("id")) == job_id for job in board.get("jobs") or [])


def from_ashby(board: dict, job_id: str) -> str:
    for job in board.get("jobs") or []:
        if str(job.get("id")) == job_id:
            return job.get("descriptionPlain") or _html_text(job.get("descriptionHtml") or "")
    return ""


def from_workday(data: dict) -> str:
    return _html_text(((data.get("jobPostingInfo") or {}).get("jobDescription")) or "")


def from_smartrecruiters(data: dict) -> str:
    sections = ((data.get("jobAd") or {}).get("sections")) or {}
    return "\n".join(_html_text(str((sections.get(k) or {}).get("text", "")))
                     for k in ("companyDescription", "jobDescription", "qualifications", "additionalInformation"))


_LD_JSON = re.compile(r"<script[^>]+type=[\"']application/ld\+json[\"'][^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)


def from_page(page_html: str) -> str:
    """Prefer the JobPosting structured data most career sites embed; else the page text."""
    for m in _LD_JSON.finditer(page_html[:3_000_000]):
        blob = m.group(1).strip()[:500_000]
        try:
            data = json.loads(blob)
        except ValueError:
            continue
        stack = [data]
        while stack:
            item = stack.pop()
            if isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, dict):
                kind = item.get("@type")
                if kind == "JobPosting" or (isinstance(kind, list) and "JobPosting" in kind):
                    text = _html_text(str(item.get("description") or ""))
                    if len(text) >= MIN_JD_CHARS:
                        return text
                stack.extend(v for v in item.values() if isinstance(v, (dict, list)))
    text = _html_text(page_html)
    return text if len(text) >= MIN_JD_CHARS and _JD_WORDS.search(text) else ""


def result_from_text(text: str, source: str, *, empty_reason: str) -> JDResult:
    text = normalise_jd(text)
    if len(text) < MIN_JD_CHARS:
        return JDResult.unavailable(empty_reason)
    return JDResult.ok(text, source)


def from_paste(text: str) -> JDResult:
    return result_from_text(text, "paste", empty_reason="Pasted text is too short to be a job description")


def http_reason(status: int, site: str) -> str:
    if status in (401, 403, 429, 999):
        return f"{site} blocked the request (HTTP {status}): open in browser, then paste the JD"
    return f"{site} returned HTTP {status}: open in browser, then paste the JD"


def acquire(p: Plan, *, get_json: Callable[[str], tuple[int, object]],
            get_page: Callable[[str], tuple[int, str]]) -> JDResult:
    """Fetch per plan. ``get_json``/``get_page`` return (status, parsed JSON | page HTML)."""
    if p.kind == "none" or not p.url:
        return JDResult.unavailable(p.why_not or "Not fetchable: paste the job description")
    site = {"greenhouse": "Greenhouse", "lever": "Lever", "ashby": "Ashby", "workday": "Workday",
            "smartrecruiters": "SmartRecruiters"}.get(p.kind, urlsplit(p.url).hostname or "site")
    if p.kind == "page":
        status, page = get_page(p.url)
        if status in (404, 410):
            return JDResult.closed(f"{site}: the posting was removed (HTTP {status})")
        if status != 200:
            return JDResult.unavailable(http_reason(status, site))
        return result_from_text(from_page(page), f"fetch:{site}",
                                empty_reason=f"{site}: no job description found on the page; paste it instead")
    status, data = get_json(p.url)
    if status in (404, 410):
        return JDResult.closed(f"{site}: the posting was removed (HTTP {status})")
    if p.kind == "ashby" and status == 200 and isinstance(data, dict) and not on_ashby_board(data, p.key or ""):
        return JDResult.closed("Ashby: the job is no longer on the company's job board")
    if status != 200 or not isinstance(data, dict):
        return JDResult.unavailable(http_reason(status, site) if status != 200 else f"{site}: unexpected reply")
    text = {
        "greenhouse": lambda: from_greenhouse(data),
        "lever": lambda: from_lever(data),
        "ashby": lambda: from_ashby(data, p.key or ""),
        "workday": lambda: from_workday(data),
        "smartrecruiters": lambda: from_smartrecruiters(data),
    }[p.kind]()
    return result_from_text(text, f"api:{p.kind}", empty_reason=f"{site}: the posting has no description")
