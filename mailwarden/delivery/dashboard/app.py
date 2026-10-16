"""Local dashboard (FastAPI, server-rendered, no JavaScript, no external assets).

Security controls:
- listens on 127.0.0.1 only (enforced by config and by `serve`);
- Host header must be 127.0.0.1:<port> or localhost:<port> (blocks DNS rebinding);
- every page except /login and the stylesheet needs the install-token cookie;
- POSTs need a CSRF token and, when sent, a same-origin Origin header;
- strict CSP and related headers on every response; no API docs routes.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
from pathlib import Path
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from jinja2 import Environment, PackageLoader, select_autoescape

from mailwarden.core.job_alerts import matches_filters, safe_link
from mailwarden.core.links import gmail_link, safe_local_path
from mailwarden.core.models import SLUG_PATTERN, Account, Category, GateDecision, Stage
from mailwarden.core.overview import CATEGORY_TITLES, Digest, build_digest, urgent_items
from mailwarden.delivery.dashboard import auth
from mailwarden.delivery.format import relative_time, short_date
from mailwarden.security.secrets import SecretStore
from mailwarden.storage.base import AccountRegistry, Repository

_SLUG = re.compile(SLUG_PATTERN)
_MSG_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
log = logging.getLogger(__name__)
_PUBLIC_PATHS = {"/login", "/static/style.css", "/static/logo-64.png", "/static/logo-180.png", "/favicon.ico"}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; "
        "form-action 'self'; connect-src 'none'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # same-origin (not no-referrer) so POSTs carry a real Origin header; nothing leaks to Gmail.
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}


@dataclass
class DashboardDeps:
    user_id: str
    port: int
    secrets: SecretStore
    repo_factory: Callable[[], Repository]
    accounts: AccountRegistry
    rules_summary: Callable[[], dict[str, dict[str, list[str]]]]
    backend_description: str
    outbound_hosts: list[str]
    digest_times: list[str]
    job_keywords: list[str] = field(default_factory=list)
    job_locations: list[str] = field(default_factory=list)
    #: Loads profile.yaml (None if not built yet); read per request so edits apply at once.
    profile_loader: Callable[[], dict | None] = lambda: None
    #: Loads matching.yaml (or the shipped defaults); read per request so edits apply at once.
    policy_loader: Callable[[], object | None] = lambda: None
    #: Job-description buttons (core.job_scoring.JobActions); None disables them.
    job_actions: object | None = None
    watchlist: list[str] = field(default_factory=list)
    apply_today_count: int = 8
    apply_today_min_score: float = 0.0
    tier_a_count: int = 5
    tier_b_count: int = 10
    apply_today_days: int = 0
    max_family_share: float = 0.0
    expire_after_days: int = 0
    now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC)


_BROWSE_URL = re.compile(r"^/jobs/browse(?:\?[A-Za-z0-9=&%+._\-]{0,500})?$")  # where Browse actions return


def _stage_label(stage: Stage | str | None) -> str:
    return str(stage).capitalize() if stage else ""


def create_app(deps: DashboardDeps) -> FastAPI:
    token = auth.ensure_install_token(deps.secrets, deps.user_id)
    csrf = auth.csrf_token(token)
    hosts = {f"127.0.0.1:{deps.port}", f"localhost:{deps.port}"}
    origins = {f"http://{h}" for h in hosts}

    env = Environment(
        loader=PackageLoader("mailwarden.delivery.dashboard", "templates"),
        autoescape=select_autoescape(["html"], default=True),
    )
    env.filters["short_date"] = lambda d: short_date(d, deps.now().astimezone().date()) if d else ""
    env.filters["ago"] = lambda t: relative_time(t, deps.now()) if t else ""
    env.filters["stage"] = _stage_label
    env.globals["csrf"] = csrf
    static = resources.files("mailwarden.delivery.dashboard").joinpath("static")
    stylesheet = static.joinpath("style.css").read_bytes()
    job_assets = {name: static.joinpath(name).read_bytes() for name in ("jobs.css", "jobs.js")}
    logos = {name: static.joinpath(name).read_bytes() for name in ("logo-64.png", "logo-180.png")}
    # Fonts shipped with the dashboard (static/fonts). Only these exact files are served.
    font_types = {".otf": "font/otf", ".ttf": "font/ttf", ".woff": "font/woff", ".woff2": "font/woff2"}
    fonts_dir = static.joinpath("fonts")
    fonts = {
        f.name: (f.read_bytes(), font_types[Path(f.name).suffix.lower()])
        for f in (fonts_dir.iterdir() if fonts_dir.is_dir() else [])
        if f.is_file() and Path(f.name).suffix.lower() in font_types
    }

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def sync_problems() -> list:
        from mailwarden.core import sync_health

        try:
            names = [a.name for a in deps.accounts.list(deps.user_id)]
            repo = deps.repo_factory()
            try:
                return sync_health.problems(repo, deps.user_id, deps.now(), accounts=names)
            finally:
                repo.close()
        except Exception:
            log.exception("could not read sync health")
            return []

    def render(name: str, request: Request, status_code: int = 200, **ctx) -> HTMLResponse:
        if name != "login.html":
            ctx.setdefault("sync_problems", sync_problems())
        html = env.get_template(name).render(path=request.url.path, **ctx)
        return HTMLResponse(html, status_code=status_code)

    def addresses() -> dict[str, str]:
        return {a.name: a.address for a in deps.accounts.list(deps.user_id)}

    def link(addrs: dict[str, str], account: str, message_id: str) -> str | None:
        return gmail_link(addrs.get(account, ""), message_id)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        public = request.url.path in _PUBLIC_PATHS or request.url.path.startswith("/static/fonts/")
        if request.headers.get("host", "") not in hosts:
            response: Response = PlainTextResponse("Invalid Host header", status_code=400)
        elif not public and not auth.token_matches(request.cookies.get(auth.COOKIE_NAME), token):
            response = render("login.html", request, status_code=401, expired=False)
        else:
            try:
                response = await call_next(request)
            except Exception as e:  # a sync is writing right now: say so instead of a bare 500
                if "database is locked" not in str(e):
                    raise
                log.warning("database busy for %s", request.url.path)
                response = render("busy.html", request, status_code=503, sync_problems=[])
                response.headers["Retry-After"] = "15"
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        return response

    async def check_post(request: Request, max_body: int = 4096) -> dict[str, str]:
        origin = request.headers.get("origin")
        if origin is not None and origin not in origins:
            raise PermissionError("cross-origin request")
        if request.headers.get("content-type", "").split(";")[0].strip() != "application/x-www-form-urlencoded":
            raise PermissionError("unexpected content type")
        body = await request.body()
        if len(body) > max_body:
            raise PermissionError("body too large")
        form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}
        if not auth.token_matches(form.get("csrf"), csrf):
            raise PermissionError("bad CSRF token")
        return form

    def forbidden() -> PlainTextResponse:
        return PlainTextResponse("Forbidden", status_code=403)

    @app.get("/static/style.css")
    def style() -> Response:
        return Response(stylesheet, media_type="text/css")

    @app.get("/static/jobs.css")
    def jobs_style() -> Response:
        return Response(job_assets["jobs.css"], media_type="text/css")

    @app.get("/static/jobs.js")
    def jobs_script() -> Response:  # the dashboard's only script: first-party, no inline code anywhere
        return Response(job_assets["jobs.js"], media_type="text/javascript")

    @app.get("/static/{name}.png")
    def logo(name: str) -> Response:
        data = logos.get(f"{name}.png")
        if data is None:
            return PlainTextResponse("Not found", status_code=404)
        return Response(data, media_type="image/png")

    @app.get("/static/fonts/{name}")
    def font(name: str) -> Response:
        entry = fonts.get(name)  # exact file names only: no paths, no traversal
        if entry is None:
            return PlainTextResponse("Not found", status_code=404)
        data, media_type = entry
        return Response(data, media_type=media_type)

    @app.get("/favicon.ico")
    def favicon() -> Response:
        return Response(logos["logo-64.png"], media_type="image/png")

    @app.get("/login")
    def login(request: Request, code: str = "", next: str = "/") -> Response:
        if not auth.redeem_login_code(deps.secrets, deps.user_id, code):
            return render("login.html", request, status_code=401, expired=bool(code))
        # Only same-site local paths: never an open redirect.
        target = safe_local_path(next) or "/"
        response = RedirectResponse(target, status_code=303)
        response.set_cookie(auth.COOKIE_NAME, token, max_age=auth.COOKIE_MAX_AGE, httponly=True,
                            samesite="strict", path="/")
        return response

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        try:
            await check_post(request)
        except PermissionError:
            return forbidden()
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(auth.COOKIE_NAME, path="/", httponly=True, samesite="strict")
        return response

    @app.get("/")
    def urgent(request: Request) -> Response:
        repo = deps.repo_factory()
        try:
            items = urgent_items(repo.list_email_meta(deps.user_id))
        finally:
            repo.close()
        addrs = addresses()
        today = deps.now().astimezone().date()
        cards = [(i, link(addrs, i.account, i.message_id), bool(i.deadline and i.deadline < today)) for i in items]
        return render("urgent.html", request, cards=cards)

    @app.get("/applications")
    def applications(request: Request) -> Response:
        from mailwarden.delivery.dashboard import app_pages

        f = app_pages.Filters.parse(request.query_params)
        addrs = addresses()
        repo = deps.repo_factory()
        try:
            apps = repo.list_applications(deps.user_id)
            history = {(a.company, a.role): repo.application_history(deps.user_id, a.company, a.role) for a in apps}
            views = app_pages.build(
                apps, history, email=lambda acct, mid: repo.get_email_meta(deps.user_id, acct, mid),
                job=lambda jid: repo.get_job(deps.user_id, jid), gmail=lambda acct, mid: link(addrs, acct, mid),
                safe_link=safe_link, now=deps.now())
        finally:
            repo.close()
        return render("applications.html", request, f=f, rows=app_pages.select(views, f),
                      summary=app_pages.summarise(views), action=app_pages.needs_action(views)[:6],
                      stages=app_pages.FILTER_STAGES, sorts=app_pages.SORTS, today=deps.now().astimezone().date())

    @app.get("/digest")
    def digest(request: Request) -> Response:
        repo = deps.repo_factory()
        quiet_since = None  # the latest digest(s) had no mail: show the last one that did
        try:
            stored = repo.latest_digest(deps.user_id)
            latest = Digest.from_json(stored[2]) if stored is not None else None
            if latest is not None and not (latest.total or latest.urgent):
                fuller = repo.latest_nonempty_digest(deps.user_id)
                if fuller is not None:
                    quiet_since, stored = fuller[0], fuller
            if stored is not None:
                d, live = Digest.from_json(stored[2]), False
            else:
                now = deps.now()
                d = build_digest(repo.list_email_meta(deps.user_id, since=now - dt.timedelta(days=1)),
                                 now=now, period_start=now - dt.timedelta(days=1))
                live = True
        finally:
            repo.close()
        addrs = addresses()
        sections = []
        for key, entries in d.sections.items():
            rows = [(e, link(addrs, e.account, e.message_id), dt.datetime.fromisoformat(e.received_at)) for e in entries]
            collapsed = key in (Category.NEWSLETTER, Category.JOB_ALERT)
            sections.append((CATEGORY_TITLES[Category(key)], rows, collapsed))
        return render("digest.html", request, d=d, live=live, sections=sections, quiet_since=quiet_since,
                      generated=dt.datetime.fromisoformat(d.generated_at),
                      sensitive_total=sum(d.sensitive_by_sender.values()))

    def _load():
        """(profile, policy, policy error). An invalid matching.yaml disables filtering and says why."""
        try:
            profile = deps.profile_loader()
        except Exception:
            profile = None
        try:
            return profile, deps.policy_loader(), None
        except Exception as e:  # PolicyError, unreadable file
            return profile, None, str(e)[:400]

    def _job_rows(profile: dict | None, policy):
        from mailwarden.core.expiry import expired_reason
        from mailwarden.core.jd import DEFAULT_DENY, plan
        from mailwarden.core.prefilter import prefilter_job
        from mailwarden.profile import match_role

        from mailwarden.core.ranking import AppliedIndex, rank_job, role_family

        repo = deps.repo_factory()
        try:
            stored = repo.list_jobs(deps.user_id)
            applied = AppliedIndex.from_applications(repo.list_applications(deps.user_id))
        finally:
            repo.close()
        now = deps.now()
        from mailwarden.core.expiry import reference_time

        ref = reference_time(stored, now)  # an outage must not expire every job
        targets = list((profile or {}).get("target_roles") or [])
        actions = deps.job_actions
        button = bool(actions and getattr(actions, "button_fetch_enabled", False))
        rows = []
        for j in stored:
            verdict = prefilter_job(j, policy) if policy is not None else None
            if targets:
                highlight = match_role(j.title, targets) is not None
            else:
                highlight = matches_filters(j.title, j.location, deps.job_keywords, deps.job_locations)
            p = plan(j.link, denied=getattr(actions, "deny", DEFAULT_DENY))
            expired = expired_reason(j, now=ref, after_days=deps.expire_after_days)
            can_fetch = (bool(actions) and j.jd_status not in ("ok", "closed") and not expired
                         and (p.automatic or (button and p.kind != "none")))
            rows.append({"job": j, "expired": expired, "match": highlight and not (verdict and verdict.excluded),
                         "link": safe_link(j.link), "verdict": verdict, "can_fetch": can_fetch,
                         "why_not": p.why_not if p.kind == "none" else None,
                         "experience": verdict.experience if verdict else None,
                         "family": role_family(j.title),
                         "needs_check": bool(verdict and verdict.needs_check),
                         "rank": rank_job(j, now=now, watchlist=deps.watchlist, applied=applied, policy=policy)})
        return rows, targets

    def _cards(rows_by_id: dict, picks) -> list[dict]:
        return [{**rows_by_id[job.id], "rank": info} for job, info in picks if job.id in rows_by_id]

    def _today(request: Request) -> Response:
        from mailwarden.delivery.dashboard import job_pages
        from mailwarden.recall import audit_due

        profile, policy, policy_error = _load()
        rows, _ = _job_rows(profile, policy)
        by_id = {r["job"].id: r for r in rows}
        picks, queue = _apply_picks(policy, with_checks=True)
        t = job_pages.tiers(picks, a_count=deps.tier_a_count, b_count=deps.tier_b_count)
        done = job_pages.applied_today([r["job"] for r in rows], deps.now())
        repo = deps.repo_factory()
        try:
            due = audit_due(repo, deps.user_id, deps.now()) if profile is not None else None
        finally:
            repo.close()
        max_stretch = policy.experience.max_stretch_in_apply_today if policy is not None else None
        return render("jobs_today.html", request, view="today", back="/jobs", tier_a=_cards(by_id, t.a),
                      tier_b=_cards(by_id, t.b), more=_cards(by_id, t.more), fill_a=_cards(by_id, t.fill_a),
                      applied=[by_id[j.id] for j in done if j.id in by_id], applied_n=len(done),
                      day_total=len(done) + len(picks), review_n=len(queue), has_profile=profile is not None,
                      policy_error=policy_error, audit_due=due, a_count=deps.tier_a_count,
                      n=deps.apply_today_count, days=deps.apply_today_days, watchlist=deps.watchlist,
                      family_pct=round(deps.max_family_share * 100), max_stretch=max_stretch,
                      expire_days=deps.expire_after_days, actions=deps.job_actions is not None)

    @app.get("/jobs")
    def jobs(request: Request, view: str = "", match: int = 0) -> Response:
        if view == "check":  # old links
            return RedirectResponse("/jobs/review", status_code=303)
        if match or view in ("candidates", "filtered", "expired", "all"):
            status = view if view in ("filtered", "expired", "all") else "candidates"
            return RedirectResponse("/jobs/browse" + (f"?status={status}" if status != "candidates" else ""),
                                    status_code=303)
        return _today(request)

    @app.get("/apply")
    def apply_view(request: Request) -> Response:
        return _today(request)  # notifications link here

    @app.get("/jobs/review")
    def review(request: Request, pos: int = 0) -> Response:
        """The Needs-a-quick-check queue, one job at a time."""
        profile, policy, policy_error = _load()
        rows, _ = _job_rows(profile, policy)
        by_id = {r["job"].id: r for r in rows}
        _, queue = _apply_picks(policy, with_checks=True)
        cards = _cards(by_id, queue)
        n = len(cards)
        pos = max(0, min(pos, n - 1)) if n else 0
        return render("jobs_review.html", request, view="review", back=f"/jobs/review?pos={pos}",
                      card=cards[pos] if n else None, pos=pos, n=n, review_n=n, policy_error=policy_error,
                      prev_url=f"/jobs/review?pos={pos - 1}" if pos > 0 else None,
                      next_url=f"/jobs/review?pos={pos + 1}" if pos + 1 < n else None,
                      has_profile=profile is not None, actions=deps.job_actions is not None)

    @app.get("/jobs/browse")
    def browse_view(request: Request) -> Response:
        from mailwarden.delivery.dashboard import job_pages

        f = job_pages.Filters.parse(request.query_params)
        profile, policy, policy_error = _load()
        rows, targets = _job_rows(profile, policy)
        shown, counts, facets = job_pages.browse(rows, f)
        page_rows, first, pages = job_pages.page_of(shown, f)
        _, queue = _apply_picks(policy, with_checks=True)
        return render("jobs_browse.html", request, view="browse", back=f.url(page=f.page), f=f, rows=page_rows,
                      total=len(shown), first=first, pages=pages, counts=counts,
                      facets=facets, statuses=job_pages.STATUSES, review_n=len(queue),
                      has_profile=profile is not None, policy_error=policy_error,
                      actions=deps.job_actions is not None, expire_days=deps.expire_after_days,
                      n=deps.apply_today_count, days=deps.apply_today_days, watchlist=deps.watchlist,
                      family_pct=round(deps.max_family_share * 100),
                      max_stretch=policy.experience.max_stretch_in_apply_today if policy is not None else None)

    def _apply_picks(policy, *, with_checks: bool = False):
        from mailwarden.core.ranking import AppliedIndex, apply_today, quick_check_queue

        repo = deps.repo_factory()
        try:
            jobs = repo.list_jobs(deps.user_id)
            applied = AppliedIndex.from_applications(repo.list_applications(deps.user_id))
        finally:
            repo.close()
        picks = apply_today(jobs, policy, n=deps.apply_today_count, now=deps.now(), watchlist=deps.watchlist,
                            applied=applied, expire_after_days=deps.expire_after_days,
                            new_within_days=deps.apply_today_days, max_family_share=deps.max_family_share,
                            min_score=deps.apply_today_min_score)
        if not with_checks:
            return picks
        checks = quick_check_queue(jobs, policy, now=deps.now(), watchlist=deps.watchlist, applied=applied,
                                   expire_after_days=deps.expire_after_days, new_within_days=deps.apply_today_days)
        return picks, checks

    @app.post("/jobs/{job_id}/applied")
    async def job_applied(request: Request, job_id: int) -> Response:
        """You applied: leaves Apply today at once, and goes into Applications (stage: applied)."""
        from mailwarden.core.applications import record_job_event

        try:
            form = await check_post(request)
        except PermissionError:
            return forbidden()
        undo = form.get("value") == "undo"
        repo = deps.repo_factory()
        try:
            job = repo.get_job(deps.user_id, job_id)
            if job is not None:
                now = deps.now()
                repo.mark_applied(deps.user_id, job_id, None if undo else now)
                if undo:
                    repo.remove_application_event(deps.user_id, f"job-{job_id}")
                elif job.applied_at is None:
                    record_job_event(repo, deps.user_id, company=job.company, role=job.title, stage=Stage.APPLIED,
                                     account=job.account, message_id=f"job-{job_id}", received_at=now, domain=None)
        finally:
            repo.close()
        return _back(form, job_id)

    @app.get("/insights")
    def insights(request: Request) -> Response:
        """Job-description fetching by site (last 30 days): where pages read fine, and where they don't."""
        repo = deps.repo_factory()
        try:
            rows = repo.fetch_stats(deps.user_id, deps.now() - dt.timedelta(days=30))
        finally:
            repo.close()
        sites: dict[str, dict[str, int]] = {}
        for host, outcome, count in rows:
            sites.setdefault(host, {})[outcome] = count
        table = []
        for host, outcomes in sites.items():
            total = sum(outcomes.values())
            ok = outcomes.get("ok", 0) + outcomes.get("closed", 0)
            failures = {k: v for k, v in outcomes.items() if k not in ("ok", "closed")}
            top = max(failures, key=failures.get) if failures else ""
            table.append({"host": host, "total": total, "ok": ok, "rate": round(100 * ok / total), "top": top,
                          "failures": failures})
        table.sort(key=lambda r: (-r["total"], r["host"]))
        return render("insights.html", request, sites=table)

    @app.post("/jobs/{job_id}/closed")
    async def job_closed(request: Request, job_id: int) -> Response:
        """You saw the posting is closed: it moves to Expired (undo: "Reopen")."""
        try:
            form = await check_post(request)
        except PermissionError:
            return forbidden()
        repo = deps.repo_factory()
        try:
            repo.mark_closed(deps.user_id, job_id, form.get("value") != "reopen")
        finally:
            repo.close()
        return _back(form, job_id)

    @app.post("/jobs/{job_id}/experience")
    async def experience_check(request: Request, job_id: int) -> Response:
        try:
            form = await check_post(request)
        except PermissionError:
            return forbidden()
        value = {"fresher": "fresher", "senior": "senior", "clear": None}.get(form.get("value", ""), "invalid")
        if value != "invalid":
            repo = deps.repo_factory()
            try:
                repo.set_experience_check(deps.user_id, job_id, value)
            finally:
                repo.close()
        return _back(form, job_id)

    def _back(form: dict[str, str], job_id: int | None = None) -> RedirectResponse:
        """Back to the view the action came from (Today, Review at the same position, or Browse with its
        filters). Only local Job alerts URLs are accepted."""
        view = form.get("view", "")
        if view == "review":
            try:
                pos = max(0, int(form.get("pos", "0")))
            except ValueError:
                pos = 0
            return RedirectResponse(f"/jobs/review?pos={pos}", status_code=303)
        if view == "browse":
            back = form.get("back", "")
            target = back if _BROWSE_URL.match(back) else "/jobs/browse"
            return RedirectResponse(target + (f"#job-{job_id}" if job_id else ""), status_code=303)
        return RedirectResponse("/jobs" + (f"#job-{job_id}" if job_id else ""), status_code=303)

    @app.post("/jobs/{job_id}/fetch-jd")
    async def fetch_jd(request: Request, job_id: int) -> Response:
        try:
            form = await check_post(request)
        except PermissionError:
            return forbidden()
        if deps.job_actions is not None:
            deps.job_actions.fetch(job_id)
        return _back(form, job_id)

    @app.post("/jobs/{job_id}/paste-jd")
    async def paste_jd(request: Request, job_id: int) -> Response:
        try:
            form = await check_post(request, max_body=120_000)
        except PermissionError:
            return forbidden()
        if deps.job_actions is not None:
            deps.job_actions.paste(job_id, form.get("jd", "")[:30_000])
        return _back(form, job_id)

    @app.post("/jobs/fetch-top")
    async def fetch_top(request: Request) -> Response:
        try:
            form = await check_post(request)
        except PermissionError:
            return forbidden()
        if deps.job_actions is not None:
            profile, policy, _ = _load()
            rows, _ = _job_rows(profile, policy)
            rows = [r for r in rows if r["can_fetch"] and not r["expired"]
                    and not (r["verdict"] and r["verdict"].excluded)]
            rows.sort(key=lambda r: (-(r["job"].score or 0), -r["job"].received_at.timestamp()))
            deps.job_actions.fetch_top([r["job"].id for r in rows[:10]])
        return _back(form)

    @app.post("/jobs/{job_id}/dismiss")
    async def dismiss_job(request: Request, job_id: int) -> Response:
        try:
            form = await check_post(request)
        except PermissionError:
            return forbidden()
        repo = deps.repo_factory()
        try:
            repo.dismiss_job(deps.user_id, job_id)
        finally:
            repo.close()
        return _back(form)

    @app.get("/sensitive")
    def sensitive(request: Request) -> Response:
        repo = deps.repo_factory()
        try:
            metas = repo.list_email_meta(deps.user_id)
        finally:
            repo.close()
        counts = Counter(m.sender_name or "Unknown sender" for m in metas if m.gate is GateDecision.SENSITIVE)
        return render("sensitive.html", request, counts=counts.most_common(), total=sum(counts.values()))

    @app.get("/settings")
    def settings(request: Request) -> Response:
        accounts: list[Account] = deps.accounts.list(deps.user_id)
        masked = [(a.name, a.provider, _mask(a.address)) for a in accounts]
        return render("settings.html", request, tiers=deps.rules_summary(), backend=deps.backend_description,
                      hosts=deps.outbound_hosts, accounts=masked, digest_times=deps.digest_times)

    @app.get("/i/{account}/{message_id}")
    def item(request: Request, account: str, message_id: str) -> Response:
        if not _SLUG.match(account) or not _MSG_ID.match(message_id):
            return PlainTextResponse("Not found", status_code=404)
        repo = deps.repo_factory()
        try:
            meta = repo.get_email_meta(deps.user_id, account, message_id)
        finally:
            repo.close()
        if meta is None:
            return render("item.html", request, status_code=404, meta=None, gmail=None, urgent=None)
        urgent_list = urgent_items([meta.model_copy(update={"dismissed": False})])
        return render("item.html", request, meta=meta, gmail=link(addresses(), account, message_id),
                      urgent=urgent_list[0] if urgent_list else None)

    @app.post("/i/{account}/{message_id}/dismiss")
    async def dismiss(request: Request, account: str, message_id: str) -> Response:
        if not _SLUG.match(account) or not _MSG_ID.match(message_id):
            return PlainTextResponse("Not found", status_code=404)
        try:
            await check_post(request)
        except PermissionError:
            return forbidden()
        repo = deps.repo_factory()
        try:
            repo.dismiss(deps.user_id, account, message_id)
        finally:
            repo.close()
        return RedirectResponse("/", status_code=303)

    return app


def _mask(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}" if domain else "***"
