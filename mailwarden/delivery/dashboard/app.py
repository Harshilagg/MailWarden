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
_PUBLIC_PATHS = {"/login", "/static/style.css", "/static/logo-64.png", "/static/logo-180.png", "/favicon.ico"}
STAGE_COLUMNS = (Stage.APPLIED, Stage.ASSESSMENT, Stage.INTERVIEW, Stage.OFFER, Stage.REJECTION, Stage.OTHER)

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; "
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
    #: Job-description buttons (core.job_scoring.JobActions); None disables them.
    job_actions: object | None = None
    watchlist: list[str] = field(default_factory=list)
    apply_today_count: int = 8
    now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC)


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

    def render(name: str, request: Request, status_code: int = 200, **ctx) -> HTMLResponse:
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
            response = await call_next(request)
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
        repo = deps.repo_factory()
        try:
            apps = repo.list_applications(deps.user_id)
            history = {(a.company, a.role): repo.application_history(deps.user_id, a.company, a.role) for a in apps}
        finally:
            repo.close()
        columns = [(s, [a for a in apps if a.current_stage is s]) for s in STAGE_COLUMNS]
        return render("applications.html", request, columns=[c for c in columns if c[1]], history=history,
                      total=len(apps))

    @app.get("/digest")
    def digest(request: Request) -> Response:
        repo = deps.repo_factory()
        try:
            stored = repo.latest_digest(deps.user_id)
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
        return render("digest.html", request, d=d, live=live, sections=sections,
                      generated=dt.datetime.fromisoformat(d.generated_at),
                      sensitive_total=sum(d.sensitive_by_sender.values()))

    def _job_rows(profile: dict | None):
        from mailwarden.core.jd import plan
        from mailwarden.core.prefilter import prefilter
        from mailwarden.profile import match_role

        from mailwarden.core.ranking import AppliedIndex, rank_job

        repo = deps.repo_factory()
        try:
            stored = repo.list_jobs(deps.user_id)
            applied = AppliedIndex.from_applications(repo.list_applications(deps.user_id))
        finally:
            repo.close()
        now = deps.now()
        targets = list((profile or {}).get("target_roles") or [])
        actions = deps.job_actions
        button = bool(actions and getattr(actions, "button_fetch_enabled", False))
        rows = []
        for j in stored:
            verdict = prefilter(j.title, j.location, profile, jd_text=j.jd_text) if profile else None
            if targets:
                highlight = match_role(j.title, targets) is not None
            else:
                highlight = matches_filters(j.title, j.location, deps.job_keywords, deps.job_locations)
            p = plan(j.link)
            can_fetch = bool(actions) and j.jd_status != "ok" and (p.automatic or (button and p.kind != "none"))
            rows.append({"job": j, "match": highlight and not (verdict and verdict.excluded),
                         "link": safe_link(j.link), "verdict": verdict, "can_fetch": can_fetch,
                         "why_not": p.why_not if p.kind == "none" else None,
                         "rank": rank_job(j, now=now, watchlist=deps.watchlist, applied=applied)})
        return rows, targets

    @app.get("/jobs")
    def jobs(request: Request, view: str = "candidates", sort: str = "score", match: int = 0) -> Response:
        if match:  # old links (/jobs?match=1) land on the candidates view
            view = "candidates"
        if view not in ("candidates", "all", "filtered"):
            view = "candidates"
        sort = sort if sort in ("score", "newest") else "score"
        try:
            profile = deps.profile_loader()
        except Exception:
            profile = None
        rows, targets = _job_rows(profile)
        excluded = [r for r in rows if r["verdict"] and r["verdict"].excluded]
        counts = {"candidates": len(rows) - len(excluded), "all": len(rows), "filtered": len(excluded)}
        if view == "candidates":
            rows = [r for r in rows if not (r["verdict"] and r["verdict"].excluded)]
        elif view == "filtered":
            rows = excluded
        if sort == "score":  # by rank; full before preliminary at equal rank; unscored last
            from mailwarden.core.ranking import sort_key

            rows.sort(key=lambda r: sort_key(r["job"], r["rank"]))
        apply_n = len(_apply_picks(profile))
        return render("jobs.html", request, rows=rows, view=view, sort=sort, counts=counts, apply_n=apply_n,
                      has_profile=profile is not None, targets=targets, keywords=deps.job_keywords,
                      locations=deps.job_locations, actions=deps.job_actions is not None)

    def _apply_picks(profile: dict | None):
        from mailwarden.core.ranking import AppliedIndex, apply_today

        repo = deps.repo_factory()
        try:
            jobs = repo.list_jobs(deps.user_id)
            applied = AppliedIndex.from_applications(repo.list_applications(deps.user_id))
        finally:
            repo.close()
        return apply_today(jobs, profile, n=deps.apply_today_count, now=deps.now(), watchlist=deps.watchlist,
                           applied=applied)

    @app.get("/apply")
    def apply_view(request: Request) -> Response:
        try:
            profile = deps.profile_loader()
        except Exception:
            profile = None
        picks = [{"job": j, "rank": info, "link": safe_link(j.link)} for j, info in _apply_picks(profile)]
        return render("apply.html", request, picks=picks, n=deps.apply_today_count, has_profile=profile is not None,
                      watchlist=deps.watchlist)

    def _back(form: dict[str, str], job_id: int | None = None) -> RedirectResponse:
        if form.get("view") == "apply":
            return RedirectResponse("/apply", status_code=303)
        view = form.get("view", "candidates")
        view = view if view in ("candidates", "all", "filtered") else "candidates"
        sort = form.get("sort", "score")
        sort = sort if sort in ("score", "newest") else "score"
        anchor = f"#job-{job_id}" if job_id else ""
        return RedirectResponse(f"/jobs?view={view}&sort={sort}{anchor}", status_code=303)

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
            profile = deps.profile_loader()
            rows, _ = _job_rows(profile)
            rows = [r for r in rows if r["can_fetch"] and not (r["verdict"] and r["verdict"].excluded)]
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
