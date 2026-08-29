"""SPECTRE OSINT web dashboard (Jinja2 + local JS). Single-user, localhost only."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from starlette.middleware.trustedhost import TrustedHostMiddleware

from spectre_osint import __version__
from spectre_osint.browser.auth import AuthService
from spectre_osint.core.case_manager import CaseManager
from spectre_osint.core.config import get_settings
from spectre_osint.core.database import init_db, session_scope
from spectre_osint.core.exceptions import SSRFBlocked, ValidationError
from spectre_osint.core.inputs import parse_target_inputs
from spectre_osint.core.models import CaseRow, EntityRow, FindingRow, InvestigationRunRow
from spectre_osint.core.pipeline import InvestigationRunner, _preflight_target  # noqa: F401
from spectre_osint.core.presentation import (
    ERROR_STATUSES,
    STATUS_FILTERS,
    classify_entity_observation,
    collection_health,
    filter_username_rows,
    group_username_rows,
    highlight_match,
    identity_view,
    investigation_meta,
    mention_findings,
    mention_groups,
    mention_relevance_counts,
    relation_label,
    search_kind_findings,
    sibling_reports,
    status_mark,
    top_evidence_rows,
    username_counts,
    username_rows,
)
from spectre_osint.core.registry import default_registry
from spectre_osint.core.ssrf import validate_url_syntax
from spectre_osint.core.timefmt import format_duration, format_ts, relative_age
from spectre_osint.core.types import EntityType
from spectre_osint.core.validators import detect_entity_type
from spectre_osint.modules.search.summary import build_intelligence_summary
from spectre_osint.web.graph_view import aggregated_graph
from spectre_osint.web.i18n import (
    LANG_COOKIE,
    THEME_COOKIE,
    normalize_lang,
    normalize_theme,
    resolve_lang,
    resolve_theme,
    translator,
)
from spectre_osint.web.jobs import create_job, execute_job, get_job

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"

COOKIE_MAX_AGE = 365 * 24 * 3600
_ENTITY_TYPE_ORDER = (
    "USERNAME",
    "SOCIAL_PROFILE",
    "PERSON",
    "DOMAIN",
    "EMAIL",
    "IP",
    "URL",
    "HASH",
    "PUBLIC_MENTION",
)


def _normalize_targets(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(item) for item in raw if item]
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    return []


def _case_card(case: dict[str, Any]) -> dict[str, Any]:
    """Presentation preview of a case. Does not change persisted investigation data."""
    targets = _normalize_targets(case.get("targets"))
    card: dict[str, Any] = {
        **case,
        "title": str(case.get("name") or ""),
        "target": targets[0] if targets else "",
        "aliases": targets[1:],
        "target_type": "",
        "confirmed": 0,
        "likely": 0,
        "mentions": 0,
        "status": "",
    }
    result = CaseManager().load_result_by_id(str(case["id"]))
    if result is None:
        if card["target"]:
            card["title"] = card["target"]
        return card
    inputs = result.inputs or {}
    card["target"] = result.target
    card["title"] = str(inputs.get("display_name") or "") or result.target
    card["aliases"] = [
        str(alias)
        for alias in (inputs.get("aliases") or [])
        if str(alias) and str(alias) != result.target
    ]
    ttype = result.target_type
    card["target_type"] = ttype.value if hasattr(ttype, "value") else str(ttype or "")
    counts = username_counts(result)
    card["confirmed"] = int(counts.get("confirmed") or 0)
    card["likely"] = int(counts.get("likely") or 0)
    card["mentions"] = int(sum(mention_relevance_counts(result).values()))
    card["status"] = "completed" if result.finished_at else "open"
    return card


def _preview_cases(cases: list[dict[str, Any]], *, limit: int | None = None) -> list[dict[str, Any]]:
    items = cases[:limit] if limit is not None else cases
    return [_case_card(case) for case in items]


def _system_stats(sessions: list[dict[str, str]], providers: list[Any]) -> dict[str, int]:
    active = sum(1 for row in sessions if row.get("session") == "ACTIVE")
    degraded_sess = sum(
        1
        for row in sessions
        if row.get("session")
        in {"CHALLENGE_REQUIRED", "SESSION_EXPIRED", "CAPTCHA_REQUIRED", "BLOCKED"}
    )
    configured = sum(
        1
        for row in providers
        if getattr(row, "configured", False) or getattr(row, "configured_label", "") == "YES"
    )
    unavailable = sum(1 for row in providers if getattr(row, "available", None) is False)
    return {
        "provider_count": len(providers),
        "configured_providers": configured,
        "active_sessions": active,
        "session_count": len(sessions),
        "degraded": degraded_sess + unavailable,
    }


@asynccontextmanager
async def lifespan(_app: FastAPI):
    get_settings()
    init_db()
    yield


app = FastAPI(title="SPECTRE OSINT", version=__version__, lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
templates.env.globals["relation_label"] = relation_label
templates.env.globals["relative_age"] = relative_age
templates.env.globals["format_ts"] = format_ts
templates.env.globals["format_duration"] = format_duration
templates.env.globals["status_mark"] = status_mark
templates.env.globals["highlight_match"] = highlight_match
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _here(request: Request) -> str:
    path = request.url.path or "/"
    if request.url.query:
        return f"{path}?{request.url.query}"
    return path


def _safe_next(value: str | None) -> str:
    raw = (value or "/").strip() or "/"
    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc:
        return "/"
    if not raw.startswith("/"):
        return "/"
    return raw


def _set_pref_cookie(response: RedirectResponse, name: str, value: str) -> None:
    response.set_cookie(
        name,
        value,
        max_age=COOKIE_MAX_AGE,
        samesite="lax",
        httponly=False,
        path="/",
    )


def render(request: Request, name: str, context: dict[str, Any]) -> HTMLResponse:
    lang = resolve_lang(request)
    theme = resolve_theme(request)
    t = translator(lang)
    payload = {
        **context,
        "request": request,
        "version": context.get("version") or __version__,
        "lang": lang,
        "theme": theme,
        "t": t,
        "html_lang": t.html_lang(),
        "here": _here(request),
        "nav": request.url.path,
    }
    try:
        return templates.TemplateResponse(request, name, payload)
    except TypeError:
        return templates.TemplateResponse(name, payload)  # type: ignore[arg-type]


@app.get("/prefs")
def prefs(
    request: Request,
    lang: str | None = None,
    theme: str | None = None,
    next: str = "/",
) -> RedirectResponse:
    response = RedirectResponse(_safe_next(next), status_code=303)
    if lang is not None:
        _set_pref_cookie(response, LANG_COOKIE, normalize_lang(lang))
    if theme is not None:
        _set_pref_cookie(response, THEME_COOKIE, normalize_theme(theme))
    return response


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    with session_scope() as session:
        cases = session.scalars(select(CaseRow).order_by(CaseRow.updated_at.desc()).limit(20)).all()
        entity_count = session.scalar(select(func.count()).select_from(EntityRow)) or 0
        finding_count = session.scalar(select(func.count()).select_from(FindingRow)) or 0
        payload = [
            {
                "id": c.id,
                "name": c.name,
                "targets": c.targets,
                "updated_at": c.updated_at,
                "active": c.active,
            }
            for c in cases
        ]
    sessions = AuthService().status_rows()
    active_sources = sum(1 for row in sessions if row.get("session") == "ACTIVE")
    registry = default_registry(http_client=None)
    providers = await registry.health(get_settings(), probe=False)
    configured_providers = sum(
        1 for row in providers if row.configured or row.status != "NOT CONFIGURED"
    )
    last_case: dict[str, Any] | None = payload[0] if payload else None
    last_health = None
    last_meta = None
    if last_case:
        result = CaseManager().load_result_by_id(str(last_case["id"]))
        if result is not None:
            last_health = collection_health(username_counts(result))
            last_meta = investigation_meta(result)
    case_cards = _preview_cases(payload, limit=6)
    return render(
        request,
        "dashboard.html",
        {
            "cases": payload,
            "case_cards": case_cards,
            "entity_count": entity_count,
            "finding_count": finding_count,
            "version": __version__,
            "sessions": sessions,
            "active_sources": active_sources,
            "configured_providers": configured_providers,
            "provider_count": len(providers),
            "last_case": last_case,
            "last_card": case_cards[0] if case_cards else None,
            "last_health": last_health,
            "last_meta": last_meta,
        },
    )


@app.get("/sessions", response_class=HTMLResponse)
async def sessions_page(request: Request) -> HTMLResponse:
    sessions = AuthService().status_rows()
    registry = default_registry(http_client=None)
    providers = await registry.health(get_settings(), probe=False)
    return render(
        request,
        "sessions.html",
        {
            "sessions": sessions,
            "system_stats": _system_stats(sessions, list(providers)),
            "version": __version__,
        },
    )


@app.get("/investigations", response_class=HTMLResponse)
def investigations(request: Request) -> HTMLResponse:
    with session_scope() as session:
        cases = session.scalars(select(CaseRow).order_by(CaseRow.updated_at.desc())).all()
        payload = [
            {
                "id": c.id,
                "name": c.name,
                "targets": c.targets,
                "updated_at": c.updated_at,
                "notes": c.notes,
            }
            for c in cases
        ]
    return render(
        request,
        "investigations.html",
        {"cases": payload, "case_cards": _preview_cases(payload)},
    )


@app.get("/entities", response_class=HTMLResponse)
def entities(request: Request, observation: str = "ALL") -> HTMLResponse:
    wanted = observation.upper()
    if wanted not in {"ALL", "LATEST", "HISTORICAL"}:
        wanted = "ALL"
    with session_scope() as session:
        rows = session.scalars(select(EntityRow).limit(200)).all()
        cases = {c.id: c.name for c in session.scalars(select(CaseRow)).all()}
        runs = list(
            session.scalars(
                select(InvestigationRunRow).where(InvestigationRunRow.status == "completed")
            )
        )
    latest_run: dict[str, InvestigationRunRow] = {}
    for run in runs:
        prev = latest_run.get(run.case_id)
        stamp = run.finished_at or run.started_at
        if prev is None:
            latest_run[run.case_id] = run
            continue
        prev_stamp = prev.finished_at or prev.started_at
        if stamp and prev_stamp and stamp > prev_stamp:
            latest_run[run.case_id] = run
    payload = []
    for row in rows:
        observed = latest_run.get(row.case_id)
        classified = classify_entity_observation(
            last_seen=row.last_seen,
            latest_run_started=observed.started_at if observed else None,
            latest_run_finished=observed.finished_at if observed else None,
        )
        item = {
            "type": row.type,
            "value": row.normalized_value,
            "confidence": row.confidence,
            "source": row.source,
            "case_id": row.case_id,
            "case_name": cases.get(row.case_id, row.case_id),
            "case_href": f"/investigations/{row.case_id}",
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
            "run_id": observed.id if observed else None,
            "kind": classified["kind"],
            "superseded": classified["superseded"],
        }
        if wanted == "LATEST" and item["kind"] != "LATEST":
            continue
        if wanted == "HISTORICAL" and item["kind"] != "HISTORICAL":
            continue
        payload.append(item)
    grouped: dict[str, list] = {}
    by_type: dict[str, list] = {}
    for item in payload:
        grouped.setdefault(item["case_name"], []).append(item)
        by_type.setdefault(str(item["type"]), []).append(item)
    ordered_types: dict[str, list] = {}
    for key in _ENTITY_TYPE_ORDER:
        if key in by_type:
            ordered_types[key] = by_type[key]
    for key, rows in by_type.items():
        if key not in ordered_types:
            ordered_types[key] = rows
    return render(
        request,
        "entities.html",
        {
            "entities": payload,
            "by_case": grouped,
            "by_type": ordered_types,
            "observation": wanted,
        },
    )


@app.get("/providers", response_class=HTMLResponse)
async def providers(request: Request, filter: str = "all") -> HTMLResponse:
    settings = get_settings()
    registry = default_registry(http_client=None)
    rows = await registry.health(settings, probe=False)
    wanted = (filter or "all").lower()
    filtered = []
    for row in rows:
        bucket = "all"
        if row.status == "NOT CONFIGURED":
            bucket = "not_configured"
        elif not row.probed:
            bucket = "not_probed"
        elif row.available is True:
            bucket = "available"
        elif row.available is False:
            bucket = "unavailable"
        if wanted != "all" and bucket != wanted:
            continue
        filtered.append(row)
    sessions = AuthService().status_rows()
    return render(
        request,
        "providers.html",
        {
            "providers": filtered,
            "provider_filter": wanted,
            "provider_total": len(rows),
            "system_stats": _system_stats(sessions, list(rows)),
        },
    )


def _start_collection_job(
    *,
    target: str,
    mode: str,
    case_name: str | None,
    background: BackgroundTasks,
    case_id: str | None = None,
    force_type: EntityType | None = None,
    refresh: bool = False,
    extra: dict[str, Any] | None = None,
) -> str:
    settings = get_settings()
    entity_type = force_type or detect_entity_type(target)
    if entity_type == EntityType.URL:
        validate_url_syntax(target)
    _preflight_target(target, entity_type, settings)
    job = create_job(
        target=target,
        mode=mode,
        case_name=case_name,
        case_id=case_id,
        force_type=entity_type.value,
        refresh=refresh,
        target_type=entity_type.value,
        extra=extra,
    )
    background.add_task(execute_job, job.id)
    return job.id


@app.post("/investigate")
async def start_investigation(
    request: Request,
    background: BackgroundTasks,
    target: str = Form(...),
    mode: str = Form("new"),
    case_name: str | None = Form(None),
    display_name: str | None = Form(None),
    email: str | None = Form(None),
    website: str | None = Form(None),
) -> RedirectResponse:
    attach = case_name if mode == "existing" and case_name else None
    if mode == "existing" and not attach:
        raise HTTPException(status_code=400, detail="Select a case to add this target to.")
    form = await request.form()
    aliases = [str(item) for item in form.getlist("alias") if str(item).strip()]
    try:
        parsed = parse_target_inputs(
            target,
            aliases=aliases,
            display_name=display_name,
            email=email,
            website=website,
        )
        extra = {"inputs": parsed.as_dict()}
        job_id = _start_collection_job(
            target=parsed.primary,
            mode=mode,
            case_name=attach,
            background=background,
            force_type=parsed.primary_type,
            extra=extra,
        )
    except (SSRFBlocked, ValidationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse(f"/collecting/{job_id}", status_code=303)


@app.get("/collecting/{job_id}", response_model=None)
def collecting_page(request: Request, job_id: str) -> Response:
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Collection job not found")
    if job.status == "complete" and job.case_id:
        return RedirectResponse(f"/investigations/{job.case_id}", status_code=303)
    return render(request, "collecting.html", {"job": job, "snapshot": job.snapshot()})


@app.get("/jobs/{job_id}")
def job_status(job_id: str) -> JSONResponse:
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Collection job not found")
    return JSONResponse(job.snapshot())


@app.get("/investigations/{case_id}", response_class=HTMLResponse)
def investigation_detail(request: Request, case_id: str, status: str = "ALL") -> HTMLResponse:
    result = CaseManager().load_result_by_id(case_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    rows = username_rows(result)
    counts = username_counts(result)
    meta = investigation_meta(result)
    reports = sibling_reports(result.report_path)
    identity = identity_view(result)
    mentions = mention_findings(result)
    mention_by_input = mention_groups(result)
    return render(
        request,
        "investigation.html",
        {
            "result": result,
            "meta": meta,
            "username_rows": filter_username_rows(rows, status),
            "username_all": rows,
            "username_groups": group_username_rows(rows),
            "counts": counts,
            "health": collection_health(counts),
            "identity": identity,
            "graph": aggregated_graph(result),
            "top_evidence": top_evidence_rows(rows),
            "mentions": mentions,
            "mention_groups": mention_by_input,
            "mention_counts": mention_relevance_counts(result),
            "intel_summary": build_intelligence_summary(result),
            "discovered_profiles": search_kind_findings(result, "discovered_profile"),
            "new_indicators": search_kind_findings(result, "indicator"),
            "auto_pivots": search_kind_findings(result, "pivot"),
            "inputs": result.inputs or {},
            "filter": status.upper(),
            "filters": STATUS_FILTERS,
            "reports": reports,
            "errors": [
                f for f in result.findings if f.status.value in ERROR_STATUSES
            ],
        },
    )


@app.post("/investigations/{case_id}/refresh")
async def refresh_investigation(case_id: str, background: BackgroundTasks) -> RedirectResponse:
    result = CaseManager().load_result_by_id(case_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    try:
        extra = {"inputs": result.inputs} if result.inputs else None
        job_id = _start_collection_job(
            target=result.target,
            mode="refresh",
            case_name=result.case_name,
            background=background,
            case_id=result.case_id,
            force_type=result.target_type,
            refresh=True,
            extra=extra,
        )
    except (SSRFBlocked, ValidationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse(f"/collecting/{job_id}", status_code=303)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__, "bind": "localhost-only"}
