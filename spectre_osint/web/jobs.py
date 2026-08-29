"""In-memory collection jobs for the localhost GUI.

Progress is derived from backend callbacks. Percent is never invented.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from spectre_osint.core.exceptions import SSRFBlocked, ValidationError
from spectre_osint.core.logger import get_logger
from spectre_osint.core.pipeline import InvestigationRunner as DefaultRunner
from spectre_osint.core.types import EntityType

logger = get_logger("spectre.web.jobs")

_LOCK = threading.Lock()
_JOBS: dict[str, CollectionJob] = {}
_MAX_JOBS = 80
_MAX_SOURCES = 16
_SECRETISH = ("cookie", "token", "storage_state", "authorization", "password")


@dataclass
class CollectionJob:
    id: str
    target: str
    mode: str
    case_name: str | None = None
    case_id: str | None = None
    force_type: str | None = None
    refresh: bool = False
    status: str = "running"
    phase: str = "initializing"
    state: str = "running"
    done: int | None = None
    total: int | None = None
    current: int | None = None
    provider: str | None = None
    message: str | None = None
    sources: list[dict[str, str]] = field(default_factory=list)
    degraded_sources: list[dict[str, str]] = field(default_factory=list)
    error: str | None = None
    target_type: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def progress_kind(self) -> str:
        return (
            "determinate"
            if (self.total and self.phase in {"catalog", "loading_catalog", "collecting"})
            else "indeterminate"
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "mode": self.mode,
            "status": self.status,
            "phase": self.phase,
            "state": self.state,
            "done": self.done,
            "current": self.current,
            "total": self.total,
            "provider": self.provider,
            "message": self.message,
            "sources": list(self.sources),
            "degraded_sources": list(self.degraded_sources),
            "case_id": self.case_id,
            "error": self.error,
            "target_type": self.target_type,
            "progress_kind": self.progress_kind,
            "refresh": self.refresh,
        }


def reset_jobs() -> None:
    with _LOCK:
        _JOBS.clear()


def get_job(job_id: str) -> CollectionJob | None:
    with _LOCK:
        return _JOBS.get(job_id)


def create_job(
    *,
    target: str,
    mode: str,
    case_name: str | None = None,
    case_id: str | None = None,
    force_type: str | None = None,
    refresh: bool = False,
    target_type: str | None = None,
    extra: dict[str, Any] | None = None,
) -> CollectionJob:
    job = CollectionJob(
        id=uuid4().hex,
        target=target,
        mode=mode,
        case_name=case_name,
        case_id=case_id,
        force_type=force_type,
        refresh=refresh,
        target_type=target_type,
        extra=dict(extra or {}),
    )
    with _LOCK:
        _JOBS[job.id] = job
        overflow = list(_JOBS.keys())[:-_MAX_JOBS]
        for key in overflow:
            _JOBS.pop(key, None)
    return job


def _sanitize_error(message: str) -> str:
    text = message.strip()
    lowered = text.lower()
    if any(token in lowered for token in _SECRETISH):
        return "Collection failed."
    return text[:400]


def update_job(job_id: str, payload: dict[str, Any]) -> None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return
        phase = payload.get("phase")
        if isinstance(phase, str) and phase:
            job.phase = phase
        state = payload.get("state")
        if isinstance(state, str) and state:
            job.state = state
        status = payload.get("status")
        if isinstance(status, str) and status:
            job.status = status

        curr_val = payload.get("current") if "current" in payload else payload.get("done")
        if curr_val is not None:
            try:
                job.done = int(curr_val)
                job.current = int(curr_val)
            except (TypeError, ValueError):
                pass

        if "total" in payload and payload["total"] is not None:
            try:
                job.total = int(payload["total"])
            except (TypeError, ValueError):
                pass

        case_id = payload.get("case_id")
        if isinstance(case_id, str) and case_id:
            job.case_id = case_id
        error = payload.get("error")
        if isinstance(error, str) and error:
            job.error = _sanitize_error(error)

        provider = payload.get("provider") or payload.get("source")
        if isinstance(provider, str) and provider:
            name = provider.strip()[:80]
            if name and not any(token in name.lower() for token in _SECRETISH):
                job.provider = name
                msg = str(payload.get("message") or payload.get("source_status") or "")[:120]
                job.message = msg
                if state == "degraded":
                    detail = msg or f"{name} unavailable; continuing"
                    if not any(d.get("provider") == name for d in job.degraded_sources):
                        job.degraded_sources.append({"provider": name, "message": detail})
                        job.degraded_sources = job.degraded_sources[-_MAX_SOURCES:]
                elif "source_status" in payload or "source" in payload:
                    job.sources.append({"name": name, "status": msg})
                    job.sources = job.sources[-_MAX_SOURCES:]


async def execute_job(job_id: str) -> None:
    job = get_job(job_id)
    if job is None:
        return

    def progress(payload: dict[str, Any]) -> None:
        update_job(job_id, payload)

    try:
        from spectre_osint.web import app as web_app

        runner = web_app.InvestigationRunner()
    except Exception:  # pragma: no cover
        runner = DefaultRunner()
    try:
        force: EntityType | None = None
        if job.force_type and job.force_type in EntityType._value2member_map_:
            force = EntityType(job.force_type)
        result = await runner.run(
            job.target,
            force_type=force,
            case_name=job.case_name,
            refresh=job.refresh,
            extra=job.extra or None,
            progress=progress,
        )
        if result is None:
            update_job(job_id, {"phase": "failed", "status": "failed", "error": "No result"})
            return
        update_job(
            job_id,
            {
                "phase": "complete",
                "status": "complete",
                "case_id": result.case_id,
                "done": job.done if job.total else None,
                "total": job.total,
            },
        )
    except (SSRFBlocked, ValidationError) as exc:
        update_job(job_id, {"phase": "failed", "status": "failed", "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        logger.warning("Collection job %s failed: %s", job_id, exc)
        update_job(job_id, {"phase": "failed", "status": "failed", "error": str(exc)})
    finally:
        await runner.close()


def spawn_job(job: CollectionJob) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(execute_job(job.id))
        return
    loop.create_task(execute_job(job.id))
