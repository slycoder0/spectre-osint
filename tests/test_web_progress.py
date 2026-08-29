"""Tests for web progress integration (Task 4B).

Verifies:
A) web job receives ProgressEvent and updates serializable state.
B) catalog preserves factual current/total.
C) phase transitions update job state accurately.
D) degraded event does not mark job as failed.
E) repeated degraded provider does not produce spam (deduplicates).
F) completion/report preserves redirect flow.
G) legacy callbacks / missing callbacks work smoothly.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from spectre_osint.core.config import Settings
from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.core.progress import ProgressEvent, ProgressPhase, ProgressState
from spectre_osint.web.app import app
from spectre_osint.web.jobs import create_job, reset_jobs, update_job


def _client(tmp_path: Path) -> TestClient:
    s = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    s.ensure_dirs()
    init_db(s)
    return TestClient(app)


def test_web_job_receives_progress_event_and_updates_snapshot(tmp_path: Path):
    # Requirement A: web job receives ProgressEvent and updates serializable state
    reset_jobs()
    job = create_job(target="alice_osint", mode="new")

    ev = ProgressEvent(
        phase=ProgressPhase.CATALOG.value,
        state=ProgressState.RUNNING.value,
        current=12,
        total=57,
        provider="github",
        message="CONFIRMED",
    )
    update_job(job.id, ev.as_dict())

    snap = job.snapshot()
    assert snap["phase"] == "catalog"
    assert snap["state"] == "running"
    assert snap["current"] == 12
    assert snap["done"] == 12
    assert snap["total"] == 57
    assert snap["provider"] == "github"
    assert snap["progress_kind"] == "determinate"


def test_catalog_preserves_factual_current_and_total(tmp_path: Path):
    # Requirement B: catalog preserves factual current/total
    reset_jobs()
    job = create_job(target="alice_osint", mode="new")

    update_job(job.id, {"phase": "catalog", "state": "running", "current": 0, "total": 40})
    assert job.current == 0
    assert job.total == 40
    assert job.progress_kind == "determinate"

    update_job(job.id, {"phase": "catalog", "state": "running", "current": 25, "total": 40})
    assert job.current == 25
    assert job.total == 40
    assert job.progress_kind == "determinate"


def test_phase_transitions_update_job_state_correctly(tmp_path: Path):
    # Requirement C: phase transitions appear properly in job state
    reset_jobs()
    job = create_job(target="alice_osint", mode="new")

    phases = ["catalog", "mentions", "search", "discovery", "correlation", "scoring", "report"]
    for ph in phases:
        update_job(job.id, {"phase": ph, "state": "running"})
        snap = job.snapshot()
        assert snap["phase"] == ph
        assert snap["state"] == "running"
        if ph != "catalog":
            # Requirement: Non-catalog phases without known totals are indeterminate
            assert snap["progress_kind"] == "indeterminate"


def test_degraded_event_does_not_mark_job_as_failed(tmp_path: Path):
    # Requirement D: degraded event does not mark job as failed
    reset_jobs()
    job = create_job(target="alice_osint", mode="new")

    update_job(
        job.id,
        {
            "phase": "mentions",
            "state": "degraded",
            "provider": "duckduckgo-html",
            "message": "duckduckgo-html unavailable (timeout); continuing",
        },
    )
    snap = job.snapshot()
    assert snap["status"] == "running"  # Job must remain running!
    assert snap["state"] == "degraded"
    assert len(snap["degraded_sources"]) == 1
    assert snap["degraded_sources"][0]["provider"] == "duckduckgo-html"


def test_repeated_degraded_provider_does_not_spam(tmp_path: Path):
    # Requirement E: repeated degraded provider does not produce duplicate notices
    reset_jobs()
    job = create_job(target="alice_osint", mode="new")

    for _ in range(5):
        update_job(
            job.id,
            {
                "phase": "mentions",
                "state": "degraded",
                "provider": "duckduckgo-html",
                "message": "duckduckgo-html unavailable; continuing",
            },
        )
    snap = job.snapshot()
    assert len(snap["degraded_sources"]) == 1


def test_completion_preserves_redirect_flow(tmp_path: Path):
    # Requirement F: completion / report preserves redirect flow
    client = _client(tmp_path)
    reset_jobs()
    job = create_job(target="alice_osint", mode="new", case_id="case-1234")

    update_job(
        job.id,
        {
            "phase": "complete",
            "status": "complete",
            "case_id": "case-1234",
        },
    )

    res = client.get(f"/jobs/{job.id}")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "complete"
    assert data["case_id"] == "case-1234"

    res_page = client.get(f"/collecting/{job.id}", follow_redirects=False)
    assert res_page.status_code == 303
    assert res_page.headers["location"] == "/investigations/case-1234"
    reset_engine()


def test_legacy_or_missing_callback_works_cleanly(tmp_path: Path):
    # Requirement G: legacy dictionary updates work cleanly
    reset_jobs()
    job = create_job(target="alice_osint", mode="new")

    update_job(
        job.id,
        {
            "phase": "loading_catalog",
            "done": 5,
            "total": 20,
            "source": "twitter",
            "source_status": "FOUND",
        },
    )
    snap = job.snapshot()
    assert snap["phase"] == "loading_catalog"
    assert snap["done"] == 5
    assert snap["total"] == 20
