"""Tests for factual progress events and CLI rendering.

Factual progress rules:
- Factual phase names (catalog, mentions, search, discovery, correlation, scoring, report).
- Factual states (running, completed, degraded).
- Exact counts when known (catalog current/total).
- Never invent percentages.
- Degraded provider does not fail investigation.
- Missing callback works cleanly.
- CLI consumes events cleanly without altering result.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import httpx
import pytest
from rich.console import Console

from spectre_osint.cli.display import CliProgressReporter
from spectre_osint.core.config import Settings
from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.core.entities import Confidence, Entity, Finding
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.pipeline import InvestigationRunner
from spectre_osint.core.progress import ProgressEvent, ProgressPhase, ProgressState
from spectre_osint.core.types import EntityType, FindingStatus
from spectre_osint.modules.username.engine import analyze_username


def _settings(tmp_path: Path) -> Settings:
    s = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    s.ensure_dirs()
    init_db(s)
    return s


@pytest.mark.asyncio
async def test_progress_event_contract_structure() -> None:
    # A ProgressEvent must hold only factual information and serialize properly
    ev = ProgressEvent(
        phase=ProgressPhase.CATALOG.value,
        state=ProgressState.RUNNING.value,
        current=18,
        total=57,
        provider="github",
        message="CONFIRMED",
    )
    payload = ev.as_dict()
    assert payload["phase"] == "catalog"
    assert payload["state"] == "running"
    assert payload["current"] == 18
    assert payload["done"] == 18  # Backwards compatibility
    assert payload["total"] == 57
    assert payload["provider"] == "github"
    assert payload["source"] == "github"  # Backwards compatibility
    assert payload["message"] == "CONFIRMED"
    assert "percent" not in payload  # Never invent percentages

    parsed = ProgressEvent.from_payload(payload)
    assert parsed.phase == "catalog"
    assert parsed.state == "running"
    assert parsed.current == 18
    assert parsed.total == 57
    assert parsed.provider == "github"


@pytest.mark.asyncio
async def test_catalog_emits_real_current_and_total(tmp_path: Path, monkeypatch) -> None:
    # Requirement B: catalog emits real current/total counts
    settings = _settings(tmp_path)
    events: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    http = HttpClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleeper=lambda _s: None,
        jitter_fn=lambda: 0.0,
    )
    monkeypatch.setattr(
        "spectre_osint.modules.username.engine.load_sites",
        lambda: [
            {"name": "Site1", "profile_url": "https://site1.example/{username}", "check_method": "generic_html", "enabled": True},
            {"name": "Site2", "profile_url": "https://site2.example/{username}", "check_method": "generic_html", "enabled": True},
            {"name": "Site3", "profile_url": "https://site3.example/{username}", "check_method": "generic_html", "enabled": True},
        ],
    )
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    try:
        await analyze_username(entity, http, concurrency=2, progress=events.append)
        catalog_events = [e for e in events if e.get("phase") == "catalog"]
        assert len(catalog_events) >= 4  # Start, 3 sites, completed
        start_ev = catalog_events[0]
        assert start_ev["current"] == 0
        assert start_ev["total"] == 3

        end_ev = catalog_events[-1]
        assert end_ev["state"] == "completed"
        assert end_ev["current"] == 3
        assert end_ev["total"] == 3
    finally:
        await http.close()
        reset_engine()


@pytest.mark.asyncio
async def test_pipeline_emits_phases_in_coherent_order(tmp_path: Path, monkeypatch) -> None:
    # Requirement A: pipeline emits phases in coherent sequence
    # Requirement C: phases without known totals do NOT receive invented percentages
    settings = _settings(tmp_path)
    events: list[dict[str, Any]] = []

    async def fake_collect(self, entity, extra):
        return {
            "findings": [
                Finding(
                    module="username",
                    title="GitHub",
                    status=FindingStatus.FOUND,
                    summary="CONFIRMED",
                    entity_id=entity.id,
                )
            ],
            "entities": [entity],
            "relationships": [],
            "evidence": [],
            "providers_queried": ["github"],
            "pivots": [],
        }

    monkeypatch.setattr(InvestigationRunner, "_collect", fake_collect)
    runner = InvestigationRunner(settings=settings)
    try:
        result = await runner.run("alice_osint", write_report=True, progress=events.append)
        assert result.case_name
        phases = [e.get("phase") for e in events]
        assert "initializing" in phases
        assert "normalizing" in phases
        assert "discovery" in phases
        assert "scoring" in phases
        assert "report" in phases

        # Verify no percentage fields are synthesized
        for ev in events:
            assert "percent" not in ev
            assert "percentage" not in ev
    finally:
        await runner.close()
        reset_engine()


@pytest.mark.asyncio
async def test_degraded_provider_emits_degraded_and_continues(tmp_path: Path) -> None:
    # Requirement D: degraded provider emits degraded status, investigation continues normally
    settings = _settings(tmp_path)
    events: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host or ""
        if "duckduckgo.com" in host:
            raise httpx.ConnectTimeout("timeout", request=request)
        return httpx.Response(200, json={"total_count": 0, "items": []})

    http = HttpClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleeper=lambda _s: None,
        jitter_fn=lambda: 0.0,
    )
    runner = InvestigationRunner(settings=settings, http=http)
    try:
        result = await runner.run("alice_osint", write_report=False, progress=events.append)
        assert result is not None
        degraded = [e for e in events if e.get("state") == "degraded"]
        assert len(degraded) >= 1
        for d in degraded:
            assert d.get("phase") in {"mentions", "search"}
            assert d.get("message") is not None
    finally:
        await runner.close()
        reset_engine()


@pytest.mark.asyncio
async def test_missing_progress_callback_works_cleanly(tmp_path: Path, monkeypatch) -> None:
    # Requirement E: callback ausente continua funcionando normalmente
    settings = _settings(tmp_path)

    async def fake_collect(self, entity, extra):
        return {
            "findings": [],
            "entities": [entity],
            "relationships": [],
            "evidence": [],
            "providers_queried": [],
        }

    monkeypatch.setattr(InvestigationRunner, "_collect", fake_collect)
    runner = InvestigationRunner(settings=settings)
    try:
        result = await runner.run("alice_osint", write_report=False, progress=None)
        assert result is not None
        assert result.target == "alice_osint"
    finally:
        await runner.close()
        reset_engine()


@pytest.mark.asyncio
async def test_cli_progress_reporter_consumes_events_without_spam(tmp_path: Path) -> None:
    # Requirement F: CLI consumes events without altering result or spamming
    output = io.StringIO()
    test_console = Console(file=output, highlight=False, force_terminal=False)
    reporter = CliProgressReporter(console_instance=test_console)

    reporter({"phase": "catalog", "state": "running", "current": 0, "total": 30})
    for i in range(1, 31):
        reporter({"phase": "catalog", "state": "running", "current": i, "total": 30, "provider": f"site{i}"})
    reporter({"phase": "catalog", "state": "completed", "current": 30, "total": 30})
    reporter({"phase": "mentions", "state": "running"})
    reporter({"phase": "mentions", "state": "degraded", "provider": "duckduckgo-html", "message": "duckduckgo-html unavailable; continuing"})
    reporter({"phase": "mentions", "state": "completed"})
    reporter({"phase": "scoring", "state": "running"})
    reporter({"phase": "scoring", "state": "completed"})

    text = output.getvalue()
    assert "Checking public profiles..." in text
    assert "30/30 checked" in text
    assert "Searching public mentions..." in text
    assert "duckduckgo-html unavailable; continuing" in text
    assert "Scoring findings..." in text
    # Ensure it did not print 30 separate lines for each individual site check
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    assert len(lines) < 15
