from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from spectre_osint.core.config import Settings
from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.core.entities import Finding
from spectre_osint.core.pipeline import InvestigationRunner
from spectre_osint.core.types import EntityType, FindingStatus
from spectre_osint.web.app import app


async def _stub_collect(self, entity, extra):
    return {
        "findings": [
            Finding(
                module="stub",
                title="stub",
                status=FindingStatus.FOUND,
                summary=entity.normalized_value,
                entity_id=entity.id,
            )
        ],
        "entities": [entity],
        "relationships": [],
        "evidence": [],
        "providers_queried": ["stub"],
    }


@pytest.mark.asyncio
async def test_two_targets_get_separate_cases(tmp_path, monkeypatch) -> None:
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    init_db(settings)
    monkeypatch.setattr(InvestigationRunner, "_collect", _stub_collect)
    runner = InvestigationRunner(settings=settings)
    try:
        first = await runner.run("alice-sec", force_type=EntityType.USERNAME, write_report=False)
        second = await runner.run(
            "https://example.com/", force_type=EntityType.URL, write_report=False
        )
        assert first.case_id != second.case_id
        assert "example.com" not in (first.target,)
        assert second.target != first.target
        cases = runner.cases.list_cases()
        combined = [tuple(c.targets or []) for c in cases]
        assert not any("alice-sec" in t and "example.com" in str(t) for t in combined)
    finally:
        await runner.close()
        reset_engine()


@pytest.mark.asyncio
async def test_explicit_case_adds_second_target(tmp_path, monkeypatch) -> None:
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    init_db(settings)
    monkeypatch.setattr(InvestigationRunner, "_collect", _stub_collect)
    runner = InvestigationRunner(settings=settings)
    try:
        first = await runner.run("alice-sec", force_type=EntityType.USERNAME, write_report=False)
        second = await runner.run(
            "https://example.com/",
            force_type=EntityType.URL,
            write_report=False,
            case_name=first.case_name,
        )
        assert first.case_id == second.case_id
        case = next(c for c in runner.cases.list_cases() if c.id == first.case_id)
        assert "alice-sec" in (case.targets or [])
        assert any("example.com" in str(t) for t in (case.targets or []))
    finally:
        await runner.close()
        reset_engine()


def test_dashboard_new_investigation_does_not_pass_case(settings, monkeypatch) -> None:
    init_db(settings)
    seen: list[tuple] = []

    class DummyRunner:
        async def run(self, target, case_name=None, **kwargs):
            seen.append((target, case_name))
            return None

        async def close(self) -> None:
            return None

    monkeypatch.setattr("spectre_osint.web.app.InvestigationRunner", DummyRunner)
    with TestClient(app) as client:
        a = client.post("/investigate", data={"target": "alice-sec", "mode": "new"})
        b = client.post(
            "/investigate",
            data={"target": "https://example.com/", "mode": "new"},
        )
        assert a.status_code in {200, 303, 400}
        assert b.status_code in {200, 303, 400}
        missing = client.post(
            "/investigate",
            data={"target": "octocat", "mode": "existing", "case_name": ""},
        )
        assert missing.status_code == 400
    assert seen[0][1] is None
    assert seen[1][1] is None
    reset_engine()
