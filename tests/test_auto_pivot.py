from __future__ import annotations

import pytest

from spectre_osint.core.config import Settings
from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.pipeline import InvestigationRunner
from spectre_osint.core.types import Confidence, EntityType, FindingStatus


@pytest.mark.asyncio
async def test_auto_pivot_depth_visited_budget(tmp_path, monkeypatch) -> None:
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
        pivot_budget=3,
    )
    settings.ensure_dirs()
    init_db(settings)
    calls: list[str] = []

    async def fake_collect(self, entity, extra):
        calls.append(entity.normalized_value)
        extra_entities = []
        if entity.normalized_value == "example.com":
            extra_entities.append(
                Entity.create(EntityType.IP, "93.184.216.34", "dns", Confidence.CONFIRMED)
            )
            extra_entities.append(
                Entity.create(EntityType.DOMAIN, "www.example.com", "ct", Confidence.CONFIRMED)
            )
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
            "entities": [entity, *extra_entities],
            "relationships": [],
            "evidence": [],
            "providers_queried": ["stub"],
        }

    monkeypatch.setattr(InvestigationRunner, "_collect", fake_collect)
    runner = InvestigationRunner(settings=settings)
    try:
        result = await runner.run("example.com", auto_pivot=True, depth=2, write_report=False)
        assert "example.com" in calls
        assert "93.184.216.34" in calls
        assert len(calls) <= 1 + settings.pivot_budget
        assert result.run_id
    finally:
        await runner.close()
        reset_engine()
