from __future__ import annotations

import pytest
from sqlalchemy import func, select

from spectre_osint.core.config import Settings
from spectre_osint.core.database import init_db, reset_engine, session_scope
from spectre_osint.core.entities import Finding
from spectre_osint.core.models import FindingRow, InvestigationRunRow
from spectre_osint.core.pipeline import InvestigationRunner
from spectre_osint.core.types import FindingStatus
from spectre_osint.reporting.html import write_html_report
from spectre_osint.reporting.json import write_json_report


@pytest.mark.asyncio
async def test_pipeline_persists_run_and_reports(tmp_path, monkeypatch) -> None:
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    init_db(settings)

    async def fake_collect(self, entity, extra):
        return {
            "findings": [
                Finding(
                    module="dns",
                    title="DNS",
                    status=FindingStatus.FOUND,
                    summary="CONFIRMED",
                    entity_id=entity.id,
                )
            ],
            "entities": [entity],
            "relationships": [],
            "evidence": [],
            "providers_queried": ["dns"],
        }

    monkeypatch.setattr(InvestigationRunner, "_collect", fake_collect)
    runner = InvestigationRunner(settings=settings)
    try:
        result = await runner.run("example.com", write_report=True)
        assert result.report_path
        from pathlib import Path

        assert Path(result.report_path).exists()
        json_files = list(settings.reports_dir.glob("*.json"))
        graph_files = list(settings.reports_dir.glob("*.graphml"))
        assert json_files
        assert graph_files
        with session_scope() as session:
            assert session.scalar(select(func.count()).select_from(InvestigationRunRow)) == 1
            assert session.scalar(select(func.count()).select_from(FindingRow)) == 1
        html = write_html_report(result, settings.reports_dir).read_text(encoding="utf-8")
        data = write_json_report(result, settings.reports_dir).read_bytes()
        assert b"example.com" in data
        assert "example.com" in html
    finally:
        await runner.close()
        reset_engine()
