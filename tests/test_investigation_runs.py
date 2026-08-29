from __future__ import annotations

from sqlalchemy import func, select

from spectre_osint.core.case_manager import CaseManager
from spectre_osint.core.database import init_db, reset_engine, session_scope
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.models import FindingRow
from spectre_osint.core.types import Confidence, EntityType, FindingStatus


def test_rerun_and_rollback(settings) -> None:
    init_db(settings)
    try:
        manager = CaseManager()
        case = manager.create("alpha")
        run = manager.start_run(case.id, "example.com", "DOMAIN")
        entity = Entity.create(EntityType.DOMAIN, "example.com", "user", Confidence.CONFIRMED)
        result = InvestigationResult(
            case_id=case.id,
            case_name=case.name,
            target="example.com",
            target_type=EntityType.DOMAIN,
            mode="PASSIVE_OSINT",
            started_at=utcnow(),
            finished_at=utcnow(),
            run_id=run.id,
            entities=[entity],
            findings=[
                Finding(
                    module="dns",
                    title="DNS",
                    status=FindingStatus.FOUND,
                    summary="ok",
                    entity_id=entity.id,
                )
            ],
        )
        manager.persist_result(result)
        manager.finish_run(run.id, status="completed")
        with session_scope() as session:
            assert session.scalar(select(func.count()).select_from(FindingRow)) == 1
        assert manager.rollback_run(run.id)
        with session_scope() as session:
            assert session.scalar(select(func.count()).select_from(FindingRow)) == 0
        stored = manager.get_run(run.id)
        assert stored is not None
        assert stored.status == "rolled_back"
        run2 = manager.start_run(case.id, "example.com", "DOMAIN")
        result.run_id = run2.id
        result.findings[0].id = "second"
        manager.persist_result(result)
        manager.finish_run(run2.id, status="completed")
        loaded = manager.load_result("alpha")
        assert loaded is not None
        assert loaded.run_id == run2.id
    finally:
        reset_engine()
