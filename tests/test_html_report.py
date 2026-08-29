from __future__ import annotations

from spectre_osint.core.entities import Entity, Finding, InvestigationResult, ScoreBreakdown, utcnow
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.reporting.html import write_html_report


def test_html_report_contains_source_and_scores(tmp_path) -> None:
    entity = Entity.create(EntityType.DOMAIN, "example.com", "user", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id="c",
        case_name="demo",
        target="example.com",
        target_type=EntityType.DOMAIN,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        finished_at=utcnow(),
        entities=[entity],
        findings=[
            Finding(
                module="dns",
                title="DNS",
                status=FindingStatus.FOUND,
                summary="CONFIRMED A=1",
                confidence=Confidence.CONFIRMED,
            )
        ],
        scores=ScoreBreakdown(
            confidence_score=80,
            risk_score=5,
            reputation_score=70,
            confidence_explain=["test"],
            risk_explain=["test"],
            reputation_explain=["test"],
        ),
        providers_queried=["dns"],
    )
    path = write_html_report(result, tmp_path)
    html = path.read_text(encoding="utf-8")
    assert "example.com" in html
    assert "Confidence" in html
    assert "SPECTRE never invents facts" in html
