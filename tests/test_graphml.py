from __future__ import annotations

from spectre_osint.core.entities import Entity, InvestigationResult, Relationship, utcnow
from spectre_osint.core.types import Confidence, EntityType, RelationType
from spectre_osint.correlation.graph import build_graph, export_graphml


def test_graphml_allows_missing_evidence_id(tmp_path) -> None:
    a = Entity.create(EntityType.DOMAIN, "example.com", "dns", Confidence.CONFIRMED)
    b = Entity.create(EntityType.IP, "93.184.216.34", "dns", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id="c",
        case_name="demo",
        target="example.com",
        target_type=EntityType.DOMAIN,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[a, b],
        relationships=[
            Relationship(
                from_entity_id=a.id,
                to_entity_id=b.id,
                relation=RelationType.RESOLVES_TO,
                source="DNS",
                confidence=Confidence.CONFIRMED,
                evidence_id=None,
            )
        ],
    )
    path = tmp_path / "g.graphml"
    export_graphml(build_graph(result), path)
    text = path.read_text(encoding="utf-8")
    assert "graphml" in text.lower()
    assert a.id in text
