from __future__ import annotations

from spectre_osint.core.entities import Entity, InvestigationResult, Relationship, utcnow
from spectre_osint.core.types import Confidence, EntityType, RelationType
from spectre_osint.correlation.confidence import merge_confidence
from spectre_osint.correlation.graph import build_graph
from spectre_osint.correlation.pivots import suggest_pivots


def test_merge_confidence_never_upgrades_inference_flag() -> None:
    assert merge_confidence(Confidence.LOW, Confidence.HIGH) == Confidence.HIGH
    assert merge_confidence(Confidence.CONFIRMED, allow_confirmed=False) == Confidence.HIGH


def test_graph_and_pivots() -> None:
    domain = Entity.create(EntityType.DOMAIN, "example.com", "dns", Confidence.CONFIRMED)
    ip = Entity.create(EntityType.IP, "1.2.3.4", "dns", Confidence.CONFIRMED)
    rel = Relationship(
        from_entity_id=domain.id,
        to_entity_id=ip.id,
        relation=RelationType.RESOLVES_TO,
        source="DNS",
        confidence=Confidence.CONFIRMED,
    )
    result = InvestigationResult(
        case_id="c",
        case_name="c",
        target="example.com",
        target_type=EntityType.DOMAIN,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[domain, ip],
        relationships=[rel],
    )
    graph = build_graph(result)
    assert graph.number_of_nodes() == 2
    assert graph.number_of_edges() == 1
    pivots = suggest_pivots(result)
    assert any(p.entity_type == EntityType.IP for p in pivots)
