"""Auto-pivot suggestions. Never executes destructive follow-ups."""

from __future__ import annotations

from spectre_osint.core.entities import Entity, InvestigationResult, PivotSuggestion
from spectre_osint.core.types import Confidence, EntityType, RelationType


def suggest_pivots(result: InvestigationResult, *, limit: int = 12) -> list[PivotSuggestion]:
    suggestions: list[PivotSuggestion] = []
    seen: set[tuple[str, str]] = set()
    by_id = {e.id: e for e in result.entities}

    def add(action: str, entity: Entity, reason: str, confidence: Confidence, source: str) -> None:
        key = (action, entity.normalized_value)
        if key in seen:
            return
        seen.add(key)
        suggestions.append(
            PivotSuggestion(
                action=action,
                target=entity.normalized_value,
                entity_type=entity.type,
                reason=reason,
                confidence=confidence,
                source=source,
            )
        )

    for rel in result.relationships:
        src = by_id.get(rel.from_entity_id)
        dst = by_id.get(rel.to_entity_id)
        if not src or not dst:
            continue
        if rel.relation == RelationType.RESOLVES_TO and dst.type == EntityType.IP:
            add("Investigate IP", dst, f"{src.normalized_value} RESOLVES_TO this address via {rel.source}", rel.confidence, rel.source)
        if rel.relation == RelationType.BELONGS_TO_ASN:
            add("Investigate ASN", dst, f"{src.normalized_value} belongs to {dst.normalized_value}", rel.confidence, rel.source)
        if rel.relation == RelationType.HAS_SUBDOMAIN:
            add("Investigate certificate SAN / subdomain", dst, "Observed in Certificate Transparency", rel.confidence, rel.source)
        if rel.relation == RelationType.HAS_PROFILE:
            add("Review public profile", dst, "Public profile URL linked from collected source", rel.confidence, rel.source)
        if rel.relation == RelationType.HAS_MX:
            add("Investigate mail provider domain", dst, "MX target from public DNS", rel.confidence, rel.source)

    for entity in result.entities:
        if entity.type == EntityType.ASN:
            add("Investigate ASN", entity, "ASN discovered from RDAP/DNS", entity.confidence, entity.source)
        if entity.type == EntityType.ORGANIZATION:
            add("Investigate GitHub organization", entity, "Public GitHub org referenced", entity.confidence, entity.source)

    for finding in result.findings:
        if finding.module == "wayback" and finding.data.get("count"):
            add(
                "Check historical URLs",
                result.entities[0] if result.entities else Entity.create(EntityType.DOMAIN, result.target, "pivot", Confidence.LOW),
                "Wayback snapshots exist",
                Confidence.HIGH,
                "wayback",
            )

    return suggestions[:limit]
