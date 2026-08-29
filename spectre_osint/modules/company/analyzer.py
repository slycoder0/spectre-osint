"""Company OSINT limited to public GitHub org + optional domain if user provided it."""

from __future__ import annotations

from typing import Any

from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.registry import ProviderRegistry
from spectre_osint.core.types import Confidence, FindingStatus


async def analyze_company(
    entity: Entity,
    http: HttpClient,
    registry: ProviderRegistry,
    settings: Any,
) -> dict[str, Any]:
    findings = [
        Finding(
            module="company",
            title="Company target",
            status=FindingStatus.FOUND,
            summary=entity.value,
            data={"name": entity.value, "note": "No domain is inferred from the name."},
            confidence=Confidence.CONFIRMED,
            entity_id=entity.id,
        )
    ]
    entities = [entity]
    relationships = []
    evidence = []
    queried = []
    provider = registry.get("github")
    if provider:
        queried.append("github")
        result = await provider.safe_search(entity, settings)
        findings.extend(result.findings)
        entities.extend(result.entities)
        relationships.extend(result.relationships)
        evidence.extend(result.evidence)
    return {
        "findings": findings,
        "entities": entities,
        "relationships": relationships,
        "evidence": evidence,
        "providers_queried": queried,
    }
