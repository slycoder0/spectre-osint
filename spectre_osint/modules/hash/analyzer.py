"""Hash intelligence. Never downloads malware."""

from __future__ import annotations

from typing import Any

from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.registry import ProviderRegistry
from spectre_osint.core.types import Confidence, FindingStatus
from spectre_osint.core.validators import detect_hash_algo


async def analyze_hash(
    entity: Entity,
    http: HttpClient,
    registry: ProviderRegistry,
    settings: Any,
) -> dict[str, Any]:
    algo = detect_hash_algo(entity.normalized_value)
    findings = [
        Finding(
            module="hash",
            title="Hash type",
            status=FindingStatus.FOUND,
            summary=f"{algo} {entity.normalized_value}",
            data={"algorithm": algo, "hash": entity.normalized_value},
            confidence=Confidence.CONFIRMED,
            entity_id=entity.id,
        )
    ]
    entities = [entity]
    relationships = []
    evidence = []
    queried: list[str] = []
    for name in ("virustotal", "alienvault"):
        provider = registry.get(name)
        if not provider:
            continue
        queried.append(name)
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
