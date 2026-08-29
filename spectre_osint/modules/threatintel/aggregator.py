"""Aggregate threat intel across configured providers. Always keep source + timestamp."""

from __future__ import annotations

from typing import Any

from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.registry import ProviderRegistry
from spectre_osint.core.types import Confidence, FindingStatus


async def analyze_threat(
    entity: Entity,
    http: HttpClient,
    registry: ProviderRegistry,
    settings: Any,
) -> dict[str, Any]:
    names = ["virustotal", "alienvault", "urlscan", "abuseipdb", "greynoise", "shodan"]
    findings: list[Finding] = []
    entities = [entity]
    relationships = []
    evidence = []
    queried = []
    panel: dict[str, Any] = {}
    for name in names:
        provider = registry.get(name)
        if not provider or entity.type not in provider.supported_entities:
            panel[name] = "N/A"
            continue
        queried.append(name)
        result = await provider.safe_search(entity, settings)
        findings.extend(result.findings)
        entities.extend(result.entities)
        relationships.extend(result.relationships)
        evidence.extend(result.evidence)
        if result.status == FindingStatus.NOT_CONFIGURED:
            panel[name] = "Provider not configured"
        elif result.status == FindingStatus.PROVIDER_UNAVAILABLE:
            panel[name] = "PROVIDER UNAVAILABLE"
        elif result.status == FindingStatus.NOT_FOUND:
            panel[name] = "NOT FOUND"
        else:
            panel[name] = result.payload or result.status.value
    findings.insert(
        0,
        Finding(
            module="threatintel",
            title="Aggregated threat intelligence",
            status=FindingStatus.FOUND,
            summary=" | ".join(f"{k}: {v}" for k, v in panel.items()),
            data={"panel": panel},
            confidence=Confidence.HIGH if any(isinstance(v, dict) for v in panel.values()) else Confidence.LOW,
            entity_id=entity.id,
        ),
    )
    return {
        "findings": findings,
        "entities": entities,
        "relationships": relationships,
        "evidence": evidence,
        "providers_queried": queried,
    }
