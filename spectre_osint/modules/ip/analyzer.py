"""IP intelligence. Distinguishes RDAP/DNS from historical provider intel."""

from __future__ import annotations

import asyncio
from typing import Any

from spectre_osint.core.entities import Entity, Finding, Relationship
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.registry import ProviderRegistry
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.core.validators import ip_version, is_private_ip
from spectre_osint.modules.dns.resolver import reverse_dns


async def analyze_ip(
    entity: Entity,
    http: HttpClient,
    registry: ProviderRegistry,
    settings: Any,
    *,
    include_optional: bool = True,
) -> dict[str, Any]:
    findings: list[Finding] = []
    entities: list[Entity] = [entity]
    relationships: list[Relationship] = []
    evidence = []
    queried = ["ptr", "rdap"]

    version = ip_version(entity.normalized_value)
    private = is_private_ip(entity.normalized_value)
    findings.append(
        Finding(
            module="ip",
            title="IP classification",
            status=FindingStatus.FOUND,
            summary=f"IPv{version} private={private}",
            data={"version": version, "private": private, "value": entity.normalized_value},
            confidence=Confidence.CONFIRMED,
            entity_id=entity.id,
        )
    )

    ptrs = await reverse_dns(entity.normalized_value)
    if ptrs:
        ev = make_evidence(
            source="DNS PTR",
            provider="dns",
            confidence=Confidence.CONFIRMED,
            raw={"ptr": ptrs},
            entity_id=entity.id,
        )
        evidence.append(ev)
        findings.append(
            Finding(
                module="ip",
                title="Reverse DNS",
                status=FindingStatus.FOUND,
                summary="CONFIRMED " + ", ".join(ptrs),
                data={"ptr": ptrs},
                confidence=Confidence.CONFIRMED,
                entity_id=entity.id,
            )
        )
        for name in ptrs:
            try:
                host = Entity.create(EntityType.DOMAIN, name, source="PTR", confidence=Confidence.CONFIRMED)
                entities.append(host)
                from spectre_osint.core.types import RelationType

                relationships.append(
                    Relationship(
                        from_entity_id=entity.id,
                        to_entity_id=host.id,
                        relation=RelationType.RESOLVES_TO,
                        source="PTR",
                        confidence=Confidence.CONFIRMED,
                        evidence_id=ev.id,
                    )
                )
            except Exception:
                continue
    else:
        findings.append(
            Finding(
                module="ip",
                title="Reverse DNS",
                status=FindingStatus.NOT_FOUND,
                summary="NOT FOUND",
                entity_id=entity.id,
            )
        )

    async def run_provider(name: str) -> None:
        provider = registry.get(name)
        if not provider:
            return
        queried.append(name)
        result = await provider.safe_search(entity, settings)
        findings.extend(result.findings)
        entities.extend(result.entities)
        relationships.extend(result.relationships)
        evidence.extend(result.evidence)

    names = ["rdap"]
    if not private:
        names.append("ipinfo")
        if include_optional:
            names.extend(
                ["abuseipdb", "virustotal", "greynoise", "shodan", "censys", "alienvault"]
            )
    elif include_optional:
        findings.append(
            Finding(
                module="ip",
                title="External providers skipped",
                status=FindingStatus.SKIPPED,
                summary="Private/reserved IP is not sent to external intelligence providers",
                entity_id=entity.id,
            )
        )
    await asyncio.gather(*(run_provider(n) for n in names))

    return {
        "findings": findings,
        "entities": entities,
        "relationships": relationships,
        "evidence": evidence,
        "providers_queried": queried,
    }
