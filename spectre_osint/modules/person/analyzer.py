"""People OSINT — strictly public sources, never identity confirmation."""

from __future__ import annotations

from typing import Any

from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.registry import ProviderRegistry
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.modules.username.checker import analyze_username


async def analyze_person(
    entity: Entity,
    http: HttpClient,
    registry: ProviderRegistry,
    settings: Any,
    *,
    username: str | None = None,
    email: str | None = None,
) -> dict[str, Any]:
    findings = [
        Finding(
            module="person",
            title="Person investigation bounds",
            status=FindingStatus.FOUND,
            summary="Public-source search only. Similar profiles are possible_match, never confirmed identity.",
            data={"name": entity.value, "username": username, "email": email},
            confidence=Confidence.LOW,
            entity_id=entity.id,
        )
    ]
    entities = [entity]
    relationships = []
    evidence = []
    queried = []

    if email:
        from spectre_osint.modules.email.analyzer import analyze_email

        mail_entity = Entity.create(
            EntityType.EMAIL, email, source="person-input", confidence=Confidence.MEDIUM
        )
        mail_bundle = await analyze_email(mail_entity, http, registry, settings)
        findings.extend(mail_bundle["findings"])
        entities.extend(mail_bundle["entities"])
        relationships.extend(mail_bundle["relationships"])
        evidence.extend(mail_bundle["evidence"])
        queried.extend(mail_bundle["providers_queried"])

    if username:
        user_entity = Entity.create(
            EntityType.USERNAME, username, source="person-input", confidence=Confidence.MEDIUM
        )
        user_bundle = await analyze_username(user_entity, http, concurrency=settings.max_concurrency)
        findings.extend(user_bundle["findings"])
        entities.extend(user_bundle["entities"])
        relationships.extend(user_bundle["relationships"])
        evidence.extend(user_bundle["evidence"])
        queried.extend(user_bundle["providers_queried"])

    provider = registry.get("github")
    if provider:
        queried.append("github")
        target = (
            Entity.create(EntityType.USERNAME, username, source="person", confidence=Confidence.MEDIUM)
            if username
            else entity
        )
        result = await provider.safe_search(target, settings)
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
