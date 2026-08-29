"""Email OSINT: format, domain DNS/MX/SPF/DMARC, Gravatar, optional HIBP/GitHub.

Never attempts password discovery.
"""

from __future__ import annotations

import hashlib
from typing import Any

from spectre_osint.core.entities import Entity, Finding, Relationship
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.registry import ProviderRegistry
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType
from spectre_osint.modules.dns.resolver import resolve_records

FREE_PROVIDERS = {
    "gmail.com": "Google",
    "googlemail.com": "Google",
    "outlook.com": "Microsoft",
    "hotmail.com": "Microsoft",
    "live.com": "Microsoft",
    "yahoo.com": "Yahoo",
    "icloud.com": "Apple",
    "proton.me": "Proton",
    "protonmail.com": "Proton",
    "zoho.com": "Zoho",
}


async def analyze_email(
    entity: Entity,
    http: HttpClient,
    registry: ProviderRegistry,
    settings: Any,
) -> dict[str, Any]:
    local, domain = entity.normalized_value.split("@", 1)
    domain_entity = Entity.create(EntityType.DOMAIN, domain, source="email", confidence=Confidence.CONFIRMED)
    findings: list[Finding] = [
        Finding(
            module="email",
            title="Email format",
            status=FindingStatus.FOUND,
            summary=f"local={local} domain={domain}",
            data={
                "local_part": local,
                "domain": domain,
                "provider_guess": FREE_PROVIDERS.get(domain),
                "corporate_like": domain not in FREE_PROVIDERS,
            },
            confidence=Confidence.CONFIRMED,
            entity_id=entity.id,
        )
    ]
    entities: list[Entity] = [entity, domain_entity]
    relationships = [
        Relationship(
            from_entity_id=entity.id,
            to_entity_id=domain_entity.id,
            relation=RelationType.BELONGS_TO_DOMAIN,
            source="email",
            confidence=Confidence.CONFIRMED,
        )
    ]
    evidence = []
    queried = ["dns"]

    dns = await resolve_records(domain)
    findings.append(
        Finding(
            module="email",
            title="Mailbox domain DNS",
            status=FindingStatus.FOUND if dns.records.get("MX") else FindingStatus.NOT_FOUND,
            summary=(
                f"MX={dns.records.get('MX')} providers={dns.mail_providers} "
                f"SPF={dns.spf.get('present')} DMARC={dns.dmarc.get('policy')}"
            ),
            data={
                "mx": dns.records.get("MX"),
                "txt": dns.records.get("TXT"),
                "spf": dns.spf,
                "dmarc": dns.dmarc,
                "mail_providers": dns.mail_providers,
            },
            confidence=Confidence.CONFIRMED if dns.records.get("MX") else None,
            entity_id=entity.id,
        )
    )

    gravatar = await _gravatar(entity, http)
    findings.append(gravatar["finding"])
    evidence.extend(gravatar["evidence"])
    queried.append("gravatar")

    for name in ("hibp", "github"):
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


async def _gravatar(entity: Entity, http: HttpClient) -> dict[str, Any]:
    digest = hashlib.md5(entity.normalized_value.encode("utf-8")).hexdigest()  # noqa: S324 — Gravatar API contract
    url = f"https://www.gravatar.com/{digest}.json"
    try:
        response = await http.get(
            url,
            provider="gravatar",
            follow_redirects=True,
            accept_statuses={200, 404},
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "finding": Finding(
                module="email",
                title="Gravatar",
                status=FindingStatus.PROVIDER_UNAVAILABLE,
                summary=f"PROVIDER UNAVAILABLE: {exc}",
                entity_id=entity.id,
            ),
            "evidence": [],
        }
    if response.status_code == 404 or not response.json_data:
        return {
            "finding": Finding(
                module="email",
                title="Gravatar",
                status=FindingStatus.NOT_FOUND,
                summary="NOT FOUND",
                entity_id=entity.id,
            ),
            "evidence": [],
        }
    entry = (response.json_data.get("entry") or [{}])[0]
    display = entry.get("displayName")
    evidence = make_evidence(
        source="Gravatar",
        provider="gravatar",
        confidence=Confidence.MEDIUM,
        url=url,
        raw={"displayName": display, "profileUrl": entry.get("profileUrl")},
        entity_id=entity.id,
        notes="Public Gravatar profile is not identity confirmation.",
    )
    finding = Finding(
        module="email",
        title="Gravatar",
        status=FindingStatus.FOUND,
        summary=f"public profile displayName={display!r}",
        data={
            "display_name": display,
            "profile_url": entry.get("profileUrl"),
            "hash": digest,
        },
        confidence=Confidence.MEDIUM,
        entity_id=entity.id,
    )
    return {"finding": finding, "evidence": [evidence]}
