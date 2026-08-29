"""Certificate Transparency via crt.sh (public, no API key)."""

from __future__ import annotations

from typing import Any

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Relationship
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType
from spectre_osint.core.validators import is_domain, normalize_domain
from spectre_osint.providers.base import Provider, ProviderResult


class CrtShProvider(Provider):
    name = "crtsh"
    supported_entities = frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN})
    requires_api_key = False
    health_url = "https://crt.sh/"
    rate_limit = "1.0s"

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        query = entity.normalized_value
        url = "https://crt.sh/"
        response = await self.http.get(
            url,
            provider=self.name,
            params={"q": query, "output": "json"},
            follow_redirects=True,
            cache_ttl=settings.cache_crtsh_ttl,
            accept_statuses=set(range(200, 500)),
        )
        if response.status_code >= 400:
            raise ProviderUnavailable(f"crt.sh HTTP {response.status_code}")
        rows = response.json_data
        if not isinstance(rows, list):
            if response.status_code == 200 and not rows:
                return _empty(entity)
            raise ProviderUnavailable("crt.sh returned non-JSON or unexpected payload")
        if not rows:
            return _empty(entity)

        parsed = _parse_certificates(rows, query)
        evidence = make_evidence(
            source="Certificate Transparency",
            provider=self.name,
            confidence=Confidence.CONFIRMED,
            url=f"https://crt.sh/?q={query}",
            raw={"count": len(parsed["certificates"]), "sample": parsed["certificates"][:5]},
            entity_id=entity.id,
        )
        from spectre_osint.core.entities import Finding

        finding = Finding(
            module=self.name,
            title="Certificate Transparency",
            status=FindingStatus.FOUND,
            summary=(
                f"CONFIRMED {len(parsed['certificates'])} certificates, "
                f"{len(parsed['subdomains'])} unique names"
            ),
            data=parsed,
            confidence=Confidence.CONFIRMED,
            entity_id=entity.id,
        )
        sub_entities: list[Entity] = []
        relationships: list[Relationship] = []
        for name in parsed["subdomains"][:200]:
            if name == entity.normalized_value:
                continue
            try:
                sub = Entity.create(
                    EntityType.SUBDOMAIN if name.endswith(entity.normalized_value) else EntityType.DOMAIN,
                    name,
                    source="crt.sh",
                    confidence=Confidence.CONFIRMED,
                    tags=["certificate-transparency"],
                )
            except Exception:
                continue
            sub_entities.append(sub)
            relationships.append(
                Relationship(
                    from_entity_id=entity.id,
                    to_entity_id=sub.id,
                    relation=RelationType.HAS_SUBDOMAIN
                    if name.endswith("." + entity.normalized_value) or name.endswith(entity.normalized_value)
                    else RelationType.HAS_CERTIFICATE,
                    source="crt.sh",
                    confidence=Confidence.CONFIRMED,
                    evidence_id=evidence.id,
                )
            )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            entities=sub_entities,
            relationships=relationships,
            evidence=[evidence],
            payload={"certificates": len(parsed["certificates"]), "names": len(parsed["subdomains"])},
        )


def _empty(entity: Entity) -> ProviderResult:
    from spectre_osint.core.entities import Finding

    return ProviderResult(
        provider="crtsh",
        status=FindingStatus.NOT_FOUND,
        findings=[
            Finding(
                module="crtsh",
                title="Certificate Transparency",
                status=FindingStatus.NOT_FOUND,
                summary="NOT FOUND",
                entity_id=entity.id,
            )
        ],
    )


def _parse_certificates(rows: list[dict[str, Any]], apex: str) -> dict[str, Any]:
    certs: list[dict[str, Any]] = []
    names: set[str] = set()
    seen_ids: set[Any] = set()
    for row in rows:
        cert_id = row.get("id") or row.get("min_cert_id")
        if cert_id in seen_ids:
            continue
        seen_ids.add(cert_id)
        name_value = row.get("name_value") or ""
        sans = []
        for part in str(name_value).split("\n"):
            host = part.strip().lower().lstrip("*.")
            if host and is_domain(host):
                try:
                    host = normalize_domain(host)
                except Exception:
                    continue
                sans.append(host)
                names.add(host)
        certs.append(
            {
                "id": cert_id,
                "issuer": row.get("issuer_name"),
                "common_name": (row.get("common_name") or "").lower(),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
                "serial": row.get("serial_number"),
                "sans": sorted(set(sans)),
            }
        )
    certs.sort(key=lambda c: c.get("not_before") or "", reverse=True)
    timeline = []
    for cert in certs[:50]:
        if cert.get("not_before"):
            timeline.append(
                {
                    "date": cert["not_before"],
                    "label": f"Certificate issued CN={cert.get('common_name')}",
                    "source": "crt.sh",
                }
            )
    return {
        "certificates": certs[:250],
        "subdomains": sorted(names),
        "timeline": timeline,
        "query": apex,
    }
