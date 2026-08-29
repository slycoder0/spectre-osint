"""Internet Archive CDX API (public)."""

from __future__ import annotations

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, ProviderKeyType
from spectre_osint.providers.base import Provider, ProviderResult


class WaybackProvider(Provider):
    name = "wayback"
    supported_entities = frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.URL})
    requires_api_key = False
    key_type = ProviderKeyType.KEYLESS
    health_url = "https://archive.org/wayback/available?url=example.com"
    rate_limit = "0.8s"

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        host = entity.normalized_value
        if entity.type == EntityType.URL:
            from urllib.parse import urlparse

            host = urlparse(entity.normalized_value).hostname or entity.normalized_value
        url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"{host}/*",
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype",
            "collapse": "urlkey",
            "limit": "100",
            "filter": "statuscode:200",
        }
        response = await self.http.get(
            url,
            provider=self.name,
            params=params,
            follow_redirects=True,
            cache_ttl=settings.cache_default_ttl,
        )
        if response.status_code >= 400:
            raise ProviderUnavailable(f"Wayback HTTP {response.status_code}")
        rows = response.json_data
        if not isinstance(rows, list) or len(rows) <= 1:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.NOT_FOUND,
                findings=[
                    Finding(
                        module=self.name,
                        title="Wayback Machine",
                        status=FindingStatus.NOT_FOUND,
                        summary="NOT FOUND",
                        entity_id=entity.id,
                    )
                ],
            )
        header, *body = rows
        snapshots = [dict(zip(header, row, strict=False)) for row in body if isinstance(row, list)]
        timestamps = [str(s.get("timestamp")) for s in snapshots if s.get("timestamp")]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        evidence = make_evidence(
            source="Wayback Machine CDX",
            provider=self.name,
            confidence=Confidence.CONFIRMED,
            url=f"https://web.archive.org/web/*/{host}",
            raw={"count": len(snapshots), "first": first_seen, "last": last_seen},
            entity_id=entity.id,
        )
        finding = Finding(
            module=self.name,
            title="Wayback Machine",
            status=FindingStatus.FOUND,
            summary=f"CONFIRMED {len(snapshots)} public snapshots first={first_seen} last={last_seen}",
            data={
                "count": len(snapshots),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "snapshots": snapshots[:100],
            },
            confidence=Confidence.CONFIRMED,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            evidence=[evidence],
            payload={"count": len(snapshots), "first_seen": first_seen, "last_seen": last_seen},
        )
