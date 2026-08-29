"""VirusTotal v3 client. Requires API key. Never fabricates detections."""

from __future__ import annotations

import base64

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, ProviderKeyType
from spectre_osint.providers.base import Provider, ProviderResult


class VirusTotalProvider(Provider):
    name = "virustotal"
    supported_entities = frozenset(
        {EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP, EntityType.URL, EntityType.HASH}
    )
    requires_api_key = True
    key_type = ProviderKeyType.REQUIRED_API_KEY
    optional_secret = "virustotal_api_key"
    health_url = "https://www.virustotal.com/api/v3/domains/example.com"
    rate_limit = "1.0s / VT quota"

    def is_configured(self, settings: Settings) -> bool:
        return settings.secret_present("virustotal_api_key")

    def health_headers(self, settings: Settings) -> dict[str, str]:
        key = settings.virustotal_api_key.get_secret_value() if settings.virustotal_api_key else ""
        return {"x-apikey": key, "Accept": "application/json"} if key else {}

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        key = settings.virustotal_api_key.get_secret_value() if settings.virustotal_api_key else ""
        path = _vt_path(entity)
        url = f"https://www.virustotal.com/api/v3/{path}"
        response = await self.http.get(
            url,
            provider=self.name,
            headers={"x-apikey": key, "Accept": "application/json"},
            follow_redirects=True,
            cache_ttl=settings.cache_vt_ttl,
            accept_statuses={200, 404, 401, 403, 429},
        )
        if response.status_code in {401, 403}:
            raise ProviderUnavailable("VirusTotal rejected the API key")
        if response.status_code == 404:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.NOT_FOUND,
                findings=[
                    Finding(
                        module=self.name,
                        title="VirusTotal",
                        status=FindingStatus.NOT_FOUND,
                        summary="NOT FOUND",
                        entity_id=entity.id,
                    )
                ],
            )
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"VirusTotal HTTP {response.status_code}")
        stats = (
            (response.json_data.get("data") or {}).get("attributes") or {}
        ).get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        detections = malicious + suspicious
        confidence = Confidence.CONFIRMED if detections else Confidence.HIGH
        evidence = make_evidence(
            source="VirusTotal",
            provider=self.name,
            confidence=confidence,
            url=url,
            raw={"stats": stats},
            entity_id=entity.id,
        )
        finding = Finding(
            module=self.name,
            title="VirusTotal",
            status=FindingStatus.FOUND,
            summary=f"{detections} detections (malicious={malicious} suspicious={suspicious})",
            data={
                "detections": detections,
                "malicious": malicious,
                "suspicious": suspicious,
                "stats": stats,
                "reputation": ((response.json_data.get("data") or {}).get("attributes") or {}).get(
                    "reputation"
                ),
            },
            confidence=confidence,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            evidence=[evidence],
            payload={"detections": detections, "stats": stats},
        )


def _vt_path(entity: Entity) -> str:
    if entity.type in {EntityType.DOMAIN, EntityType.SUBDOMAIN}:
        return f"domains/{entity.normalized_value}"
    if entity.type == EntityType.IP:
        return f"ip_addresses/{entity.normalized_value}"
    if entity.type == EntityType.HASH:
        return f"files/{entity.normalized_value}"
    encoded = base64.urlsafe_b64encode(entity.normalized_value.encode()).decode().rstrip("=")
    return f"urls/{encoded}"
