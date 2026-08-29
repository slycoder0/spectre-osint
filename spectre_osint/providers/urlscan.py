"""urlscan.io search API."""

from __future__ import annotations

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, ProviderKeyType
from spectre_osint.providers.base import Provider, ProviderResult


class UrlscanProvider(Provider):
    name = "urlscan"
    supported_entities = frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.URL, EntityType.IP})
    requires_api_key = False
    key_type = ProviderKeyType.OPTIONAL_API_KEY
    optional_secret = "urlscan_api_key"
    health_url = "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1"
    rate_limit = "1.0s"

    def is_configured(self, settings: Settings) -> bool:
        return True

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        if entity.type == EntityType.IP:
            query = f"ip:{entity.normalized_value}"
        elif entity.type == EntityType.URL:
            query = f'page.url:"{entity.normalized_value}"'
        else:
            query = f"domain:{entity.normalized_value}"
        headers = {"Accept": "application/json"}
        if settings.secret_present("urlscan_api_key") and settings.urlscan_api_key:
            headers["API-Key"] = settings.urlscan_api_key.get_secret_value()
        response = await self.http.get(
            "https://urlscan.io/api/v1/search/",
            provider=self.name,
            headers=headers,
            params={"q": query, "size": 20},
            follow_redirects=True,
            cache_ttl=settings.cache_default_ttl,
            accept_statuses={200, 400, 429},
        )
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"URLScan HTTP {response.status_code}")
        results = response.json_data.get("results") or []
        if not results:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.NOT_FOUND,
                findings=[
                    Finding(
                        module=self.name,
                        title="URLScan",
                        status=FindingStatus.NOT_FOUND,
                        summary="NOT FOUND",
                        entity_id=entity.id,
                    )
                ],
            )
        evidence = make_evidence(
            source="urlscan.io",
            provider=self.name,
            confidence=Confidence.HIGH,
            url="https://urlscan.io/api/v1/search/",
            raw={"total": response.json_data.get("total"), "n": len(results)},
            entity_id=entity.id,
        )
        observations = []
        for item in results[:20]:
            page = item.get("page") or {}
            observations.append(
                {
                    "url": page.get("url"),
                    "ip": page.get("ip"),
                    "country": page.get("country"),
                    "server": page.get("server"),
                    "asn": page.get("asn"),
                    "time": item.get("task", {}).get("time"),
                }
            )
        finding = Finding(
            module=self.name,
            title="URLScan",
            status=FindingStatus.FOUND,
            summary=f"{len(results)} observations",
            data={"observations": observations, "total": response.json_data.get("total")},
            confidence=Confidence.HIGH,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            evidence=[evidence],
            payload={"observations": len(results)},
        )
