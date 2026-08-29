"""Censys Search API v2. Requires API ID + secret."""

from __future__ import annotations

import base64

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, ProviderKeyType
from spectre_osint.providers.base import Provider, ProviderResult


class CensysProvider(Provider):
    name = "censys"
    supported_entities = frozenset({EntityType.IP, EntityType.DOMAIN, EntityType.SUBDOMAIN})
    requires_api_key = True
    key_type = ProviderKeyType.REQUIRED_API_KEY
    optional_secret = "censys_api_id"
    health_url = "https://search.censys.io/api/v2/hosts/1.1.1.1"
    rate_limit = "1.0s"

    def is_configured(self, settings: Settings) -> bool:
        return settings.secret_present("censys_api_id") and settings.secret_present("censys_api_secret")

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        user = settings.censys_api_id.get_secret_value() if settings.censys_api_id else ""
        secret = settings.censys_api_secret.get_secret_value() if settings.censys_api_secret else ""
        token = base64.b64encode(f"{user}:{secret}".encode()).decode()
        if entity.type == EntityType.IP:
            url = f"https://search.censys.io/api/v2/hosts/{entity.normalized_value}"
        else:
            url = "https://search.censys.io/api/v2/hosts/search"
        params = None if entity.type == EntityType.IP else {"q": entity.normalized_value, "per_page": 5}
        response = await self.http.get(
            url,
            provider=self.name,
            headers={"Authorization": f"Basic {token}", "Accept": "application/json"},
            params=params,
            follow_redirects=True,
            cache_ttl=settings.cache_vt_ttl,
            accept_statuses={200, 404, 401, 403},
        )
        if response.status_code in {401, 403}:
            raise ProviderUnavailable("Censys rejected credentials")
        if response.status_code == 404:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.NOT_FOUND,
                findings=[
                    Finding(
                        module=self.name,
                        title="Censys",
                        status=FindingStatus.NOT_FOUND,
                        summary="NOT FOUND",
                        entity_id=entity.id,
                    )
                ],
            )
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"Censys HTTP {response.status_code}")
        evidence = make_evidence(
            source="Censys (external intelligence, not a local scan)",
            provider=self.name,
            confidence=Confidence.HIGH,
            url="https://search.censys.io/",
            raw={"keys": list((response.json_data.get("result") or {}).keys())[:20]},
            entity_id=entity.id,
            notes="Observed services from external intelligence — not a local active scan",
        )
        finding = Finding(
            module=self.name,
            title="Censys",
            status=FindingStatus.FOUND,
            summary="Censys record retrieved (external intelligence)",
            data={
                "origin": "external_intelligence",
                "not_a_local_scan": True,
                "result_keys": list((response.json_data.get("result") or {}).keys())[:30],
            },
            confidence=Confidence.HIGH,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            evidence=[evidence],
        )
