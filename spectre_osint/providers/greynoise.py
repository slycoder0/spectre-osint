"""GreyNoise Community API."""

from __future__ import annotations

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, ProviderKeyType
from spectre_osint.providers.base import Provider, ProviderResult


class GreyNoiseProvider(Provider):
    name = "greynoise"
    supported_entities = frozenset({EntityType.IP})
    requires_api_key = False
    key_type = ProviderKeyType.OPTIONAL_API_KEY
    optional_secret = "greynoise_api_key"
    health_url = "https://api.greynoise.io/v3/community/8.8.8.8"
    rate_limit = "1.0s"

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        headers = {"Accept": "application/json"}
        if settings.secret_present("greynoise_api_key") and settings.greynoise_api_key:
            headers["key"] = settings.greynoise_api_key.get_secret_value()
        response = await self.http.get(
            f"https://api.greynoise.io/v3/community/{entity.normalized_value}",
            provider=self.name,
            headers=headers,
            follow_redirects=True,
            cache_ttl=settings.cache_vt_ttl,
            accept_statuses={200, 404, 429},
        )
        if response.status_code == 404:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.NOT_FOUND,
                findings=[
                    Finding(
                        module=self.name,
                        title="GreyNoise",
                        status=FindingStatus.NOT_FOUND,
                        summary="NOT FOUND",
                        entity_id=entity.id,
                    )
                ],
            )
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"GreyNoise HTTP {response.status_code}")
        data = response.json_data
        evidence = make_evidence(
            source="GreyNoise Community",
            provider=self.name,
            confidence=Confidence.HIGH,
            url=f"https://viz.greynoise.io/ip/{entity.normalized_value}",
            raw={
                "classification": data.get("classification"),
                "noise": data.get("noise"),
                "riot": data.get("riot"),
                "name": data.get("name"),
            },
            entity_id=entity.id,
        )
        finding = Finding(
            module=self.name,
            title="GreyNoise",
            status=FindingStatus.FOUND,
            summary=f"classification={data.get('classification')} noise={data.get('noise')} riot={data.get('riot')}",
            data={
                "classification": data.get("classification"),
                "noise": data.get("noise"),
                "riot": data.get("riot"),
                "name": data.get("name"),
                "last_seen": data.get("last_seen"),
                "link": data.get("link"),
            },
            confidence=Confidence.HIGH,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            evidence=[evidence],
            payload=finding.data,
        )
