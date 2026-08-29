"""AlienVault OTX indicator API. Key optional but recommended."""

from __future__ import annotations

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, ProviderKeyType
from spectre_osint.providers.base import Provider, ProviderResult


class AlienVaultProvider(Provider):
    name = "alienvault"
    supported_entities = frozenset(
        {EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP, EntityType.URL, EntityType.HASH}
    )
    requires_api_key = False
    key_type = ProviderKeyType.OPTIONAL_API_KEY
    optional_secret = "otx_api_key"
    health_url = "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general"
    rate_limit = "1.0s"

    def is_configured(self, settings: Settings) -> bool:
        return True

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        kind = {
            EntityType.DOMAIN: "domain",
            EntityType.SUBDOMAIN: "hostname",
            EntityType.IP: "IPv4" if "." in entity.normalized_value else "IPv6",
            EntityType.URL: "url",
            EntityType.HASH: "file",
        }[entity.type]
        url = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{entity.normalized_value}/general"
        headers = {"Accept": "application/json"}
        if settings.secret_present("otx_api_key") and settings.otx_api_key:
            headers["X-OTX-API-KEY"] = settings.otx_api_key.get_secret_value()
        response = await self.http.get(
            url,
            provider=self.name,
            headers=headers,
            follow_redirects=True,
            cache_ttl=settings.cache_vt_ttl,
            accept_statuses={200, 404, 400},
        )
        if response.status_code in {400, 404}:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.NOT_FOUND,
                findings=[
                    Finding(
                        module=self.name,
                        title="AlienVault OTX",
                        status=FindingStatus.NOT_FOUND,
                        summary="NOT FOUND",
                        entity_id=entity.id,
                    )
                ],
            )
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"AlienVault HTTP {response.status_code}")
        pulses = (response.json_data.get("pulse_info") or {}).get("count") or 0
        evidence = make_evidence(
            source="AlienVault OTX",
            provider=self.name,
            confidence=Confidence.HIGH if pulses else Confidence.MEDIUM,
            url=url,
            raw={"pulse_count": pulses, "validation": response.json_data.get("validation")},
            entity_id=entity.id,
        )
        finding = Finding(
            module=self.name,
            title="AlienVault OTX",
            status=FindingStatus.FOUND,
            summary=f"{pulses} pulses",
            data={
                "pulses": pulses,
                "reputation": response.json_data.get("reputation"),
                "type": response.json_data.get("type_title"),
            },
            confidence=Confidence.HIGH if pulses else Confidence.MEDIUM,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            evidence=[evidence],
            payload={"pulses": pulses},
        )
