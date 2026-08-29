"""Shodan host API. Historical/observed services, never presented as a live scan."""

from __future__ import annotations

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, ProviderKeyType
from spectre_osint.providers.base import Provider, ProviderResult


class ShodanProvider(Provider):
    name = "shodan"
    supported_entities = frozenset({EntityType.IP})
    requires_api_key = True
    key_type = ProviderKeyType.REQUIRED_API_KEY
    optional_secret = "shodan_api_key"
    health_url = "https://api.shodan.io/api-info"
    rate_limit = "1.0s"

    def is_configured(self, settings: Settings) -> bool:
        return settings.secret_present("shodan_api_key")

    def health_params(self, settings: Settings) -> dict[str, str]:
        key = settings.shodan_api_key.get_secret_value() if settings.shodan_api_key else ""
        return {"key": key} if key else {}

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        key = settings.shodan_api_key.get_secret_value() if settings.shodan_api_key else ""
        response = await self.http.get(
            f"https://api.shodan.io/shodan/host/{entity.normalized_value}",
            provider=self.name,
            params={"key": key},
            follow_redirects=True,
            cache_ttl=settings.cache_vt_ttl,
            accept_statuses={200, 404},
        )
        if response.status_code == 404:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.NOT_FOUND,
                findings=[
                    Finding(
                        module=self.name,
                        title="Shodan",
                        status=FindingStatus.NOT_FOUND,
                        summary="NOT FOUND",
                        entity_id=entity.id,
                    )
                ],
            )
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"Shodan HTTP {response.status_code}")
        data = response.json_data
        ports = data.get("ports") or []
        evidence = make_evidence(
            source="Shodan (external intelligence, not a local scan)",
            provider=self.name,
            confidence=Confidence.HIGH,
            url=f"https://www.shodan.io/host/{entity.normalized_value}",
            raw={"ports": ports, "org": data.get("org"), "last_update": data.get("last_update")},
            entity_id=entity.id,
            notes="Observed services from external intelligence — not a local active scan",
        )
        finding = Finding(
            module=self.name,
            title="Shodan observed services",
            status=FindingStatus.FOUND,
            summary=f"Observed (external intel) ports={ports} org={data.get('org')}",
            data={
                "origin": "external_intelligence",
                "not_a_local_scan": True,
                "ports": ports,
                "org": data.get("org"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "hostnames": data.get("hostnames"),
                "last_update": data.get("last_update"),
                "tags": data.get("tags"),
                "os": data.get("os"),
            },
            confidence=Confidence.HIGH,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            evidence=[evidence],
            payload={"ports": ports, "origin": "external_intelligence"},
        )
