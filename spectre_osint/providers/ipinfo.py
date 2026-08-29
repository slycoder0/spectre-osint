"""IPinfo.io. Token optional for low volume; token recommended."""

from __future__ import annotations

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, ProviderKeyType
from spectre_osint.providers.base import Provider, ProviderResult


class IPinfoProvider(Provider):
    name = "ipinfo"
    supported_entities = frozenset({EntityType.IP})
    requires_api_key = False
    key_type = ProviderKeyType.OPTIONAL_API_KEY
    optional_secret = "ipinfo_token"
    health_url = "https://ipinfo.io/8.8.8.8/json"
    rate_limit = "1.0s"

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        params = {}
        if settings.secret_present("ipinfo_token") and settings.ipinfo_token:
            params["token"] = settings.ipinfo_token.get_secret_value()
        response = await self.http.get(
            f"https://ipinfo.io/{entity.normalized_value}/json",
            provider=self.name,
            params=params,
            follow_redirects=True,
            cache_ttl=settings.cache_rdap_ttl,
            accept_statuses={200, 403, 404, 429},
        )
        if response.status_code in {401, 403, 429}:
            if not settings.secret_present("ipinfo_token"):
                return self._not_configured()
            raise ProviderUnavailable(f"IPinfo HTTP {response.status_code}")
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"IPinfo HTTP {response.status_code}")
        data = response.json_data
        evidence = make_evidence(
            source="IPinfo",
            provider=self.name,
            confidence=Confidence.HIGH,
            url=f"https://ipinfo.io/{entity.normalized_value}",
            raw={
                "org": data.get("org"),
                "country": data.get("country"),
                "city": data.get("city"),
                "hostname": data.get("hostname"),
            },
            entity_id=entity.id,
        )
        finding = Finding(
            module=self.name,
            title="IPinfo",
            status=FindingStatus.FOUND,
            summary=f"{data.get('org')} {data.get('country')} {data.get('city')}",
            data={
                "hostname": data.get("hostname"),
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "org": data.get("org"),
                "postal": data.get("postal"),
                "timezone": data.get("timezone"),
                "loc": data.get("loc"),
                "anycast": data.get("anycast"),
                "privacy": data.get("privacy"),
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
