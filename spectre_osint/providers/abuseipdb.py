"""AbuseIPDB check API. Requires API key."""

from __future__ import annotations

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, ProviderKeyType
from spectre_osint.providers.base import Provider, ProviderResult


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    supported_entities = frozenset({EntityType.IP})
    requires_api_key = True
    key_type = ProviderKeyType.REQUIRED_API_KEY
    optional_secret = "abuseipdb_api_key"
    health_url = "https://api.abuseipdb.com/api/v2/check"
    rate_limit = "1.0s"

    def is_configured(self, settings: Settings) -> bool:
        return settings.secret_present("abuseipdb_api_key")

    def health_headers(self, settings: Settings) -> dict[str, str]:
        key = settings.abuseipdb_api_key.get_secret_value() if settings.abuseipdb_api_key else ""
        return {"Key": key, "Accept": "application/json"} if key else {}

    def health_params(self, settings: Settings) -> dict[str, str]:
        return {"ipAddress": "8.8.8.8", "maxAgeInDays": "90"}

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        key = settings.abuseipdb_api_key.get_secret_value() if settings.abuseipdb_api_key else ""
        response = await self.http.get(
            "https://api.abuseipdb.com/api/v2/check",
            provider=self.name,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": entity.normalized_value, "maxAgeInDays": 90, "verbose": True},
            follow_redirects=True,
            cache_ttl=settings.cache_vt_ttl,
        )
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"AbuseIPDB HTTP {response.status_code}")
        data = response.json_data.get("data") or {}
        score = data.get("abuseConfidenceScore")
        evidence = make_evidence(
            source="AbuseIPDB",
            provider=self.name,
            confidence=Confidence.HIGH,
            url="https://www.abuseipdb.com/",
            raw={
                "abuseConfidenceScore": score,
                "totalReports": data.get("totalReports"),
                "usageType": data.get("usageType"),
                "isp": data.get("isp"),
            },
            entity_id=entity.id,
        )
        finding = Finding(
            module=self.name,
            title="AbuseIPDB",
            status=FindingStatus.FOUND,
            summary=f"abuse score={score} reports={data.get('totalReports')}",
            data={
                "abuse_score": score,
                "total_reports": data.get("totalReports"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "is_tor": data.get("isTor"),
                "country": data.get("countryCode"),
                "last_reported": data.get("lastReportedAt"),
            },
            confidence=Confidence.HIGH,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            evidence=[evidence],
            payload={"abuse_score": score},
        )
