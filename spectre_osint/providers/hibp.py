"""Have I Been Pwned v3. Requires API key. Never attempts password discovery."""

from __future__ import annotations

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, ProviderKeyType
from spectre_osint.providers.base import Provider, ProviderResult


class HIBPProvider(Provider):
    name = "hibp"
    supported_entities = frozenset({EntityType.EMAIL})
    requires_api_key = True
    key_type = ProviderKeyType.REQUIRED_API_KEY
    optional_secret = "hibp_api_key"
    health_url = "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com"
    rate_limit = "1.6s"

    def is_configured(self, settings: Settings) -> bool:
        return settings.secret_present("hibp_api_key")

    def health_headers(self, settings: Settings) -> dict[str, str]:
        key = settings.hibp_api_key.get_secret_value() if settings.hibp_api_key else ""
        return {"hibp-api-key": key, "user-agent": "SPECTRE-OSINT"} if key else {}

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        key = settings.hibp_api_key.get_secret_value() if settings.hibp_api_key else ""
        response = await self.http.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{entity.normalized_value}",
            provider=self.name,
            headers={
                "hibp-api-key": key,
                "user-agent": "SPECTRE-OSINT",
                "Accept": "application/json",
            },
            params={"truncateResponse": "false"},
            follow_redirects=True,
            cache_ttl=settings.cache_vt_ttl,
            accept_statuses={200, 404, 401},
        )
        if response.status_code == 401:
            raise ProviderUnavailable("HIBP rejected the API key")
        if response.status_code == 404:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.NOT_FOUND,
                findings=[
                    Finding(
                        module=self.name,
                        title="Have I Been Pwned",
                        status=FindingStatus.NOT_FOUND,
                        summary="NOT FOUND",
                        entity_id=entity.id,
                    )
                ],
            )
        if response.status_code >= 400:
            raise ProviderUnavailable(f"HIBP HTTP {response.status_code}")
        if not isinstance(response.json_data, list):
            raise ProviderUnavailable("HIBP returned non-JSON or unexpected payload")
        breaches = response.json_data
        names = [b.get("Name") for b in breaches if isinstance(b, dict)]
        evidence = make_evidence(
            source="Have I Been Pwned",
            provider=self.name,
            confidence=Confidence.CONFIRMED,
            url="https://haveibeenpwned.com/",
            raw={"breaches": names},
            entity_id=entity.id,
        )
        finding = Finding(
            module=self.name,
            title="Have I Been Pwned",
            status=FindingStatus.FOUND,
            summary=f"CONFIRMED {len(breaches)} authorized breach records",
            data={
                "breaches": [
                    {
                        "name": b.get("Name"),
                        "domain": b.get("Domain"),
                        "breach_date": b.get("BreachDate"),
                        "data_classes": b.get("DataClasses"),
                    }
                    for b in breaches
                    if isinstance(b, dict)
                ]
            },
            confidence=Confidence.CONFIRMED,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            evidence=[evidence],
            payload={"count": len(breaches)},
        )
