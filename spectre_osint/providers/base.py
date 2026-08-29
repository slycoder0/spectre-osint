"""Provider plugin contract.

A provider never invents data. Missing keys yield NOT_CONFIGURED.
Transport failures yield PROVIDER_UNAVAILABLE. The investigation continues.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Evidence, Finding, Relationship
from spectre_osint.core.exceptions import (
    ProviderNotConfigured,
    ProviderUnavailable,
    RateLimitExceeded,
)
from spectre_osint.core.logger import get_logger
from spectre_osint.core.types import EntityType, FindingStatus, ProviderKeyType

logger = get_logger("spectre.providers")


@dataclass
class ProviderHealth:
    name: str
    configured: bool
    available: bool | None
    status: str
    rate_limit: str
    requires_key: bool
    notes: str = ""
    key_type: str = ProviderKeyType.KEYLESS.value
    probed: bool = False
    last_check: str | None = None
    configured_label: str = "N/A"


@dataclass
class ProviderResult:
    provider: str
    status: FindingStatus
    findings: list[Finding] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class Provider(ABC):
    name: str = "base"
    supported_entities: frozenset[EntityType] = frozenset()
    requires_api_key: bool = False
    key_type: ProviderKeyType = ProviderKeyType.KEYLESS
    optional_secret: str | None = None
    health_url: str | None = None
    is_passive: bool = True
    rate_limit: str = "moderate"

    def __init__(self, http_client: Any = None) -> None:
        self.http = http_client

    def is_configured(self, settings: Settings) -> bool:
        if self.key_type == ProviderKeyType.REQUIRED_API_KEY or self.requires_api_key:
            if self.optional_secret:
                return settings.secret_present(self.optional_secret)
            return False
        return True

    def health_headers(self, settings: Settings) -> dict[str, str]:
        return {}

    def health_params(self, settings: Settings) -> dict[str, str]:
        return {}

    def configured_display(self, settings: Settings) -> str:
        if self.key_type == ProviderKeyType.KEYLESS:
            return "N/A"
        if self.optional_secret:
            return "YES" if settings.secret_present(self.optional_secret) else "NO"
        return "YES" if self.is_configured(settings) else "NO"

    async def check_health(self, settings: Settings, *, probe: bool = False) -> ProviderHealth:
        """Configuration status. Optional cheap probe via health_url.

        KEYLESS / missing optional key is not an error. REQUIRED without a key
        is NOT CONFIGURED and is never probed.
        """
        from spectre_osint.core.health_store import HealthStore

        store = HealthStore(settings)
        previous = store.last(self.name)
        configured = self.is_configured(settings)
        key_type = (
            self.key_type.value
            if isinstance(self.key_type, ProviderKeyType)
            else str(self.key_type)
        )
        if self.key_type == ProviderKeyType.REQUIRED_API_KEY and not configured:
            return ProviderHealth(
                name=self.name,
                configured=False,
                available=False,
                status="NOT CONFIGURED",
                rate_limit=self.rate_limit,
                requires_key=True,
                notes="API key required; not a global error.",
                key_type=key_type,
                probed=False,
                last_check=previous.get("checked_at") if previous else None,
                configured_label=self.configured_display(settings),
            )
        if not probe:
            return ProviderHealth(
                name=self.name,
                configured=configured,
                available=None,
                status="NOT PROBED",
                rate_limit=self.rate_limit,
                requires_key=self.requires_api_key
                or self.key_type == ProviderKeyType.REQUIRED_API_KEY,
                notes="No live probe. KEYLESS does not mean the remote service is up.",
                key_type=key_type,
                probed=False,
                last_check=previous.get("checked_at") if previous else None,
                configured_label=self.configured_display(settings),
            )
        return await self._probe(settings, store, configured, key_type, previous)

    async def _probe(
        self,
        settings: Settings,
        store: Any,
        configured: bool,
        key_type: str,
        previous: dict | None,
    ) -> ProviderHealth:
        from spectre_osint.core.exceptions import (
            ProviderUnavailable,
            RateLimitExceeded,
            SSRFBlocked,
        )

        url = self.health_url
        if not url or self.http is None:
            return ProviderHealth(
                name=self.name,
                configured=configured,
                available=None,
                status="NOT PROBED",
                rate_limit=self.rate_limit,
                requires_key=self.requires_api_key,
                notes="No health_url configured.",
                key_type=key_type,
                probed=False,
                last_check=previous.get("checked_at") if previous else None,
                configured_label=self.configured_display(settings),
            )
        try:
            headers = self.health_headers(settings) or None
            params = self.health_params(settings) or None
            response = await self.http.get(
                url,
                provider=self.name,
                headers=headers,
                params=params,
                follow_redirects=True,
                use_cache=False,
                accept_statuses=set(range(200, 600)),
            )
            code = response.status_code
            if code == 429:
                status, available, notes = "RATE LIMITED", False, "HTTP 429"
            elif code in {401, 403}:
                status, available, notes = "AUTH REJECTED", False, f"HTTP {code}"
            elif code >= 500:
                status, available, notes = "UNAVAILABLE", False, f"HTTP {code}"
            elif 200 <= code < 500:
                status, available, notes = "ONLINE", True, f"HTTP {code}"
            else:
                status, available, notes = "UNAVAILABLE", False, f"HTTP {code}"
        except RateLimitExceeded:
            status, available, notes, code = "RATE LIMITED", False, "429", 429
        except (ProviderUnavailable, SSRFBlocked, Exception) as exc:  # noqa: BLE001
            status, available, notes, code = "UNAVAILABLE", False, str(exc), None
        store.record(
            self.name,
            {"status": status, "http_status": code, "available": available},
        )
        last = store.last(self.name)
        return ProviderHealth(
            name=self.name,
            configured=configured,
            available=available,
            status=status,
            rate_limit=self.rate_limit,
            requires_key=self.requires_api_key,
            notes=notes,
            key_type=key_type,
            probed=True,
            last_check=last.get("checked_at") if last else None,
            configured_label=self.configured_display(settings),
        )

    @abstractmethod
    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        raise NotImplementedError

    def _not_configured(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.NOT_CONFIGURED,
            findings=[
                Finding(
                    module=self.name,
                    title=f"{self.name} not configured",
                    status=FindingStatus.NOT_CONFIGURED,
                    summary="Provider not configured",
                )
            ],
            error="Provider not configured",
        )

    def _unavailable(self, reason: str) -> ProviderResult:
        logger.warning("[!] %s unavailable Reason: %s Continuing investigation...", self.name, reason)
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.PROVIDER_UNAVAILABLE,
            findings=[
                Finding(
                    module=self.name,
                    title=f"{self.name} unavailable",
                    status=FindingStatus.PROVIDER_UNAVAILABLE,
                    summary=f"PROVIDER UNAVAILABLE: {reason}",
                    data={"reason": reason},
                )
            ],
            error=reason,
        )

    async def safe_search(self, entity: Entity, settings: Settings) -> ProviderResult:
        if entity.type not in self.supported_entities:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.SKIPPED,
                error=f"{self.name} does not support {entity.type}",
            )
        try:
            if self.requires_api_key and not self.is_configured(settings):
                return self._not_configured()
            return await self.search(entity, settings)
        except ProviderNotConfigured:
            return self._not_configured()
        except (ProviderUnavailable, RateLimitExceeded) as exc:
            return self._unavailable(str(exc))
        except Exception as exc:  # noqa: BLE001 — providers must never kill the pipeline
            return self._unavailable(str(exc))
