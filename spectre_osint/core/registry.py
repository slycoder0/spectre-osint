"""Provider plugin registry. New sources register without changing the core."""

from __future__ import annotations

from collections.abc import Iterable

from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.types import EntityType
from spectre_osint.providers.base import Provider, ProviderHealth


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, Provider] = {}

    def register(self, provider: Provider) -> None:
        self._providers[provider.name] = provider

    def get(self, name: str) -> Provider | None:
        return self._providers.get(name)

    def all(self) -> list[Provider]:
        return list(self._providers.values())

    def for_entity(self, entity_type: EntityType) -> list[Provider]:
        return [p for p in self._providers.values() if entity_type in p.supported_entities]

    async def health(
        self,
        settings: Settings | None = None,
        *,
        probe: bool = False,
        names: list[str] | None = None,
    ) -> list[ProviderHealth]:
        cfg = settings or get_settings()
        results: list[ProviderHealth] = []
        wanted = {n.lower() for n in names} if names else None
        for provider in self._providers.values():
            if wanted and provider.name.lower() not in wanted:
                continue
            results.append(await provider.check_health(cfg, probe=probe))
        return results


def default_registry(http_client: object | None = None) -> ProviderRegistry:
    """Import providers lazily to avoid circular imports at module load."""
    from spectre_osint.providers.abuseipdb import AbuseIPDBProvider
    from spectre_osint.providers.alienvault import AlienVaultProvider
    from spectre_osint.providers.censys import CensysProvider
    from spectre_osint.providers.crtsh import CrtShProvider
    from spectre_osint.providers.github import GitHubProvider
    from spectre_osint.providers.greynoise import GreyNoiseProvider
    from spectre_osint.providers.hibp import HIBPProvider
    from spectre_osint.providers.ipinfo import IPinfoProvider
    from spectre_osint.providers.rdap import RdapProvider
    from spectre_osint.providers.shodan import ShodanProvider
    from spectre_osint.providers.urlscan import UrlscanProvider
    from spectre_osint.providers.virustotal import VirusTotalProvider
    from spectre_osint.providers.wayback import WaybackProvider

    registry = ProviderRegistry()
    providers: Iterable[Provider] = [
        CrtShProvider(http_client),
        RdapProvider(http_client),
        VirusTotalProvider(http_client),
        AlienVaultProvider(http_client),
        UrlscanProvider(http_client),
        AbuseIPDBProvider(http_client),
        ShodanProvider(http_client),
        CensysProvider(http_client),
        HIBPProvider(http_client),
        GitHubProvider(http_client),
        IPinfoProvider(http_client),
        GreyNoiseProvider(http_client),
        WaybackProvider(http_client),
    ]
    for provider in providers:
        registry.register(provider)
    return registry
