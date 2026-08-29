"""Certificate Transparency module wrapping the crt.sh provider."""

from __future__ import annotations

from typing import Any

from spectre_osint.core.entities import Entity
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.registry import ProviderRegistry


async def collect_certificates(
    entity: Entity,
    http: HttpClient,
    registry: ProviderRegistry,
    settings: Any,
) -> dict[str, Any]:
    provider = registry.get("crtsh")
    if provider is None:
        return {"findings": [], "entities": [entity], "relationships": [], "evidence": [], "providers_queried": []}
    result = await provider.safe_search(entity, settings)
    return {
        "findings": result.findings,
        "entities": [entity, *result.entities],
        "relationships": result.relationships,
        "evidence": result.evidence,
        "providers_queried": ["crtsh"],
    }
