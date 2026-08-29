from __future__ import annotations

import pytest

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.providers.virustotal import VirusTotalProvider


@pytest.mark.asyncio
async def test_virustotal_not_configured() -> None:
    settings = Settings(virustotal_api_key=None)
    provider = VirusTotalProvider(http_client=None)
    entity = Entity.create(EntityType.DOMAIN, "example.com", "t", Confidence.CONFIRMED)
    result = await provider.safe_search(entity, settings)
    assert result.status == FindingStatus.NOT_CONFIGURED
    assert result.findings[0].summary == "Provider not configured"


def test_default_registry_lists_core_providers() -> None:
    from spectre_osint.core.registry import default_registry

    registry = default_registry(http_client=None)
    names = {p.name for p in registry.all()}
    assert {"crtsh", "rdap", "virustotal", "wayback", "github"} <= names


@pytest.mark.asyncio
async def test_health_does_not_claim_available_without_probe() -> None:
    from spectre_osint.core.config import Settings
    from spectre_osint.core.registry import default_registry

    registry = default_registry(http_client=None)
    rows = await registry.health(Settings())
    crtsh = next(r for r in rows if r.name == "crtsh")
    assert crtsh.configured is True
    assert crtsh.available is None
    assert crtsh.status == "NOT PROBED"
    vt = next(r for r in rows if r.name == "virustotal")
    assert vt.configured is False
    assert vt.available is False
    assert vt.status == "NOT CONFIGURED"
