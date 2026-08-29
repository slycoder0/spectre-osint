from __future__ import annotations

import httpx
import pytest

from spectre_osint.core.config import Settings
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.registry import default_registry
from spectre_osint.core.types import ProviderKeyType
from spectre_osint.providers.virustotal import VirusTotalProvider


@pytest.mark.asyncio
async def test_keyless_not_probed_and_required_not_configured(tmp_path) -> None:
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    registry = default_registry(http_client=None)
    rows = await registry.health(settings, probe=False)
    crtsh = next(r for r in rows if r.name == "crtsh")
    assert crtsh.key_type == ProviderKeyType.KEYLESS.value
    assert crtsh.configured_label == "N/A"
    assert crtsh.probed is False
    assert crtsh.status == "NOT PROBED"
    vt = next(r for r in rows if r.name == "virustotal")
    assert vt.key_type == ProviderKeyType.REQUIRED_API_KEY.value
    assert vt.configured is False
    assert vt.status == "NOT CONFIGURED"


@pytest.mark.asyncio
async def test_probe_records_timestamp(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        registry = default_registry(http)
        rows = await registry.health(settings, probe=True, names=["crtsh"])
        assert rows[0].probed is True
        assert rows[0].status == "ONLINE"
        assert rows[0].last_check
        assert "sk-" not in (rows[0].notes or "")
    finally:
        await http.close()


def test_virustotal_health_headers_redactable() -> None:
    from pydantic import SecretStr

    settings = Settings(virustotal_api_key=SecretStr("SPECTRE_CANARY_SECRET_9f3a2c1b"))
    headers = VirusTotalProvider().health_headers(settings)
    assert "x-apikey" in headers
