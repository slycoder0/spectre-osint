"""Honest User-Agent (B2-06): one identifiable UA, no browser-UA rotation.

Before B2-06 `HttpClient.pick_ua()` sent a random browser User-Agent from
`data/user_agents.txt` on ~35% of requests. SPECTRE now always identifies itself as
`SPECTRE-OSINT/<version> (+<project URL>)`. These tests also pin that removing the
rotation did not touch the SSRF policy or the pinned-connection behavior of HttpClient.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from spectre_osint import __version__
from spectre_osint.core.config import BUNDLED_DATA_DIR, PROJECT_URL, Settings
from spectre_osint.core.exceptions import SSRFBlocked
from spectre_osint.core.http_client import HttpClient
from spectre_osint.modules.username.catalog import load_catalog

HONEST_UA = f"SPECTRE-OSINT/{__version__} (+{PROJECT_URL})"


def _settings(tmp_path: Path, **kwargs: object) -> Settings:
    values: dict[str, object] = {
        "data_dir": tmp_path / "data",
        "reports_dir": tmp_path / "reports",
        "logs_dir": tmp_path / "logs",
        "database_url": f"sqlite:///{tmp_path / 't.db'}",
        "http_max_retries": 1,
    }
    values.update(kwargs)
    settings = Settings(_env_file=None, **values)  # type: ignore[arg-type]
    settings.ensure_dirs()
    return settings


async def _public_resolver(_host: str) -> list[str]:
    return ["93.184.216.34"]


async def _loopback_resolver(_host: str) -> list[str]:
    return ["127.0.0.1"]


def test_project_url_is_the_public_repository() -> None:
    assert PROJECT_URL == "https://github.com/slycoder0/spectre-osint"


def test_default_user_agent_names_project_version_and_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SPECTRE_USER_AGENT", raising=False)
    assert Settings(_env_file=None).user_agent == HONEST_UA


@pytest.mark.asyncio
async def test_every_request_carries_the_same_honest_user_agent(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("user-agent", ""))
        return httpx.Response(200, text="ok")

    settings = _settings(tmp_path, ssrf_enabled=False)
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        for i in range(60):
            await http.get(f"https://example.test/u/{i}", provider="demo", use_cache=False, min_interval=0)
    finally:
        await http.close()
    assert len(seen) == 60
    assert set(seen) == {HONEST_UA}
    assert not any("Mozilla" in ua for ua in seen)


@pytest.mark.asyncio
async def test_operator_override_is_sent_verbatim(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("user-agent", ""))
        return httpx.Response(200, text="ok")

    settings = _settings(tmp_path, ssrf_enabled=False, user_agent="SPECTRE-OSINT/lab (+mailto:lab@example.test)")
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        for i in range(10):
            await http.get(f"https://example.test/o/{i}", provider="demo", use_cache=False, min_interval=0)
    finally:
        await http.close()
    assert set(seen) == {"SPECTRE-OSINT/lab (+mailto:lab@example.test)"}


def test_no_browser_user_agent_list_ships_with_the_package() -> None:
    assert not (BUNDLED_DATA_DIR / "user_agents.txt").exists()
    for path in BUNDLED_DATA_DIR.iterdir():
        if path.is_file() and path.suffix in {".txt", ".yaml", ".yml", ".json"}:
            assert "Mozilla/5.0" not in path.read_text(encoding="utf-8"), path.name


def test_http_client_has_no_rotation_pool(tmp_path: Path) -> None:
    http = HttpClient(_settings(tmp_path))
    try:
        assert not hasattr(http, "user_agents")
        assert http.user_agent() == HONEST_UA
    finally:
        import asyncio

        asyncio.run(http.close())


def test_bundled_catalog_never_overrides_the_user_agent() -> None:
    offenders: list[str] = []
    for site in load_catalog().sites:
        headers: dict[str, str] = {}
        headers.update(getattr(site, "headers", None) or {})
        request = getattr(site, "request", None)
        headers.update(getattr(request, "headers", None) or {})
        if any(name.lower() == "user-agent" for name in headers):
            offenders.append(site.slug)
    assert offenders == []


# --- SSRF / HttpClient protections are unchanged ------------------------------------------


@pytest.mark.asyncio
async def test_ssrf_still_blocks_a_target_resolving_to_loopback(tmp_path: Path) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="should never be reached")

    settings = _settings(tmp_path, ssrf_enabled=True)
    http = HttpClient(settings, transport=httpx.MockTransport(handler), resolver=_loopback_resolver)
    try:
        with pytest.raises(SSRFBlocked):
            await http.get("https://rebind.example.test/", provider="demo", use_cache=False, min_interval=0)
    finally:
        await http.close()
    assert calls == []


@pytest.mark.asyncio
async def test_ssrf_still_blocks_a_redirect_into_a_private_address(tmp_path: Path) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(302, headers={"location": "http://10.0.0.5/admin"})

    settings = _settings(tmp_path, ssrf_enabled=True)
    http = HttpClient(settings, transport=httpx.MockTransport(handler), resolver=_public_resolver)
    try:
        with pytest.raises(SSRFBlocked):
            await http.get("https://example.test/start", provider="demo", use_cache=False, min_interval=0)
    finally:
        await http.close()
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_pinned_request_keeps_host_header_and_honest_ua(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    settings = _settings(tmp_path, ssrf_enabled=True)
    http = HttpClient(settings, transport=httpx.MockTransport(handler), resolver=_public_resolver)
    try:
        await http.get("https://example.test/profile", provider="demo", use_cache=False, min_interval=0)
    finally:
        await http.close()
    (request,) = seen
    assert request.url.host == "93.184.216.34"
    assert request.headers["host"] == "example.test"
    assert request.headers["user-agent"] == HONEST_UA
