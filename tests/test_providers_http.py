from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from pydantic import SecretStr

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
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

CANARY = "SPECTRE_CANARY_SECRET_9f3a2c1b"


def _settings(tmp_path) -> Settings:
    s = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
        virustotal_api_key=SecretStr(CANARY),
        shodan_api_key=SecretStr(CANARY),
        censys_api_id=SecretStr("id"),
        censys_api_secret=SecretStr(CANARY),
        abuseipdb_api_key=SecretStr(CANARY),
        hibp_api_key=SecretStr(CANARY),
        urlscan_api_key=SecretStr(CANARY),
        github_token=SecretStr(CANARY),
        ipinfo_token=SecretStr(CANARY),
        greynoise_api_key=SecretStr(CANARY),
        otx_api_key=SecretStr(CANARY),
        http_max_retries=1,
    )
    s.ensure_dirs()
    return s


def _entity() -> Entity:
    return Entity.create(EntityType.DOMAIN, "example.com", "t", Confidence.CONFIRMED)


def _ip() -> Entity:
    return Entity.create(EntityType.IP, "1.1.1.1", "t", Confidence.CONFIRMED)


def _email() -> Entity:
    return Entity.create(EntityType.EMAIL, "user@example.com", "t", Confidence.CONFIRMED)


def _user() -> Entity:
    return Entity.create(EntityType.USERNAME, "octocat", "t", Confidence.CONFIRMED)


JSON_OK: dict[str, Callable[[], object]] = {
    "crtsh": lambda: [{"id": 1, "name_value": "www.example.com", "common_name": "example.com"}],
    "rdap": lambda: {"ldhName": "EXAMPLE.COM", "entities": []},
    "virustotal": lambda: {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}},
    "alienvault": lambda: {"pulse_info": {"count": 2}, "type_title": "domain"},
    "urlscan": lambda: {"results": [{"page": {"url": "https://example.com"}, "task": {}}], "total": 1},
    "abuseipdb": lambda: {"data": {"abuseConfidenceScore": 0, "totalReports": 0}},
    "shodan": lambda: {"ports": [443], "org": "Example"},
    "censys": lambda: {"result": {"ip": "1.1.1.1"}},
    "hibp": lambda: [{"Name": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04"}],
    "github": lambda: {"login": "octocat", "html_url": "https://github.com/octocat", "public_repos": 8},
    "ipinfo": lambda: {"org": "AS13335", "country": "US", "city": "Los Angeles"},
    "greynoise": lambda: {"classification": "benign", "noise": False, "riot": True},
    "wayback": lambda: [["timestamp", "original"], ["20200101120000", "http://example.com/"]],
}


def _client(tmp_path, status: int, body: object | None, *, timeout: bool = False) -> HttpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if timeout:
            raise httpx.ReadTimeout("timeout")
        if status == 429:
            return httpx.Response(429, headers={"Retry-After": "0"}, text="rate")
        if isinstance(body, str):
            return httpx.Response(status, text=body)
        if body is None:
            return httpx.Response(status, text="not-json")
        return httpx.Response(status, json=body)

    return HttpClient(_settings(tmp_path), transport=httpx.MockTransport(handler))


PROVIDERS = [
    ("crtsh", CrtShProvider, _entity, FindingStatus.FOUND),
    ("rdap", RdapProvider, _entity, FindingStatus.FOUND),
    ("virustotal", VirusTotalProvider, _entity, FindingStatus.FOUND),
    ("alienvault", AlienVaultProvider, _entity, FindingStatus.FOUND),
    ("urlscan", UrlscanProvider, _entity, FindingStatus.FOUND),
    ("abuseipdb", AbuseIPDBProvider, _ip, FindingStatus.FOUND),
    ("shodan", ShodanProvider, _ip, FindingStatus.FOUND),
    ("censys", CensysProvider, _ip, FindingStatus.FOUND),
    ("hibp", HIBPProvider, _email, FindingStatus.FOUND),
    ("github", GitHubProvider, _user, FindingStatus.FOUND),
    ("ipinfo", IPinfoProvider, _ip, FindingStatus.FOUND),
    ("greynoise", GreyNoiseProvider, _ip, FindingStatus.FOUND),
    ("wayback", WaybackProvider, _entity, FindingStatus.FOUND),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("name,cls,entity_fn,ok_status", PROVIDERS)
async def test_provider_200(tmp_path, name, cls, entity_fn, ok_status) -> None:
    http = _client(tmp_path, 200, JSON_OK[name]())
    try:
        result = await cls(http).safe_search(entity_fn(), http.settings)
        assert result.status == ok_status
        assert CANARY not in str(result.findings)
    finally:
        await http.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("name,cls,entity_fn,_s", PROVIDERS)
async def test_provider_404(tmp_path, name, cls, entity_fn, _s) -> None:
    http = _client(tmp_path, 404, {"error": "missing"})
    try:
        result = await cls(http).safe_search(entity_fn(), http.settings)
        assert result.status in {
            FindingStatus.NOT_FOUND,
            FindingStatus.PROVIDER_UNAVAILABLE,
        }
    finally:
        await http.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("name,cls,entity_fn,_s", PROVIDERS)
async def test_provider_429(tmp_path, name, cls, entity_fn, _s) -> None:
    http = _client(tmp_path, 429, None)
    try:
        result = await cls(http).safe_search(entity_fn(), http.settings)
        assert result.status == FindingStatus.PROVIDER_UNAVAILABLE
    finally:
        await http.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("name,cls,entity_fn,_s", PROVIDERS)
async def test_provider_5xx(tmp_path, name, cls, entity_fn, _s) -> None:
    http = _client(tmp_path, 502, "oops")
    try:
        result = await cls(http).safe_search(entity_fn(), http.settings)
        assert result.status == FindingStatus.PROVIDER_UNAVAILABLE
    finally:
        await http.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("name,cls,entity_fn,_s", PROVIDERS)
async def test_provider_invalid_json(tmp_path, name, cls, entity_fn, _s) -> None:
    http = _client(tmp_path, 200, None)
    try:
        result = await cls(http).safe_search(entity_fn(), http.settings)
        assert result.status in {
            FindingStatus.PROVIDER_UNAVAILABLE,
            FindingStatus.NOT_FOUND,
        }
    finally:
        await http.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("name,cls,entity_fn,_s", PROVIDERS)
async def test_provider_timeout(tmp_path, name, cls, entity_fn, _s) -> None:
    http = _client(tmp_path, 200, {}, timeout=True)
    try:
        result = await cls(http).safe_search(entity_fn(), http.settings)
        assert result.status == FindingStatus.PROVIDER_UNAVAILABLE
    finally:
        await http.close()
