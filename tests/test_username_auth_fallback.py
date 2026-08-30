from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.fake import FakeBrowserBackend
from spectre_osint.browser.models import FetchOutcome
from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.result_cache import ResultCache
from spectre_osint.core.types import AccessMode, Confidence, EntityType, UsernameCheckStatus
from spectre_osint.modules.username.catalog import SiteDefinition
from spectre_osint.modules.username.engine import _check_site, analyze_username, classify_html


def _settings(tmp_path):
    s = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        auth_dir=tmp_path / "auth",
        browser_profiles_dir=tmp_path / "browser-profiles",
        browser_backend="fake",
        keyring_enabled=False,
        ssrf_enabled=False,
    )
    s.ensure_dirs()
    return s


def test_captcha_and_challenge_classify() -> None:
    captcha, _, _ = classify_html(
        status_code=200,
        body="please complete captcha",
        title="Verify",
        final_url="https://www.tiktok.com/@x",
        site={"captcha_patterns": ["captcha"], "check_method": "login_wall"},
        username="x",
    )
    assert captcha == UsernameCheckStatus.CAPTCHA_REQUIRED
    challenge, _, _ = classify_html(
        status_code=200,
        body="checkpoint required",
        title="",
        final_url="https://instagram.com/x",
        site={"challenge_patterns": ["checkpoint"], "check_method": "login_wall"},
        username="x",
    )
    assert challenge == UsernameCheckStatus.CHALLENGE_REQUIRED


@pytest.mark.asyncio
async def test_login_required_stays_without_session(tmp_path) -> None:
    settings = _settings(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Please log in to continue", headers={"content-type": "text/html"})

    transport = httpx.MockTransport(handler)
    http = HttpClient(settings, transport=transport)
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    bundle = await analyze_username(
        entity,
        http,
        categories=["Social"],
        auth_service=AuthService(settings),
        result_cache=ResultCache(settings),
    )
    insta = next(f for f in bundle["findings"] if f.title == "Instagram")
    assert insta.data["check_status"] == "LOGIN_REQUIRED"
    assert insta.data["access_mode"] == AccessMode.ANONYMOUS_PUBLIC.value
    await http.close()


@pytest.mark.asyncio
async def test_authenticated_public_fallback_and_cache(tmp_path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    await service.login("instagram")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Please log in to continue", headers={"content-type": "text/html"})

    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    cache = ResultCache(settings)
    bundle = await analyze_username(
        entity, http, categories=["Social"], auth_service=service, result_cache=cache
    )
    insta = next(f for f in bundle["findings"] if f.title == "Instagram")
    assert insta.data["anonymous_status"] == "LOGIN_REQUIRED"
    assert insta.data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
    assert insta.data["check_status"] in {"LIKELY", "CONFIRMED", "INCONCLUSIVE"}
    cached = await analyze_username(
        entity, http, categories=["Social"], auth_service=service, result_cache=cache
    )
    insta2 = next(f for f in cached["findings"] if f.title == "Instagram")
    assert insta2.data.get("cache_state") == "CACHED"
    await http.close()


@pytest.mark.asyncio
async def test_session_expired_not_bypassed(tmp_path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    await service.login("instagram")
    FakeBrowserBackend.verify_status["instagram"] = UsernameCheckStatus.SESSION_EXPIRED.value
    FakeBrowserBackend.verify_status["instagram"] = __import__(
        "spectre_osint.core.types", fromlist=["SessionStatus"]
    ).SessionStatus.EXPIRED

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Please log in to continue")

    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    bundle = await analyze_username(
        entity, http, categories=["Social"], auth_service=service, result_cache=ResultCache(settings)
    )
    insta = next(f for f in bundle["findings"] if f.title == "Instagram")
    assert insta.data["check_status"] == "SESSION_EXPIRED"
    await http.close()


@pytest.mark.asyncio
async def test_authenticated_public_routes_via_auth_platform(tmp_path) -> None:
    """Verify that _authenticated_public routes session checks and fetches using auth_platform rather than human site name."""
    settings = _settings(tmp_path)
    http = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, text="Login wall please log in")))
    sem = asyncio.Semaphore(5)
    entity = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)

    # Track calls to auth_service
    has_active_calls = []
    fetch_calls = []

    class StubAuthService:
        def has_active(self, platform: str | None) -> bool:
            has_active_calls.append(platform)
            return platform == "instagram"

        async def fetch_public_profile(self, site_name: str, username: str, profile_url: str) -> FetchOutcome | None:
            fetch_calls.append((site_name, username, profile_url))
            if site_name == "instagram":
                return FetchOutcome(
                    status=UsernameCheckStatus.LIKELY.value,
                    url=profile_url,
                    status_code=200,
                    title="Alice (@alice) • Instagram photos and videos",
                    canonical_url=profile_url,
                    og_title="Alice (@alice)",
                )
            return None

    site_dict = {
        "name": "Instagram Web",
        "category": "Social",
        "profile_url": "https://www.instagram.com/{username}/",
        "check_method": "login_wall",
        "requires_auth": True,
        "auth_platform": "instagram",
        "expected_status": [200],
        "not_found_status": [404],
        "login_patterns": ["log in"],
    }
    site = SiteDefinition.model_validate(site_dict).to_dict()

    res = await _check_site(
        entity,
        site,
        http,
        sem,
        auth_service=StubAuthService(),
    )
    finding = res["finding"]

    # 1. Routing used "instagram", NOT "Instagram Web"
    assert "instagram" in has_active_calls
    assert "Instagram Web" not in has_active_calls
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0] == "instagram"
    assert fetch_calls[0][1] == "alice"

    # 2. Finding display identity preserved as "Instagram Web"
    assert finding.data["platform"] == "Instagram Web"
    assert finding.data["site"] == "Instagram Web"
    assert finding.data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
    assert finding.data["check_status"] in {UsernameCheckStatus.LIKELY.value, UsernameCheckStatus.CONFIRMED.value}

    # 3. Test normalization with uppercase / whitespace in auth_platform
    site_unnormalized = {
        "name": "Instagram Custom",
        "category": "Social",
        "profile_url": "https://www.instagram.com/{username}/",
        "check_method": "login_wall",
        "requires_auth": True,
        "auth_platform": " Instagram ",
        "expected_status": [200],
        "not_found_status": [404],
        "login_patterns": ["log in"],
    }
    site_norm = SiteDefinition.model_validate(site_unnormalized).to_dict()
    has_active_calls.clear()
    fetch_calls.clear()

    res_norm = await _check_site(
        entity,
        site_norm,
        http,
        sem,
        auth_service=StubAuthService(),
    )
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0] == "instagram"
    assert res_norm["finding"].data["platform"] == "Instagram Custom"

    await http.close()


@pytest.mark.asyncio
async def test_authenticated_json_api_fallback_and_cache_transition(tmp_path: Any) -> None:
    """Verify that authenticated json_api triggers LOGIN_REQUIRED on 401/403 and transitions cleanly across cache."""
    settings = _settings(tmp_path)
    sem = asyncio.Semaphore(5)
    entity = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)
    result_cache = ResultCache(settings)

    class MockAuthService:
        def __init__(self) -> None:
            self.active_platforms: set[str] = set()
            self.called_platforms: list[str] = []

        def has_active(self, platform: str) -> bool:
            return platform in self.active_platforms

        async def fetch_public_profile(self, platform: str, username: str, url: str) -> FetchOutcome:
            self.called_platforms.append(platform)
            return FetchOutcome(
                status="OK",
                status_code=200,
                body=f'<html><head><title>{username} Profile</title></head><body><h1>{username}</h1><a href="https://example.com/{username}">Profile</a></body></html>',
                url=url,
                title=f"{username} Profile",
                og_title=username,
            )

    site_auth = SiteDefinition.model_validate({
        "name": "JSON Auth Platform",
        "category": "Social",
        "profile_url": "https://api.example.com/users/{username}",
        "check_method": "json_api",
        "confidence_strategy": "explicit_api",
        "json_id_field": "id",
        "requires_auth": True,
        "auth_platform": "instagram",
        "expected_status": [200],
        "not_found_status": [404],
    }).to_dict()

    site_no_auth = SiteDefinition.model_validate({
        "name": "JSON No Auth Platform",
        "category": "Social",
        "profile_url": "https://api.example.com/users/{username}",
        "check_method": "json_api",
        "confidence_strategy": "explicit_api",
        "json_id_field": "id",
        "requires_auth": False,
        "expected_status": [200],
        "not_found_status": [404],
    }).to_dict()

    auth_svc = MockAuthService()

    # 1. Test 401 on requires_auth=True without active session -> LOGIN_REQUIRED (cached)
    http_401 = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"error": "unauthorized"})))
    try:
        res1 = await _check_site(entity, site_auth, http_401, sem, result_cache=result_cache, auth_service=auth_svc)
        assert res1["finding"].data["check_status"] == UsernameCheckStatus.LOGIN_REQUIRED.value
        assert res1["finding"].data["access_mode"] == AccessMode.ANONYMOUS_PUBLIC.value
        assert len(auth_svc.called_platforms) == 0

        # Operator logs in (active session created)
        auth_svc.active_platforms.add("instagram")

        # 2. Rescan with active session -> Cache does NOT suppress fallback, authenticated fetch executes
        res2 = await _check_site(entity, site_auth, http_401, sem, result_cache=result_cache, auth_service=auth_svc)
        assert res2["finding"].data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
        assert res2["finding"].data["check_status"] in {
            UsernameCheckStatus.CONFIRMED.value,
            UsernameCheckStatus.LIKELY.value,
        }
        assert len(auth_svc.called_platforms) == 1
        assert auth_svc.called_platforms[0] == "instagram"
    finally:
        await http_401.close()

    # 3. Test 403 on requires_auth=True with active session directly -> authenticated fetch executes
    entity_403 = Entity.create(EntityType.USERNAME, "bob", "user", Confidence.CONFIRMED)
    http_403 = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(403, json={"error": "forbidden"})))
    try:
        res3 = await _check_site(entity_403, site_auth, http_403, sem, result_cache=result_cache, auth_service=auth_svc)
        assert res3["finding"].data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
        assert res3["finding"].data["check_status"] in {
            UsernameCheckStatus.CONFIRMED.value,
            UsernameCheckStatus.LIKELY.value,
        }
        assert len(auth_svc.called_platforms) == 2
        assert auth_svc.called_platforms[1] == "instagram"
    finally:
        await http_403.close()

    # 4. Test 401 & 403 on requires_auth=False -> BLOCKED (not LOGIN_REQUIRED)
    http_no_auth = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"error": "unauthorized"})))
    try:
        res_na = await _check_site(entity, site_no_auth, http_no_auth, sem, result_cache=result_cache, auth_service=auth_svc)
        assert res_na["finding"].data["check_status"] == UsernameCheckStatus.BLOCKED.value
        assert res_na["finding"].data["access_mode"] == AccessMode.ANONYMOUS_PUBLIC.value
    finally:
        await http_no_auth.close()


@pytest.mark.asyncio
async def test_end_to_end_auth_routing_with_platform_alias(tmp_path: Any) -> None:
    """Verify that catalog platform alias canonicalizes before runtime and routes through AuthService without alias leakage."""
    settings = _settings(tmp_path)
    sem = asyncio.Semaphore(5)
    entity = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)

    called_platforms: list[str] = []

    class AliasMockAuthService:
        def has_active(self, platform: str) -> bool:
            return platform == "instagram"

        async def fetch_public_profile(self, platform: str, username: str, url: str) -> FetchOutcome:
            called_platforms.append(platform)
            return FetchOutcome(
                status="OK",
                status_code=200,
                body=f'<html><head><title>{username} on Instagram</title></head><body><h1>{username}</h1><a href="https://instagram.com/{username}">Profile</a></body></html>',
                url=url,
                title=f"{username} on Instagram",
                og_title=username,
            )

    # 1. Alias input in catalog definition
    site_def = SiteDefinition.model_validate({
        "name": "Instagram Web",
        "category": "Social",
        "profile_url": "https://www.instagram.com/{username}/",
        "check_method": "login_wall",
        "auth_platform": "ig",
        "login_patterns": ["Please log in"],
    }).to_dict()

    # Catalog model exports canonical slug, not raw alias
    assert site_def["auth_platform"] == "instagram"

    http = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, text="Please log in to continue")))
    try:
        res = await _check_site(entity, site_def, http, sem, auth_service=AliasMockAuthService())
        assert len(called_platforms) == 1
        # AuthService received canonical slug, never raw alias
        assert called_platforms[0] == "instagram"

        finding = res["finding"]
        # Human-facing display name is preserved
        assert finding.data["platform"] == "Instagram Web"
        assert finding.data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
        assert finding.data["check_status"] in {
            UsernameCheckStatus.CONFIRMED.value,
            UsernameCheckStatus.LIKELY.value,
        }
    finally:
        await http.close()
