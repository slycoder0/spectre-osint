from __future__ import annotations

import asyncio
import json
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


@pytest.mark.asyncio
async def test_legacy_blocked_cache_reclassification_and_auth_fallback(tmp_path: Any) -> None:
    """Verify that legacy anonymous BLOCKED entries on 401/403 for requires_auth providers are reclassified to LOGIN_REQUIRED."""
    settings = _settings(tmp_path)
    result_cache = ResultCache(settings)
    sem = asyncio.Semaphore(5)
    entity = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)

    site_auth = SiteDefinition.model_validate({
        "name": "Instagram",
        "category": "Social",
        "profile_url": "https://www.instagram.com/{username}/",
        "check_method": "login_wall",
        "auth_platform": "instagram",
        "login_patterns": ["Please log in"],
    }).to_dict()

    site_no_auth = SiteDefinition.model_validate({
        "name": "Public API",
        "category": "Development",
        "profile_url": "https://api.example.com/{username}",
        "check_method": "generic_html",
        "requires_auth": False,
    }).to_dict()

    called_platforms: list[str] = []

    class MockAuthService:
        def __init__(self, active: bool = False) -> None:
            self.active = active

        def has_active(self, platform: str) -> bool:
            return self.active if platform == "instagram" else False

        async def fetch_public_profile(self, platform: str, username: str, url: str) -> FetchOutcome:
            called_platforms.append(platform)
            return FetchOutcome(
                status="OK",
                status_code=200,
                body=f"<html><body><h1>{username}</h1></body></html>",
                url=url,
                title=f"{username} on Instagram",
            )

    # 1. Seed legacy anonymous cache entry: check_status="BLOCKED", http_status=401, access_mode="ANONYMOUS_PUBLIC"
    legacy_payload_401 = {
        "platform": "Instagram",
        "username": "alice",
        "check_status": UsernameCheckStatus.BLOCKED.value,
        "status": UsernameCheckStatus.BLOCKED.value,
        "verification_status": UsernameCheckStatus.BLOCKED.value,
        "http_status": 401,
        "access_mode": AccessMode.ANONYMOUS_PUBLIC.value,
        "profile_url": "https://www.instagram.com/alice/",
    }
    result_cache.set("username", "Instagram", "alice", legacy_payload_401, access_mode=AccessMode.ANONYMOUS_PUBLIC.value)

    # Without active session -> returns reclassified LOGIN_REQUIRED from cache (preserving cache age, no live auth fetch)
    auth_inactive = MockAuthService(active=False)
    http = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    try:
        res1 = await _check_site(entity, site_auth, http, sem, result_cache=result_cache, auth_service=auth_inactive)
        f1 = res1["finding"]
        assert f1.data["check_status"] == UsernameCheckStatus.LOGIN_REQUIRED.value
        assert f1.data["cache_state"] == "CACHED"
        assert len(called_platforms) == 0
    finally:
        await http.close()

    # 2. Test HTTP 403 legacy cache without active session
    legacy_payload_403 = {
        "platform": "Instagram",
        "username": "bob",
        "check_status": UsernameCheckStatus.BLOCKED.value,
        "status": UsernameCheckStatus.BLOCKED.value,
        "verification_status": UsernameCheckStatus.BLOCKED.value,
        "http_status": 403,
        "access_mode": AccessMode.ANONYMOUS_PUBLIC.value,
        "profile_url": "https://www.instagram.com/bob/",
    }
    entity_bob = Entity.create(EntityType.USERNAME, "bob", "user", Confidence.CONFIRMED)
    result_cache.set("username", "Instagram", "bob", legacy_payload_403, access_mode=AccessMode.ANONYMOUS_PUBLIC.value)
    http_bob = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    try:
        res_bob = await _check_site(entity_bob, site_auth, http_bob, sem, result_cache=result_cache, auth_service=auth_inactive)
        f_bob = res_bob["finding"]
        assert f_bob.data["check_status"] == UsernameCheckStatus.LOGIN_REQUIRED.value
        assert f_bob.data["cache_state"] == "CACHED"
        assert len(called_platforms) == 0
    finally:
        await http_bob.close()

    # 3. Same legacy 401 cache entry WITH active session -> bypasses anonymous cache, triggers live authenticated fetch
    auth_active = MockAuthService(active=True)
    http_active = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(401, text="Unauthorized")))
    try:
        res2 = await _check_site(entity, site_auth, http_active, sem, result_cache=result_cache, auth_service=auth_active)
        f2 = res2["finding"]
        assert f2.data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
        assert f2.data["check_status"] in {UsernameCheckStatus.CONFIRMED.value, UsernameCheckStatus.LIKELY.value}
        assert len(called_platforms) == 1
        assert called_platforms[0] == "instagram"
    finally:
        await http_active.close()

    # 4. Genuine BLOCKED (e.g. anti-bot 200) on requires_auth provider MUST remain BLOCKED
    real_blocked_payload = {
        "platform": "Instagram",
        "username": "charlie",
        "check_status": UsernameCheckStatus.BLOCKED.value,
        "status": UsernameCheckStatus.BLOCKED.value,
        "verification_status": UsernameCheckStatus.BLOCKED.value,
        "http_status": 200,
        "access_mode": AccessMode.ANONYMOUS_PUBLIC.value,
        "profile_url": "https://www.instagram.com/charlie/",
    }
    entity_charlie = Entity.create(EntityType.USERNAME, "charlie", "user", Confidence.CONFIRMED)
    result_cache.set("username", "Instagram", "charlie", real_blocked_payload, access_mode=AccessMode.ANONYMOUS_PUBLIC.value)
    http_charlie = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    try:
        res_charlie = await _check_site(entity_charlie, site_auth, http_charlie, sem, result_cache=result_cache, auth_service=auth_active)
        f_charlie = res_charlie["finding"]
        # Real block must NOT be converted to LOGIN_REQUIRED
        assert f_charlie.data["check_status"] == UsernameCheckStatus.BLOCKED.value
        assert f_charlie.data["cache_state"] == "CACHED"
    finally:
        await http_charlie.close()

    # 5. Non-auth provider with 401/403 BLOCKED MUST remain BLOCKED
    no_auth_blocked_payload = {
        "platform": "Public API",
        "username": "david",
        "check_status": UsernameCheckStatus.BLOCKED.value,
        "status": UsernameCheckStatus.BLOCKED.value,
        "verification_status": UsernameCheckStatus.BLOCKED.value,
        "http_status": 401,
        "access_mode": AccessMode.ANONYMOUS_PUBLIC.value,
        "profile_url": "https://api.example.com/david",
    }
    entity_david = Entity.create(EntityType.USERNAME, "david", "user", Confidence.CONFIRMED)
    result_cache.set("username", "Public API", "david", no_auth_blocked_payload, access_mode=AccessMode.ANONYMOUS_PUBLIC.value)
    http_david = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    try:
        res_david = await _check_site(entity_david, site_no_auth, http_david, sem, result_cache=result_cache, auth_service=auth_active)
        f_david = res_david["finding"]
        # Non-auth provider must NOT be reclassified
        assert f_david.data["check_status"] == UsernameCheckStatus.BLOCKED.value
        assert f_david.data["cache_state"] == "CACHED"
    finally:
        await http_david.close()


@pytest.mark.asyncio
async def test_authenticated_json_fallback_discards_anonymous_json_error_metadata(tmp_path: Any) -> None:
    """Verify that anonymous JSON error responses are discarded when authenticated fallback succeeds."""
    settings = _settings(tmp_path)
    result_cache = ResultCache(settings)
    sem = asyncio.Semaphore(5)
    entity = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)

    site_def = SiteDefinition.model_validate({
        "name": "JSON Auth Site",
        "category": "Development",
        "profile_url": "https://example.com/api/users/{username}",
        "check_method": "json_api",
        "confidence_strategy": "explicit_api",
        "auth_platform": "twitch",
        "requires_auth": True,
        "json_id_field": "id",
        "display_name_fields": ["name"],
        "bio_field": "bio",
        "avatar_field": "avatar",
        "website_fields": ["website"],
    }).to_dict()

    # Anonymous response: HTTP 401 with error JSON containing hostile/deceptive field names
    anonymous_json = {
        "error": "login required",
        "name": "Authentication Service",
        "bio": "Please log in to continue",
        "website": "https://support.example.com",
        "avatar": "https://example.com/login-logo.png",
    }
    http = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(401, json=anonymous_json)))

    class MockAuthService:
        def has_active(self, platform: str) -> bool:
            return platform == "twitch"

        async def fetch_public_profile(self, platform: str, username: str, url: str) -> FetchOutcome:
            return FetchOutcome(
                status="OK",
                status_code=200,
                url="https://example.com/alice",
                title="Alice in Tech",
                canonical_url="https://example.com/alice",
                body=(
                    '<html><head><title>Alice in Tech</title>'
                    '<meta property="og:title" content="Alice Tech">'
                    '<link rel="canonical" href="https://example.com/alice">'
                    '</head><body><h1>Alice in Tech</h1>'
                    '<p>Real developer bio</p>'
                    '<a rel="me" href="https://alicetech.org">Personal Web</a>'
                    '</body></html>'
                ),
            )

    try:
        res = await _check_site(
            entity,
            site_def,
            http,
            sem,
            result_cache=result_cache,
            auth_service=MockAuthService(),
        )
        finding = res["finding"]
        data = finding.data
        assert data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
        assert data["check_status"] in {UsernameCheckStatus.CONFIRMED.value, UsernameCheckStatus.LIKELY.value}
        assert data["anonymous_status"] == UsernameCheckStatus.LOGIN_REQUIRED.value

        # Assert anonymous JSON values are strictly discarded
        assert data["display_name"] != "Authentication Service"
        assert data["bio"] != "Please log in to continue"
        assert data["website"] != "https://support.example.com"
        assert data["avatar_url"] != "https://example.com/login-logo.png"

        # Assert authenticated response values are authoritative
        assert data["final_url"] == "https://example.com/alice"
        assert data["http_status"] == 200
        assert data["page_title"] == "Alice in Tech"
        assert data["canonical"] == "https://example.com/alice"
        assert data["website"] == "https://alicetech.org/"

        # Assert observed provenance contains no anonymous JSON API fields
        observed = data["observed"]
        for v in observed.values():
            assert "json_auth_site_api" not in v.get("source", "")

        # Assert Evidence uses authenticated response
        evidence = res["evidence"][0]
        assert evidence.url == "https://example.com/alice"
        raw_data = json.loads(evidence.raw_reference or "{}")
        assert raw_data["title"] == "Alice in Tech"
        assert raw_data["http_status"] == 200
        assert raw_data["public_name"] != "Authentication Service"

        # Assert no entity created for support.example.com
        entity_values = [e.value for e in res["entities"]]
        assert "https://support.example.com" not in entity_values

        # Assert ResultCache payload does not persist raw HTML body
        cached = result_cache.get("username", "JSON Auth Site", "alice", access_mode=AccessMode.AUTHENTICATED_PUBLIC.value)
        assert cached is not None
        assert "body" not in cached.payload
        assert "<html>" not in str(cached.payload)
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_authenticated_html_fallback_discards_anonymous_login_metadata(tmp_path: Any) -> None:
    """Verify that anonymous login HTML metadata does not leak into authenticated positive finding."""
    settings = _settings(tmp_path)
    result_cache = ResultCache(settings)
    sem = asyncio.Semaphore(5)
    entity = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)

    site_def = SiteDefinition.model_validate({
        "name": "HTML Auth Site",
        "category": "Social",
        "profile_url": "https://example.com/{username}",
        "check_method": "login_wall",
        "auth_platform": "instagram",
        "login_patterns": ["Please sign in to view this profile"],
    }).to_dict()

    # Anonymous response: login page with deceptive metadata
    anonymous_html = (
        '<html><head><title>Sign in to Example</title>'
        '<meta property="og:title" content="Example Login Portal">'
        '<meta property="og:image" content="https://example.com/login-logo.png">'
        '<meta name="description" content="Sign in to continue to Example">'
        '<link rel="canonical" href="https://example.com/login">'
        '</head><body><h1>Please sign in to view this profile</h1>'
        '<a href="https://support.example.com">Support</a>'
        '</body></html>'
    )
    http = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, text=anonymous_html)))

    class MockAuthService:
        def has_active(self, platform: str) -> bool:
            return platform == "instagram"

        async def fetch_public_profile(self, platform: str, username: str, url: str) -> FetchOutcome:
            return FetchOutcome(
                status="OK",
                status_code=200,
                url="https://example.com/alice",
                title="Alice (@alice) • Example",
                canonical_url="https://example.com/alice",
                og_title="Alice Example",
                body=(
                    '<html><head><title>Alice (@alice) • Example</title>'
                    '<meta property="og:title" content="Alice Example">'
                    '<link rel="canonical" href="https://example.com/alice">'
                    '</head><body><h1>Alice Example</h1>'
                    '<p>Authentic profile bio</p>'
                    '<a rel="me" href="https://alice-personal.org">Personal Blog</a>'
                    '</body></html>'
                ),
            )

    try:
        res = await _check_site(
            entity,
            site_def,
            http,
            sem,
            result_cache=result_cache,
            auth_service=MockAuthService(),
        )
        finding = res["finding"]
        data = finding.data
        assert data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
        assert data["check_status"] in {UsernameCheckStatus.CONFIRMED.value, UsernameCheckStatus.LIKELY.value}

        # Anonymous login metadata must not leak
        assert data["display_name"] == "Alice Example"
        assert data["bio"] != "Sign in to continue to Example"
        assert data["avatar_url"] != "https://example.com/login-logo.png"
        assert data["website"] == "https://alice-personal.org/"
        assert data["final_url"] == "https://example.com/alice"
        assert data["http_status"] == 200
        assert data["page_title"] == "Alice (@alice) • Example"
        assert data["canonical"] == "https://example.com/alice"

        evidence = res["evidence"][0]
        assert evidence.url == "https://example.com/alice"
        raw_data = json.loads(evidence.raw_reference or "{}")
        assert raw_data["title"] == "Alice (@alice) • Example"
        assert raw_data["public_name"] == "Alice Example"

        # SOCIAL_PROFILE Entity metadata
        profile_entity = next(e for e in res["entities"] if e.type == EntityType.SOCIAL_PROFILE)
        assert profile_entity.metadata["public_name"] == "Alice Example"

        # No support website entity
        entity_values = [e.value for e in res["entities"]]
        assert "https://support.example.com" not in entity_values
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_authenticated_fallback_with_no_profile_metadata_yields_none(tmp_path: Any) -> None:
    """Verify that when authenticated page has no extractable profile metadata, values are None and do not fall back to login page."""
    settings = _settings(tmp_path)
    result_cache = ResultCache(settings)
    sem = asyncio.Semaphore(5)
    entity = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)

    site_def = SiteDefinition.model_validate({
        "name": "Bare Auth Site",
        "category": "Social",
        "profile_url": "https://example.com/{username}",
        "check_method": "login_wall",
        "auth_platform": "instagram",
        "login_patterns": ["Please sign in"],
    }).to_dict()

    anonymous_html = (
        '<html><head><title>Sign in to Example</title>'
        '<meta property="og:title" content="Login Title">'
        '<meta property="og:image" content="https://example.com/login.jpg">'
        '<meta name="description" content="Login description">'
        '</head><body><h1>Please sign in</h1>'
        '<a href="https://support.example.com">Support</a>'
        '</body></html>'
    )
    http = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, text=anonymous_html)))

    class MockAuthService:
        def has_active(self, platform: str) -> bool:
            return platform == "instagram"

        async def fetch_public_profile(self, platform: str, username: str, url: str) -> FetchOutcome:
            return FetchOutcome(
                status="OK",
                status_code=200,
                url="https://example.com/alice",
                title=f"{username} Profile",
                body="<html><body><h1>Profile found</h1></body></html>",
            )

    try:
        res = await _check_site(
            entity,
            site_def,
            http,
            sem,
            result_cache=result_cache,
            auth_service=MockAuthService(),
        )
        finding = res["finding"]
        data = finding.data
        assert data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
        assert data["check_status"] in {UsernameCheckStatus.CONFIRMED.value, UsernameCheckStatus.LIKELY.value}

        # All unprovided fields must be None/empty — zero fallback to anonymous login metadata
        assert data["display_name"] is None
        assert data["bio"] is None
        assert data["avatar_url"] is None
        assert data["website"] is None
        assert data["public_links"] == []
        assert data["final_url"] == "https://example.com/alice"
        assert data["http_status"] == 200

        # No linked website entities created
        linked_website_entities = [e for e in res["entities"] if e.type != EntityType.SOCIAL_PROFILE]
        assert len(linked_website_entities) == 0
    finally:
        await http.close()
