from __future__ import annotations

import httpx
import pytest

from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.fake import FakeBrowserBackend
from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.result_cache import ResultCache
from spectre_osint.core.types import AccessMode, Confidence, EntityType, UsernameCheckStatus
from spectre_osint.modules.username.engine import analyze_username, classify_html


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
