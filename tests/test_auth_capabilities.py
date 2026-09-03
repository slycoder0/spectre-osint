"""Auth capabilities, OAuth rejection, and X no-retry. No real X/Google login."""

from __future__ import annotations

import httpx
import pytest
from typer.testing import CliRunner

from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.fake import FakeBrowserBackend
from spectre_osint.browser.login_flow import STOP, classify_browser_state, next_login_action
from spectre_osint.browser.models import (
    ANONYMOUS_LOOKUP_UNAFFECTED,
    AUTH_PLATFORMS,
    OFFICIAL_API_SUGGESTION,
    browser_login_permitted,
    official_api_suggestion,
)
from spectre_osint.cli.commands import app
from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.result_cache import ResultCache
from spectre_osint.core.types import (
    AccessMode,
    AuthCapability,
    Confidence,
    EntityType,
    SessionStatus,
    UsernameCheckStatus,
)
from spectre_osint.modules.username.engine import analyze_username

runner = CliRunner()
GOOGLE_OAUTH_TEXT = "This browser or app may not be secure. Try using a different browser."


def _settings(tmp_path) -> Settings:
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


def test_platform_auth_capabilities() -> None:
    assert AUTH_PLATFORMS["instagram"].auth_capability is AuthCapability.PLAYWRIGHT_SESSION
    assert AUTH_PLATFORMS["instagram"].preferred_browser == "playwright"
    assert AUTH_PLATFORMS["instagram"].retry_browser_after_limit is True
    assert official_api_suggestion(AUTH_PLATFORMS["instagram"]) is None
    x = AUTH_PLATFORMS["x"]
    assert x.auth_capability is AuthCapability.BOTH
    assert x.preferred_browser == "chrome"
    assert x.retry_browser_after_limit is False
    assert official_api_suggestion(x) == OFFICIAL_API_SUGGESTION
    tiktok = AUTH_PLATFORMS["tiktok"]
    assert tiktok.auth_capability is AuthCapability.CHROME_CDP_SESSION
    assert tiktok.preferred_browser == "chrome"
    for slug in ("facebook", "threads", "twitch"):
        assert AUTH_PLATFORMS[slug].auth_capability is AuthCapability.PLAYWRIGHT_SESSION


def test_oauth_browser_rejected_is_distinct_from_limited_and_captcha() -> None:
    spec = AUTH_PLATFORMS["x"]
    oauth = next_login_action(
        spec,
        url="https://accounts.google.com/signin/oauth",
        cookies=[],
        visible_text=GOOGLE_OAUTH_TEXT,
        visited_login=True,
        visited_home=False,
    )
    assert oauth.kind == STOP
    assert oauth.status == SessionStatus.OAUTH_BROWSER_REJECTED
    limited = classify_browser_state(
        spec, spec.login_url, "We've temporarily limited your login. Please try again later."
    )
    captcha = classify_browser_state(spec, spec.login_url, "please complete the captcha recaptcha")
    challenge = classify_browser_state(AUTH_PLATFORMS["instagram"], spec.login_url, "checkpoint challenge")
    expired = classify_browser_state(spec, spec.login_url, "")
    assert limited is SessionStatus.TEMPORARILY_LIMITED
    assert captcha is SessionStatus.CAPTCHA_REQUIRED
    assert challenge is SessionStatus.CHALLENGE_REQUIRED
    assert expired is SessionStatus.EXPIRED
    assert len({oauth.status, limited, captcha, challenge, expired}) == 5


@pytest.mark.asyncio
async def test_x_does_not_retry_browser_login_after_temporarily_limited(tmp_path) -> None:
    settings = _settings(tmp_path)
    FakeBrowserBackend.login_status["x"] = SessionStatus.TEMPORARILY_LIMITED
    service = AuthService(settings)
    first = await service.login("x")
    assert first.status == SessionStatus.TEMPORARILY_LIMITED
    assert FakeBrowserBackend.login_calls == 1
    assert not service.allows_browser_login("x")
    assert not browser_login_permitted(AUTH_PLATFORMS["x"], first)
    second = await service.login("x")
    assert second.status == SessionStatus.TEMPORARILY_LIMITED
    assert FakeBrowserBackend.login_calls == 1
    assert not service.has_active("x")


@pytest.mark.asyncio
async def test_x_does_not_retry_after_oauth_browser_rejected(tmp_path) -> None:
    settings = _settings(tmp_path)
    FakeBrowserBackend.login_status["x"] = SessionStatus.OAUTH_BROWSER_REJECTED
    service = AuthService(settings)
    first = await service.login("x")
    assert first.status == SessionStatus.OAUTH_BROWSER_REJECTED
    assert FakeBrowserBackend.login_calls == 1
    assert OFFICIAL_API_SUGGESTION in first.notes
    assert ANONYMOUS_LOOKUP_UNAFFECTED in first.notes
    second = await service.login("x")
    assert second.status == SessionStatus.OAUTH_BROWSER_REJECTED
    assert FakeBrowserBackend.login_calls == 1


@pytest.mark.asyncio
async def test_instagram_browser_login_still_retries_after_captcha(tmp_path) -> None:
    settings = _settings(tmp_path)
    FakeBrowserBackend.login_status["instagram"] = SessionStatus.CAPTCHA_REQUIRED
    service = AuthService(settings)
    first = await service.login("instagram")
    assert first.status == SessionStatus.CAPTCHA_REQUIRED
    assert FakeBrowserBackend.login_calls == 1
    assert service.allows_browser_login("instagram")
    FakeBrowserBackend.login_status["instagram"] = SessionStatus.ACTIVE
    second = await service.login("instagram")
    assert second.status == SessionStatus.ACTIVE
    assert FakeBrowserBackend.login_calls == 2
    assert service.has_active("instagram")


@pytest.mark.asyncio
async def test_x_anonymous_username_lookup_unaffected_after_limited_login(tmp_path) -> None:
    settings = _settings(tmp_path)
    FakeBrowserBackend.login_status["x"] = SessionStatus.TEMPORARILY_LIMITED
    service = AuthService(settings)
    await service.login("x")
    assert not service.has_active("x")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Sign in to X", headers={"content-type": "text/html"})

    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    bundle = await analyze_username(
        entity,
        http,
        categories=["Social"],
        auth_service=service,
        result_cache=ResultCache(settings),
    )
    x_finding = next(f for f in bundle["findings"] if f.title == "X")
    assert x_finding.data["check_status"] == UsernameCheckStatus.LOGIN_REQUIRED.value
    assert x_finding.data["access_mode"] == AccessMode.ANONYMOUS_PUBLIC.value
    assert x_finding.data["check_status"] != "TEMPORARILY_LIMITED"
    assert x_finding.status.value != "PROVIDER_UNAVAILABLE"
    await http.close()


def test_cli_explains_oauth_rejection_and_official_api(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTRE_AUTH_DIR", str(tmp_path / "auth"))
    monkeypatch.setenv("SPECTRE_BROWSER_PROFILES_DIR", str(tmp_path / "browser-profiles"))
    monkeypatch.setenv("SPECTRE_BROWSER_BACKEND", "fake")
    monkeypatch.setenv("SPECTRE_KEYRING", "false")
    from spectre_osint.core.config import reload_settings

    reload_settings()
    FakeBrowserBackend.login_status["x"] = SessionStatus.OAUTH_BROWSER_REJECTED
    result = runner.invoke(app, ["--no-banner", "auth", "login", "x"])
    assert result.exit_code == 1
    assert "OAUTH_BROWSER_REJECTED" in result.stdout
    assert "does not hide automation" in result.stdout
    assert OFFICIAL_API_SUGGESTION in result.stdout
    assert ANONYMOUS_LOOKUP_UNAFFECTED in result.stdout
    again = runner.invoke(app, ["--no-banner", "auth", "login", "x"])
    assert again.exit_code == 1
    assert "Opening SPECTRE-owned" not in again.stdout
    assert FakeBrowserBackend.login_calls == 1
