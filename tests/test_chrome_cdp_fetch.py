"""CHROME_CDP_SESSION verify/fetch uses the persistent Chrome profile, not storage_state."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.chrome import (
    COLLECTION_NO_WINDOW_FLAG,
    ensure_chrome_profile,
    is_personal_chrome_profile,
    write_devtools_active_port,
)
from spectre_osint.browser.fake import (
    FakeCdpBrowser,
    FakeCdpConnector,
    FakeCdpSession,
    FakeChromeLauncher,
)
from spectre_osint.browser.manager import ChromeCdpBackend, PlaywrightBackend
from spectre_osint.browser.models import AUTH_PLATFORMS, cdp_session_sentinel, is_cdp_session_state
from spectre_osint.cli.commands import app
from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.result_cache import ResultCache
from spectre_osint.core.types import (
    AccessMode,
    Confidence,
    EntityType,
    SessionStatus,
    UsernameCheckStatus,
)
from spectre_osint.modules.username.engine import analyze_username

runner = CliRunner()


def _settings(tmp_path: Path) -> Settings:
    s = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        auth_dir=tmp_path / "auth",
        browser_profiles_dir=tmp_path / "browser-profiles",
        chrome_profiles_dir=tmp_path / "chrome-profiles",
        browser_backend="fake",
        keyring_enabled=False,
    )
    s.ensure_dirs()
    return s


def _backend(settings: Settings) -> ChromeCdpBackend:
    return ChromeCdpBackend(settings, launcher=FakeChromeLauncher(), connector=FakeCdpConnector())


def _legacy_cdp_cookies() -> dict:
    return {
        "cookies": [
            {
                "name": "sessionid",
                "value": "legacy-chrome-cookie",
                "domain": ".tiktok.com",
                "path": "/",
                "sameSite": "Unspecified",
                "expires": "nope",
                "httpOnly": True,
            }
        ],
        "origins": [],
    }


@pytest.mark.asyncio
async def test_playwright_session_still_uses_storage_state(tmp_path: Path, monkeypatch) -> None:
    recorded: dict[str, object] = {}

    class FakePage:
        url = "https://www.instagram.com/alice_osint/"

        async def goto(self, url: str, wait_until: str = "domcontentloaded") -> object:
            del wait_until
            self.url = url
            return type("Resp", (), {"status": 200})()

        async def title(self) -> str:
            return "alice_osint"

        async def evaluate(self, _script: str) -> str:
            return "alice_osint Instagram public profile"

    class FakeContext:
        async def new_page(self) -> FakePage:
            return FakePage()

    class FakeBrowser:
        async def new_context(self, storage_state: object = None) -> FakeContext:
            recorded["storage_state"] = storage_state
            return FakeContext()

        async def close(self) -> None:
            recorded["closed"] = True

    class FakeChromium:
        async def launch(self, headless: bool = True) -> FakeBrowser:
            recorded["launch_headless"] = headless
            return FakeBrowser()

    class FakePlaywrightChromium:
        async def __aenter__(self) -> FakeChromium:
            return FakeChromium()

        async def __aexit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr("spectre_osint.browser.manager.PlaywrightChromium", FakePlaywrightChromium)
    state = {"cookies": [{"name": "sessionid", "value": "TESTCOOKIE_NOT_A_REAL_SESSION"}], "origins": []}
    outcome = await PlaywrightBackend(_settings(tmp_path)).fetch_public(
        AUTH_PLATFORMS["instagram"],
        "https://www.instagram.com/alice_osint/",
        state,
    )
    assert recorded["storage_state"] is state
    assert recorded["launch_headless"] is True
    assert outcome.status == UsernameCheckStatus.LIKELY.value


@pytest.mark.asyncio
async def test_chrome_cdp_never_calls_new_context_storage_state(tmp_path: Path, monkeypatch) -> None:
    async def boom(self: PlaywrightBackend, *args: object, **kwargs: object) -> None:
        del self, args, kwargs
        raise AssertionError("CHROME_CDP_SESSION must not use Playwright storage_state fetch")

    monkeypatch.setattr(PlaywrightBackend, "fetch_public", boom)
    settings = _settings(tmp_path)
    backend = _backend(settings)
    outcome = await backend.fetch_public(
        AUTH_PLATFORMS["tiktok"],
        "https://www.tiktok.com/@alice_osint",
        _legacy_cdp_cookies(),
    )
    assert FakeCdpBrowser.new_context_calls == []
    assert FakeCdpConnector.last_endpoint is not None
    assert FakeCdpConnector.last_endpoint.startswith("http://127.0.0.1:")
    assert outcome.status == UsernameCheckStatus.LIKELY.value


@pytest.mark.asyncio
async def test_chrome_cdp_connects_over_cdp_and_uses_existing_context(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    backend = _backend(settings)
    outcome = await backend.fetch_public_cdp(
        AUTH_PLATFORMS["tiktok"],
        "https://www.tiktok.com/@alice_osint",
        cdp_session_sentinel(AUTH_PLATFORMS["tiktok"]),
    )
    assert FakeCdpConnector.connect_calls >= 1
    assert FakeCdpConnector.last_endpoint is not None
    assert FakeCdpConnector.last_endpoint.startswith("http://127.0.0.1:")
    assert backend.last_used_existing_context is True
    assert FakeCdpConnector.last_browser is not None
    assert FakeCdpConnector.last_browser.contexts
    assert outcome.url == "https://www.tiktok.com/@alice_osint"
    assert FakeCdpBrowser.new_context_calls == []


@pytest.mark.asyncio
async def test_existing_valid_cdp_is_reused(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    write_devtools_active_port(profile, 9333, "/devtools/browser/fake")
    backend = _backend(settings)
    await backend.fetch_public_cdp(
        AUTH_PLATFORMS["tiktok"],
        "https://www.tiktok.com/@alice_osint",
        cdp_session_sentinel(AUTH_PLATFORMS["tiktok"]),
    )
    assert backend.last_cdp_reused is True
    assert backend.last_cdp_launched is False
    assert FakeChromeLauncher.spawned == []
    assert FakeCdpConnector.last_endpoint == "http://127.0.0.1:9333"


@pytest.mark.asyncio
async def test_chrome_is_launched_when_no_valid_endpoint(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    backend = _backend(settings)
    await backend.fetch_public_cdp(
        AUTH_PLATFORMS["tiktok"],
        "https://www.tiktok.com/@alice_osint",
        cdp_session_sentinel(AUTH_PLATFORMS["tiktok"]),
    )
    assert backend.last_cdp_reused is False
    assert backend.last_cdp_launched is True
    assert FakeChromeLauncher.spawned
    joined = " ".join(FakeChromeLauncher.spawned[0])
    assert "--remote-debugging-port=0" in joined
    assert "User Data" not in joined
    assert COLLECTION_NO_WINDOW_FLAG in FakeChromeLauncher.spawned[0]
    assert "about:blank" not in FakeChromeLauncher.spawned[0]
    assert "tiktok.com" not in joined
    assert backend.last_launch_minimized is True
    assert backend.last_created_page_closed is True
    assert FakeCdpBrowser.close_calls == 0
    assert "Page.bringToFront" not in [item[0] for item in FakeCdpSession.sent]


@pytest.mark.asyncio
async def test_verify_session_uses_cdp_backend_for_tiktok(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    logged = await service.login("tiktok", browser="chrome")
    assert logged.status == SessionStatus.ACTIVE
    assert is_cdp_session_state(service.store.load_state("tiktok"))
    FakeCdpConnector.last_endpoint = None
    FakeCdpBrowser.new_context_calls = []
    profile = await service.verify("tiktok")
    assert profile.status == SessionStatus.ACTIVE
    assert FakeCdpConnector.last_endpoint is not None
    assert FakeCdpConnector.last_endpoint.startswith("http://127.0.0.1:")
    assert FakeCdpBrowser.new_context_calls == []


@pytest.mark.asyncio
async def test_authenticated_public_fetch_uses_cdp_backend(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    await service.login("tiktok", browser="chrome")
    FakeCdpConnector.last_endpoint = None
    FakeCdpBrowser.new_context_calls = []
    outcome = await service.fetch_public_profile(
        "TikTok", "alice_osint", "https://www.tiktok.com/@alice_osint"
    )
    assert outcome is not None
    assert FakeCdpConnector.last_endpoint is not None
    assert FakeCdpBrowser.new_context_calls == []
    assert outcome.status == UsernameCheckStatus.LIKELY.value
    assert outcome.status != UsernameCheckStatus.CONFIRMED.value


@pytest.mark.asyncio
async def test_malformed_legacy_cdp_storage_state_does_not_crash(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    backend = _backend(settings)
    status = await backend.verify_session(AUTH_PLATFORMS["tiktok"], _legacy_cdp_cookies())
    assert status == SessionStatus.ACTIVE
    assert FakeCdpBrowser.new_context_calls == []
    garbage = {"cookies": "not-a-list", "origins": None, "backend": "CHROME_CDP_SESSION"}
    status2 = await backend.verify_session(AUTH_PLATFORMS["tiktok"], garbage)
    assert status2 == SessionStatus.ACTIVE
    assert FakeCdpBrowser.new_context_calls == []


@pytest.mark.asyncio
async def test_cdp_unavailable_maps_to_explicit_status(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    write_devtools_active_port(profile, 9333, "/devtools/browser/fake")
    FakeCdpConnector.fail_connect = True
    backend = _backend(settings)
    outcome = await backend.fetch_public_cdp(
        AUTH_PLATFORMS["tiktok"],
        "https://www.tiktok.com/@alice_osint",
        cdp_session_sentinel(AUTH_PLATFORMS["tiktok"]),
    )
    assert outcome.status == SessionStatus.CDP_UNAVAILABLE.value
    status = await backend.verify_session(
        AUTH_PLATFORMS["tiktok"], cdp_session_sentinel(AUTH_PLATFORMS["tiktok"])
    )
    assert status == SessionStatus.CDP_UNAVAILABLE


def test_cli_verify_cdp_unavailable_has_no_traceback(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTRE_AUTH_DIR", str(tmp_path / "auth"))
    monkeypatch.setenv("SPECTRE_BROWSER_PROFILES_DIR", str(tmp_path / "browser-profiles"))
    monkeypatch.setenv("SPECTRE_CHROME_PROFILES_DIR", str(tmp_path / "chrome-profiles"))
    monkeypatch.setenv("SPECTRE_BROWSER_BACKEND", "fake")
    monkeypatch.setenv("SPECTRE_KEYRING", "false")
    from spectre_osint.core.config import reload_settings

    reload_settings()
    login = runner.invoke(app, ["--no-banner", "auth", "login", "tiktok", "--browser", "chrome"])
    assert login.exit_code == 0
    FakeCdpConnector.fail_connect = True
    result = runner.invoke(app, ["--no-banner", "auth", "verify", "tiktok"])
    assert result.exit_code == 1
    assert "tiktok: CDP_UNAVAILABLE" in result.stdout
    assert "Invalid cookie fields" not in result.stdout
    assert "Protocol error" not in result.stdout
    assert not isinstance(result.exception, ConnectionError)


@pytest.mark.asyncio
async def test_cleanup_disconnects_without_deleting_profile(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    marker = profile / ".spectre-owned"
    backend = _backend(settings)
    await backend.fetch_public_cdp(
        AUTH_PLATFORMS["tiktok"],
        "https://www.tiktok.com/@alice_osint",
        cdp_session_sentinel(AUTH_PLATFORMS["tiktok"]),
    )
    assert profile.is_dir()
    assert marker.is_file()
    assert FakeCdpConnector.disconnected is True
    assert FakeCdpBrowser.close_calls == 0
    assert backend.last_disconnected is True
    assert backend.last_created_page_closed is True


@pytest.mark.asyncio
async def test_personal_chrome_profile_remains_rejected(tmp_path: Path) -> None:
    personal = tmp_path / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
    personal.mkdir(parents=True)
    assert is_personal_chrome_profile(personal) is True
    settings = _settings(tmp_path)
    backend = _backend(settings)
    await backend.fetch_public_cdp(
        AUTH_PLATFORMS["tiktok"],
        "https://www.tiktok.com/@alice_osint",
        cdp_session_sentinel(AUTH_PLATFORMS["tiktok"]),
    )
    assert FakeChromeLauncher.spawned
    joined = " ".join(FakeChromeLauncher.spawned[0])
    assert "User Data" not in joined
    spectre = ensure_chrome_profile(settings, "tiktok")
    assert is_personal_chrome_profile(spectre) is False
    assert spectre != personal


@pytest.mark.asyncio
async def test_instagram_playwright_verify_does_not_use_cdp(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    await service.login("instagram")
    FakeCdpConnector.last_endpoint = None
    FakeChromeLauncher.spawned = []
    profile = await service.verify("instagram")
    assert profile.status == SessionStatus.ACTIVE
    assert FakeCdpConnector.last_endpoint is None
    assert FakeChromeLauncher.spawned == []


@pytest.mark.asyncio
async def test_username_tiktok_authenticated_public_uses_cdp(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    await service.login("tiktok", browser="chrome")

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, text="Please log in to continue", headers={"content-type": "text/html"})

    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    bundle = await analyze_username(
        entity,
        http,
        categories=["Social"],
        auth_service=service,
        result_cache=ResultCache(settings),
    )
    tiktok = next(f for f in bundle["findings"] if f.title == "TikTok")
    assert tiktok.data["anonymous_status"] == "LOGIN_REQUIRED"
    assert tiktok.data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
    assert tiktok.data["check_status"] == UsernameCheckStatus.LIKELY.value
    assert tiktok.data["check_status"] != UsernameCheckStatus.CONFIRMED.value
    assert FakeCdpConnector.last_endpoint is not None
    assert FakeCdpBrowser.new_context_calls == []
    await http.close()


@pytest.mark.asyncio
async def test_two_consecutive_collections_reuse_spectre_chrome(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    backend = _backend(settings)
    url = "https://www.tiktok.com/@alice_osint"
    state = cdp_session_sentinel(AUTH_PLATFORMS["tiktok"])
    first = await backend.fetch_public_cdp(AUTH_PLATFORMS["tiktok"], url, state)
    assert backend.last_cdp_launched is True
    launched = len(FakeChromeLauncher.spawned)
    assert launched == 1
    second = await backend.fetch_public_cdp(AUTH_PLATFORMS["tiktok"], url, state)
    assert second.status == first.status
    assert backend.last_cdp_reused is True
    assert backend.last_cdp_launched is False
    assert len(FakeChromeLauncher.spawned) == launched


@pytest.mark.asyncio
async def test_manual_login_still_opens_visible_login_url(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    backend = _backend(settings)
    await backend.interactive_login(AUTH_PLATFORMS["tiktok"], timeout_s=1)
    assert FakeChromeLauncher.spawned
    joined = " ".join(FakeChromeLauncher.spawned[0])
    assert AUTH_PLATFORMS["tiktok"].login_url in joined
    assert COLLECTION_NO_WINDOW_FLAG not in FakeChromeLauncher.spawned[0]
    assert backend.last_launch_minimized is False


@pytest.mark.asyncio
async def test_browser_visible_collection_is_opt_in(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.browser_visible = True
    backend = _backend(settings)
    await backend.fetch_public_cdp(
        AUTH_PLATFORMS["tiktok"],
        "https://www.tiktok.com/@alice_osint",
        cdp_session_sentinel(AUTH_PLATFORMS["tiktok"]),
    )
    assert backend.last_cdp_launched is True
    assert backend.last_launch_minimized is False
    assert "https://www.tiktok.com/@alice_osint" in FakeChromeLauncher.spawned[0]
    assert COLLECTION_NO_WINDOW_FLAG not in FakeChromeLauncher.spawned[0]


@pytest.mark.asyncio
async def test_collection_closes_bootstrap_about_blank(tmp_path: Path) -> None:
    from spectre_osint.browser.fake import FakeCdpContext

    FakeCdpContext.bootstrap_url = "about:blank"
    settings = _settings(tmp_path)
    backend = _backend(settings)
    await backend.fetch_public_cdp(
        AUTH_PLATFORMS["tiktok"],
        "https://www.tiktok.com/@alice_osint",
        cdp_session_sentinel(AUTH_PLATFORMS["tiktok"]),
    )
    FakeCdpContext.bootstrap_url = None
    browser = FakeCdpConnector.last_browser
    assert browser is not None
    pages = list(browser.contexts[0].pages)
    leftover_blank = [p for p in pages if (p.url or "").startswith("about:")]
    leftover_target = [p for p in pages if "tiktok.com/@alice_osint" in (p.url or "")]
    assert leftover_target == []
    assert leftover_blank == []
    assert backend.last_created_page_closed is True
    assert backend.last_bootstrap_retained is False
    assert backend.last_pages_remaining == 0
    assert FakeCdpBrowser.close_calls == 0
    assert backend.last_minimized_via_cdp is True
    methods = [item[0] for item in FakeCdpSession.sent]
    assert "Browser.setWindowBounds" in methods
    assert "Page.bringToFront" not in methods
    assert all(
        (params.get("bounds") or {}).get("windowState") == "minimized"
        for method, params in FakeCdpSession.sent
        if method == "Browser.setWindowBounds"
    )


def _tiktok_fetch(backend: ChromeCdpBackend):
    return backend.fetch_public_cdp(
        AUTH_PLATFORMS["tiktok"],
        "https://www.tiktok.com/@alice_osint",
        cdp_session_sentinel(AUTH_PLATFORMS["tiktok"]),
    )


@pytest.mark.asyncio
async def test_collection_on_empty_context_closes_created_page(tmp_path: Path) -> None:
    from spectre_osint.browser.fake import FakeCdpContext, FakeCdpPage

    FakeCdpContext.start_urls = []
    FakeCdpConnector.persist_browser = True
    settings = _settings(tmp_path)
    backend = _backend(settings)
    await _tiktok_fetch(backend)
    browser = FakeCdpConnector.last_browser
    assert browser is not None
    assert list(browser.contexts[0].pages) == []
    assert backend.last_pages_before == 0
    assert backend.last_collection_page_created is True
    assert backend.last_created_page_closed is True
    assert backend.last_created_ids
    assert backend.last_closed_ids
    assert backend.last_pages_remaining == 0
    assert FakeCdpBrowser.close_calls == 0
    assert backend.last_disconnected is True
    assert all(page.closed for page in browser.contexts[0].spectre_pages)
    assert FakeCdpPage.closed_count >= 1


@pytest.mark.asyncio
async def test_collection_preserves_preexisting_operator_page(tmp_path: Path) -> None:
    from spectre_osint.browser.fake import FakeCdpContext

    operator = "https://www.tiktok.com/"
    FakeCdpContext.start_urls = [operator]
    FakeCdpConnector.persist_browser = True
    settings = _settings(tmp_path)
    backend = _backend(settings)
    await _tiktok_fetch(backend)
    browser = FakeCdpConnector.last_browser
    assert browser is not None
    pages = list(browser.contexts[0].pages)
    assert len(pages) == 1
    assert pages[0].url == operator
    assert pages[0].closed is False
    assert pages[0].created_by_spectre is False
    assert backend.last_pages_before == 1
    assert backend.last_collection_page_created is True
    assert backend.last_created_page_closed is True
    assert backend.last_pages_remaining == 1
    assert all(item.closed for item in browser.contexts[0].spectre_pages)
    leftover_blank = [p for p in pages if (p.url or "").startswith("about:")]
    assert leftover_blank == []
    assert FakeCdpBrowser.close_calls == 0
    assert backend.last_disconnected is True


@pytest.mark.asyncio
async def test_two_collections_do_not_accumulate_about_blank(tmp_path: Path) -> None:
    from spectre_osint.browser.fake import FakeCdpContext

    operator = "https://www.tiktok.com/"
    FakeCdpContext.start_urls = [operator]
    FakeCdpConnector.persist_browser = True
    settings = _settings(tmp_path)
    backend = _backend(settings)
    first = await _tiktok_fetch(backend)
    after_first = list(FakeCdpConnector.last_browser.contexts[0].pages)  # type: ignore[union-attr]
    second = await _tiktok_fetch(backend)
    browser = FakeCdpConnector.last_browser
    assert browser is not None
    pages = list(browser.contexts[0].pages)
    assert second.status == first.status
    assert backend.last_cdp_reused is True
    assert pages[0] is after_first[0]
    assert pages[0].closed is False
    assert pages[0].url == operator
    leftover_blank = [p for p in pages if (p.url or "").startswith("about:")]
    assert leftover_blank == []
    assert len(pages) == 1
    assert FakeCdpBrowser.close_calls == 0
    assert backend.last_disconnected is True


@pytest.mark.asyncio
async def test_cdp_page_debug_has_counts_not_urls(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("DEBUG", logger="spectre.browser")
    settings = _settings(tmp_path)
    backend = _backend(settings)
    await _tiktok_fetch(backend)
    lines = [rec.getMessage() for rec in caplog.records if rec.getMessage().startswith("cdp pages before=")]
    assert lines
    message = lines[-1]
    assert "created=" in message
    assert "closed=" in message
    assert "remaining=" in message
    assert "http" not in message.lower()
    assert "about:blank" not in message
    assert "cookie" not in message.lower()
