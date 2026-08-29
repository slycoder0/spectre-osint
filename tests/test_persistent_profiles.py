"""Persistent SPECTRE Chromium profiles. Tests never open a real X login."""

from __future__ import annotations

import inspect
import stat
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.fake import FakeBrowserBackend
from spectre_osint.browser.login_flow import (
    GOTO_HOME,
    GOTO_LOGIN,
    STOP,
    SUCCESS,
    WAIT,
    classify_browser_state,
    next_login_action,
)
from spectre_osint.browser.manager import PlaywrightBackend
from spectre_osint.browser.models import AUTH_PLATFORMS
from spectre_osint.browser.userdata import (
    assert_spectre_owned_profile,
    ensure_platform_profile,
    platform_profile_dir,
    wipe_platform_profile,
)
from spectre_osint.cli.commands import app
from spectre_osint.core.config import Settings
from spectre_osint.core.exceptions import PathSafetyError
from spectre_osint.core.types import SessionStatus

runner = CliRunner()
COOKIE = "TESTCOOKIE_NOT_A_REAL_SESSION"


def _settings(tmp_path: Path) -> Settings:
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


def test_persistent_profile_dir_created_with_restricted_mode(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    path = ensure_platform_profile(settings, "x")
    assert path == tmp_path / "browser-profiles" / "x"
    assert path.is_dir()
    assert (path / ".spectre-owned").is_file()
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_platforms_are_isolated(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    insta = ensure_platform_profile(settings, "instagram")
    x_dir = ensure_platform_profile(settings, "x")
    twitch = ensure_platform_profile(settings, "twitch")
    assert insta != x_dir != twitch
    assert insta.name == "instagram"
    assert x_dir.name == "x"
    (insta / "marker-insta").write_text("instagram-only")
    assert not (x_dir / "marker-insta").exists()


def test_refuses_personal_chrome_profile(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    root = settings.resolved_browser_profiles_dir
    with pytest.raises(PathSafetyError):
        assert_spectre_owned_profile(Path.home() / ".config" / "google-chrome" / "Default", root)
    chrome_root = tmp_path / "google" / "chrome"
    chrome_root.mkdir(parents=True)
    with pytest.raises(PathSafetyError):
        assert_spectre_owned_profile(chrome_root / "instagram", chrome_root)


def test_polling_does_not_navigate_again() -> None:
    spec = AUTH_PLATFORMS["x"]
    first = next_login_action(
        spec,
        url="about:blank",
        cookies=[],
        visible_text="",
        visited_login=False,
        visited_home=False,
    )
    assert first.kind == GOTO_LOGIN
    assert first.navigate_to == spec.login_url
    waiting = next_login_action(
        spec,
        url=spec.login_url,
        cookies=[],
        visible_text="Sign in to X",
        visited_login=True,
        visited_home=False,
    )
    assert waiting.kind == WAIT
    assert waiting.navigate_to is None
    still = next_login_action(
        spec,
        url=spec.login_url,
        cookies=[],
        visible_text="Phone, email, or username",
        visited_login=True,
        visited_home=False,
    )
    assert still.kind == WAIT
    assert still.navigate_to is None


def test_already_authenticated_detects_active() -> None:
    spec = AUTH_PLATFORMS["x"]
    cookies = [{"name": "auth_token", "value": COOKIE}, {"name": "ct0", "value": COOKIE}]
    home = next_login_action(
        spec,
        url="about:blank",
        cookies=cookies,
        visible_text="",
        visited_login=False,
        visited_home=False,
    )
    assert home.kind == GOTO_HOME
    assert home.navigate_to == spec.home_url
    done = next_login_action(
        spec,
        url="https://x.com/home",
        cookies=cookies,
        visible_text="Home",
        visited_login=False,
        visited_home=True,
    )
    assert done.kind == SUCCESS
    assert done.status == SessionStatus.ACTIVE


def test_temporarily_limited_detected() -> None:
    spec = AUTH_PLATFORMS["x"]
    action = next_login_action(
        spec,
        url=spec.login_url,
        cookies=[],
        visible_text="We've temporarily limited your login. Please try again later.",
        visited_login=True,
        visited_home=False,
    )
    assert action.kind == STOP
    assert action.status == SessionStatus.TEMPORARILY_LIMITED
    assert action.navigate_to is None
    assert (
        classify_browser_state(
            spec,
            spec.login_url,
            "We've temporarily limited your login. Please try again later.",
        )
        is SessionStatus.TEMPORARILY_LIMITED
    )


def test_challenge_captcha_blocked_from_visible_text() -> None:
    spec = AUTH_PLATFORMS["instagram"]
    captcha = next_login_action(
        spec,
        url=spec.login_url,
        cookies=[],
        visible_text="please complete the captcha recaptcha",
        visited_login=True,
        visited_home=False,
    )
    assert captcha.status == SessionStatus.CAPTCHA_REQUIRED
    challenge = next_login_action(
        spec,
        url="https://www.instagram.com/",
        cookies=[],
        visible_text="checkpoint challenge required",
        visited_login=True,
        visited_home=False,
    )
    assert challenge.status == SessionStatus.CHALLENGE_REQUIRED
    blocked = next_login_action(
        spec,
        url="https://www.instagram.com/",
        cookies=[],
        visible_text="account suspended",
        visited_login=True,
        visited_home=False,
    )
    assert blocked.status == SessionStatus.BLOCKED


@pytest.mark.asyncio
async def test_login_session_active_and_logout_wipes_profile(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    profile = await service.login("x")
    assert profile.status == SessionStatus.ACTIVE
    x_dir = platform_profile_dir(settings, "x")
    assert x_dir.is_dir()
    stored = service.store.load_state("x")
    assert stored is not None
    assert COOKIE in str(stored)
    service.logout("x")
    assert service.store.load_state("x") is None
    assert not x_dir.exists()
    assert service.store.load_profile("x") is None


@pytest.mark.asyncio
async def test_temporarily_limited_login_is_not_active(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    FakeBrowserBackend.login_status["x"] = SessionStatus.TEMPORARILY_LIMITED
    service = AuthService(settings)
    profile = await service.login("x")
    assert profile.status == SessionStatus.TEMPORARILY_LIMITED
    assert service.store.load_state("x") is None
    assert not service.has_active("x")
    assert platform_profile_dir(settings, "x").is_dir()


@pytest.mark.asyncio
async def test_expired_session_status(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    await service.login("instagram")
    FakeBrowserBackend.verify_status["instagram"] = SessionStatus.EXPIRED
    profile = await service.verify("instagram")
    assert profile.status == SessionStatus.EXPIRED


def test_playwright_login_does_not_reload_or_snapshot_dom() -> None:
    source = inspect.getsource(PlaywrightBackend.interactive_login)
    observe = inspect.getsource(PlaywrightBackend._observe_login)
    combined = source + observe
    assert "launch_persistent_context" in combined
    assert "new_context()" not in combined
    assert "await page.content(" not in combined
    assert ".reload(" not in combined
    assert "navigator.webdriver" not in combined
    assert "stealth" not in combined.lower()
    assert "bring_to_front" not in combined


def test_gitignore_and_reports_exclude_browser_profiles(tmp_path: Path) -> None:
    gitignore = Path(__file__).resolve().parents[1] / ".gitignore"
    text = gitignore.read_text(encoding="utf-8")
    assert "browser-profiles/" in text
    settings = _settings(tmp_path)
    ensure_platform_profile(settings, "facebook")
    reports = tmp_path / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    for path in reports.rglob("*"):
        assert "browser-profiles" not in str(path)
    db = tmp_path / "t.db"
    if db.exists():
        assert b"browser-profiles" not in db.read_bytes()


def test_no_password_or_cookie_in_cli_output(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTRE_AUTH_DIR", str(tmp_path / "auth"))
    monkeypatch.setenv("SPECTRE_BROWSER_PROFILES_DIR", str(tmp_path / "browser-profiles"))
    monkeypatch.setenv("SPECTRE_BROWSER_BACKEND", "fake")
    monkeypatch.setenv("SPECTRE_KEYRING", "false")
    from spectre_osint.core.config import reload_settings

    reload_settings()
    FakeBrowserBackend.login_status["x"] = SessionStatus.TEMPORARILY_LIMITED
    limited = runner.invoke(app, ["--no-banner", "auth", "login", "x"])
    assert limited.exit_code == 1
    assert "TEMPORARILY_LIMITED" in limited.stdout
    assert "will not retry" in limited.stdout
    assert "Use official API integration for this platform when available." in limited.stdout
    assert "Anonymous public username lookup is unaffected." in limited.stdout
    assert COOKIE not in limited.stdout
    assert "password" not in limited.stdout.lower() or "never" in limited.stdout.lower()
    FakeBrowserBackend.reset()
    ok = runner.invoke(app, ["--no-banner", "auth", "login", "instagram"])
    assert ok.exit_code == 0
    assert COOKIE not in ok.stdout
    assert "sessionid=" not in ok.stdout.lower()
    logout = runner.invoke(app, ["--no-banner", "auth", "logout", "instagram"])
    assert logout.exit_code == 0
    assert "Personal Chrome" in logout.stdout


def test_wipe_is_platform_scoped(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    ensure_platform_profile(settings, "tiktok")
    ensure_platform_profile(settings, "threads")
    wipe_platform_profile(settings, "tiktok")
    assert not platform_profile_dir(settings, "tiktok").exists()
    assert platform_profile_dir(settings, "threads").is_dir()
