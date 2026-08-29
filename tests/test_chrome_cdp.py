"""SPECTRE-owned Google Chrome CDP backend. Tests never open a real Chrome login."""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from spectre_osint.browser import chrome as chrome_mod
from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.chrome import (
    ProcessChromeLauncher,
    assert_spectre_chrome_profile,
    bind_loopback_port,
    build_chrome_command,
    build_powershell_start_process_argv,
    cdp_endpoint,
    chrome_profile_dir,
    chrome_search_paths,
    command_is_safe,
    ensure_chrome_profile,
    is_loopback_cdp_endpoint,
    is_personal_chrome_profile,
    is_wsl,
    preferred_cdp_port,
    should_launch_chrome_via_start_process,
    to_windows_path,
)
from spectre_osint.browser.fake import FakeBrowserBackend, FakeCdpConnector, FakeChromeLauncher
from spectre_osint.browser.manager import ChromeCdpBackend, PlaywrightBackend, resolve_browser_kind
from spectre_osint.browser.models import AUTH_PLATFORMS
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
        chrome_profiles_dir=tmp_path / "chrome-profiles",
        browser_backend="fake",
        keyring_enabled=False,
    )
    s.ensure_dirs()
    return s


def test_detect_wsl(monkeypatch) -> None:
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
    assert is_wsl() is True
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setenv("WSL_INTEROP", "/run/WSL/1_interop")
    assert is_wsl() is True


def test_windows_chrome_search_paths_include_common_installs_not_edge(tmp_path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
    monkeypatch.setenv("SPECTRE_WINDOWS_USERPROFILE", "/mnt/c/Users/TestOperator")
    paths = [str(p).replace("\\", "/").lower() for p in chrome_search_paths(settings)]
    assert any("google/chrome/application/chrome.exe" in p for p in paths)
    assert all("msedge" not in p and "/edge/" not in p for p in paths)


def test_spectre_chrome_profile_dir_isolated_and_restricted(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    x_dir = ensure_chrome_profile(settings, "x")
    tiktok_dir = ensure_chrome_profile(settings, "tiktok")
    assert x_dir == tmp_path / "chrome-profiles" / "x"
    assert tiktok_dir == tmp_path / "chrome-profiles" / "tiktok"
    assert x_dir != tiktok_dir
    assert (x_dir / ".spectre-owned").is_file()
    if sys.platform != "win32":
        assert stat.S_IMODE(x_dir.stat().st_mode) == 0o700
    (x_dir / "x-only").write_text("x")
    assert not (tiktok_dir / "x-only").exists()
    assert chrome_profile_dir(settings, "x") != chrome_profile_dir(settings, "instagram")


def test_refuses_personal_chrome_user_data(tmp_path: Path) -> None:
    personal = tmp_path / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
    personal.mkdir(parents=True)
    assert is_personal_chrome_profile(personal) is True
    with pytest.raises(PathSafetyError):
        assert_spectre_chrome_profile(personal, tmp_path / "chrome-profiles")


def test_chrome_command_line_is_loopback_and_non_default_profile(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "x")
    exe = Path("/mnt/c/Program Files/Google/Chrome/Application/chrome.exe")
    args = build_chrome_command(exe, profile, 9226, AUTH_PLATFORMS["x"].login_url)
    joined = " ".join(args)
    assert args[0] == str(exe)
    assert "--remote-debugging-address=127.0.0.1" in args
    assert "--remote-debugging-port=9226" in args
    assert any(a.startswith("--user-data-dir=") for a in args)
    assert "User Data" not in joined
    assert "0.0.0.0" not in joined
    assert "--disable-blink-features=AutomationControlled" not in joined
    assert "navigator.webdriver" not in joined
    assert AUTH_PLATFORMS["x"].login_url in args
    assert "--start-minimized" not in args
    assert command_is_safe(args) is True
    assert cdp_endpoint(9226) == "http://127.0.0.1:9226"
    assert is_loopback_cdp_endpoint("http://127.0.0.1:9226")
    assert not is_loopback_cdp_endpoint("http://0.0.0.0:9226")
    assert not is_loopback_cdp_endpoint("http://192.168.1.10:9226")
    win = to_windows_path(Path("/mnt/c/Users/TestOperator/.spectre/chrome/x"))
    assert win.startswith("C:\\")
    assert "\\.spectre\\chrome\\x" in win.replace("/", "\\")


def test_collection_chrome_command_is_minimized_blank(tmp_path: Path, monkeypatch) -> None:
    from spectre_osint.browser.chrome import COLLECTION_NO_WINDOW_FLAG, COLLECTION_START_URL

    monkeypatch.setattr(
        chrome_mod,
        "_find_windows_exe",
        lambda names, fallbacks: Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
    )
    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    exe = Path("/mnt/c/Program Files/Google/Chrome/Application/chrome.exe")
    args = build_chrome_command(exe, profile, 0, COLLECTION_START_URL, minimized=True)
    assert COLLECTION_NO_WINDOW_FLAG in args
    assert "about:blank" not in args
    assert "--headless" not in " ".join(args)
    assert AUTH_PLATFORMS["tiktok"].login_url not in args
    assert command_is_safe(args) is True
    ps_argv = build_powershell_start_process_argv(args)
    script = ps_argv[ps_argv.index("-Command") + 1]
    assert "-WindowStyle Hidden" in script
    assert COLLECTION_NO_WINDOW_FLAG in script


def test_bind_loopback_port_never_wildcard() -> None:
    port = bind_loopback_port(preferred_cdp_port("x"))
    assert port is not None
    assert 9222 <= port <= 9299


def test_wsl_start_process_command_uses_windows_chrome_not_interop_popen(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(chrome_mod, "is_wsl", lambda: True)
    monkeypatch.setattr(chrome_mod, "is_windows", lambda: False)
    monkeypatch.setattr(
        chrome_mod,
        "_find_windows_exe",
        lambda names, fallbacks: Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
    )
    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    exe = Path("/mnt/c/Program Files/Google/Chrome/Application/chrome.exe")
    chrome_cmd = build_chrome_command(exe, profile, 9225, AUTH_PLATFORMS["tiktok"].login_url)
    assert should_launch_chrome_via_start_process(chrome_cmd[0]) is True
    ps_argv = build_powershell_start_process_argv(chrome_cmd)
    assert ps_argv[0].lower().endswith("powershell.exe")
    assert "-Command" in ps_argv
    script = ps_argv[ps_argv.index("-Command") + 1]
    assert "Start-Process" in script
    assert "-FilePath" in script
    assert "-ArgumentList" in script
    assert "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" in script
    assert "--remote-debugging-address=127.0.0.1" in script
    assert "--remote-debugging-port=9225" in script
    assert "User Data" not in script
    assert AUTH_PLATFORMS["tiktok"].login_url in script
    assert "-WindowStyle Normal" in script
    assert not ps_argv[0].lower().endswith("chrome.exe")

    captured: list[list[str]] = []

    def run(argv: list[str], timeout: float = 15.0) -> tuple[int, bytes, bytes]:
        captured.append(list(argv))
        return 0, b"", b""

    monkeypatch.setattr(chrome_mod, "run_capture_bytes", run)

    def boom(*_a, **_k):
        raise AssertionError("WSL must not Popen chrome.exe")

    monkeypatch.setattr(chrome_mod.subprocess, "Popen", boom)
    ProcessChromeLauncher(settings).spawn(chrome_cmd)
    assert captured
    assert captured[0][0].lower().endswith("powershell.exe")
    assert "Start-Process" in captured[0][-1]


def test_native_linux_still_can_popen_non_windows_chrome(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(chrome_mod, "is_wsl", lambda: False)
    monkeypatch.setattr(chrome_mod, "is_windows", lambda: False)
    exe = Path("/usr/bin/google-chrome-stable")
    assert should_launch_chrome_via_start_process(exe) is False


def test_resolve_browser_kind_instagram_stays_playwright(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    assert resolve_browser_kind(AUTH_PLATFORMS["instagram"], "auto", settings) == "fake"
    assert resolve_browser_kind(AUTH_PLATFORMS["instagram"], "playwright", settings) == "fake"
    assert resolve_browser_kind(AUTH_PLATFORMS["x"], "chrome", settings) == "chrome"


@pytest.mark.asyncio
async def test_chrome_not_found(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    FakeChromeLauncher.executable = None
    backend = ChromeCdpBackend(settings, launcher=FakeChromeLauncher(), connector=FakeCdpConnector())
    outcome = await backend.interactive_login(AUTH_PLATFORMS["x"], timeout_s=1)
    assert outcome.status == SessionStatus.CHROME_NOT_FOUND
    assert FakeChromeLauncher.spawned == []


@pytest.mark.asyncio
async def test_cdp_unavailable(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    FakeChromeLauncher.wait_ok = False
    backend = ChromeCdpBackend(settings, launcher=FakeChromeLauncher(), connector=FakeCdpConnector())
    outcome = await backend.interactive_login(AUTH_PLATFORMS["tiktok"], timeout_s=1)
    assert outcome.status == SessionStatus.WINDOWS_CDP_LAUNCH_FAILED
    assert FakeChromeLauncher.last_endpoint is not None
    assert FakeChromeLauncher.last_endpoint.startswith("http://127.0.0.1:")


@pytest.mark.asyncio
async def test_chrome_profile_locked(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "x")
    (profile / "SingletonLock").write_text("locked")
    backend = ChromeCdpBackend(settings, launcher=FakeChromeLauncher(), connector=FakeCdpConnector())
    outcome = await backend.interactive_login(AUTH_PLATFORMS["x"], user_data_dir=profile, timeout_s=1)
    assert outcome.status == SessionStatus.CHROME_PROFILE_LOCKED
    assert FakeChromeLauncher.spawned == []


@pytest.mark.asyncio
async def test_connect_over_cdp_mocked_active_session(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    FakeBrowserBackend.login_status["x"] = SessionStatus.ACTIVE
    backend = ChromeCdpBackend(settings, launcher=FakeChromeLauncher(), connector=FakeCdpConnector())
    outcome = await backend.interactive_login(AUTH_PLATFORMS["x"], timeout_s=1)
    assert outcome.status == SessionStatus.ACTIVE
    assert outcome.storage_state is not None
    assert outcome.storage_state.get("backend") == "CHROME_CDP_SESSION"
    assert outcome.storage_state.get("cookies") == []
    assert COOKIE not in str(outcome.storage_state)
    assert FakeCdpConnector.last_endpoint is not None
    assert FakeCdpConnector.last_endpoint.startswith("http://127.0.0.1:")
    assert FakeChromeLauncher.spawned
    cmd = FakeChromeLauncher.spawned[0]
    assert "--remote-debugging-address=127.0.0.1" in cmd
    assert any("--user-data-dir=" in a for a in cmd)


@pytest.mark.asyncio
async def test_chrome_cdp_session_expired_timeout(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    FakeBrowserBackend.login_status["tiktok"] = SessionStatus.EXPIRED
    backend = ChromeCdpBackend(settings, launcher=FakeChromeLauncher(), connector=FakeCdpConnector())
    outcome = await backend.interactive_login(AUTH_PLATFORMS["tiktok"], timeout_s=0)
    assert outcome.status in {SessionStatus.EXPIRED, SessionStatus.LOGIN_REQUIRED}


@pytest.mark.asyncio
async def test_auth_service_chrome_browser_and_instagram_playwright(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    insta = await service.login("instagram")
    assert insta.status == SessionStatus.ACTIVE
    assert FakeChromeLauncher.spawned == []
    x = await service.login("x", browser="chrome")
    assert x.status == SessionStatus.ACTIVE
    assert FakeChromeLauncher.spawned
    assert service.has_active("instagram")
    assert service.has_active("x")
    service.logout("x")
    assert service.store.load_state("x") is None
    assert not chrome_profile_dir(settings, "x").exists()
    assert service.has_active("instagram")


def test_cli_chrome_flag_and_no_cookie_leak(tmp_path: Path, monkeypatch) -> None:
    from tests.conftest import strip_ansi

    monkeypatch.setenv("SPECTRE_AUTH_DIR", str(tmp_path / "auth"))
    monkeypatch.setenv("SPECTRE_BROWSER_PROFILES_DIR", str(tmp_path / "browser-profiles"))
    monkeypatch.setenv("SPECTRE_CHROME_PROFILES_DIR", str(tmp_path / "chrome-profiles"))
    monkeypatch.setenv("SPECTRE_BROWSER_BACKEND", "fake")
    monkeypatch.setenv("SPECTRE_KEYRING", "false")
    from spectre_osint.core.config import reload_settings

    reload_settings()
    help_login = runner.invoke(app, ["auth", "login", "--help"])
    assert help_login.exit_code == 0
    assert "--browser" in strip_ansi(help_login.stdout)
    result = runner.invoke(app, ["--no-banner", "auth", "login", "x", "--browser", "chrome"])
    assert result.exit_code == 0
    assert "Opening SPECTRE-owned Chrome profile..." in result.stdout
    assert "Log in manually." in result.stdout
    assert "SPECTRE will connect only after authentication." in result.stdout
    assert COOKIE not in result.stdout
    assert "sessionid=" not in result.stdout.lower()


def test_cli_chrome_not_found(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTRE_AUTH_DIR", str(tmp_path / "auth"))
    monkeypatch.setenv("SPECTRE_BROWSER_PROFILES_DIR", str(tmp_path / "browser-profiles"))
    monkeypatch.setenv("SPECTRE_CHROME_PROFILES_DIR", str(tmp_path / "chrome-profiles"))
    monkeypatch.setenv("SPECTRE_BROWSER_BACKEND", "fake")
    monkeypatch.setenv("SPECTRE_KEYRING", "false")
    from spectre_osint.core.config import reload_settings

    reload_settings()
    FakeChromeLauncher.executable = None
    gone = runner.invoke(app, ["--no-banner", "auth", "login", "tiktok", "--browser", "chrome"])
    assert gone.exit_code == 1
    assert "CHROME_NOT_FOUND" in gone.stdout
    assert COOKIE not in gone.stdout


def test_instagram_playwright_backend_untouched() -> None:
    assert isinstance(PlaywrightBackend(), PlaywrightBackend)
    assert AUTH_PLATFORMS["instagram"].preferred_browser == "playwright"
    assert AUTH_PLATFORMS["instagram"].auth_capability.value == "PLAYWRIGHT_SESSION"
