"""Attach-existing CDP, DevToolsActivePort, and failed Windows launches. No real Chrome."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.chrome import (
    DevToolsEndpoint,
    discard_stale_devtools_active_port,
    is_personal_chrome_profile,
    parse_devtools_active_port,
    probe_spectre_cdp,
    read_spectre_devtools_active_port,
    snapshot_spectre_devtools_active_port,
    stop_spectre_launched_chrome,
    wait_for_spectre_cdp_ready,
    wait_for_spectre_devtools_active_port,
    websocket_matches_devtools_endpoint,
    write_devtools_active_port,
    write_windows_chrome_launcher,
)
from spectre_osint.browser.fake import FakeBrowserBackend, FakeCdpConnector, FakeChromeLauncher
from spectre_osint.browser.manager import ChromeCdpBackend
from spectre_osint.browser.models import AUTH_PLATFORMS
from spectre_osint.cli.commands import app
from spectre_osint.core.config import Settings
from spectre_osint.core.exceptions import PathSafetyError
from spectre_osint.core.types import SessionStatus

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


def test_parse_devtools_active_port_and_malformed() -> None:
    ok = parse_devtools_active_port("9444\n/devtools/browser/abc\n")
    assert ok is not None
    assert ok.port == 9444
    assert "devtools" in ok.websocket_path
    assert parse_devtools_active_port("") is None
    assert parse_devtools_active_port("not-a-port\n/ws\n") is None
    assert parse_devtools_active_port("99999\n") is None
    assert parse_devtools_active_port("-1\n") is None


def test_devtools_port_zero_in_launch_command(tmp_path: Path) -> None:
    from spectre_osint.browser.chrome import build_chrome_command, ensure_chrome_profile

    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    exe = Path("/mnt/c/Program Files/Google/Chrome/Application/chrome.exe")
    args = build_chrome_command(exe, profile, 0, AUTH_PLATFORMS["tiktok"].login_url)
    assert "--remote-debugging-port=0" in args


def test_refuses_personal_devtools_file(tmp_path: Path) -> None:
    personal = tmp_path / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
    personal.mkdir(parents=True)
    (personal / "DevToolsActivePort").write_text("9222\n/ws\n")
    assert is_personal_chrome_profile(personal)
    with pytest.raises(PathSafetyError):
        read_spectre_devtools_active_port(personal)


def test_delayed_devtools_active_port(tmp_path: Path) -> None:
    from spectre_osint.browser.chrome import ensure_chrome_profile

    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    ticks = {"n": 0}

    def sleeper(_seconds: float) -> None:
        ticks["n"] += 1
        if ticks["n"] == 1:
            write_devtools_active_port(profile, 9411, "/devtools/browser/delayed")

    found = wait_for_spectre_devtools_active_port(profile, timeout_s=2.0, sleeper=sleeper)
    assert found is not None
    assert found.port == 9411


def test_endpoint_missing_is_not_attached(tmp_path: Path) -> None:
    from spectre_osint.browser.chrome import ensure_chrome_profile

    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "x")
    write_devtools_active_port(profile, 9555)
    assert probe_spectre_cdp(profile, http_ok=lambda *_a, **_k: False) is None


@pytest.mark.asyncio
async def test_attach_existing_spectre_cdp(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    from spectre_osint.browser.chrome import ensure_chrome_profile

    profile = ensure_chrome_profile(settings, "tiktok")
    write_devtools_active_port(profile, 9333, "/devtools/browser/fake")
    FakeChromeLauncher.wait_ok = True
    FakeBrowserBackend.login_status["tiktok"] = SessionStatus.ACTIVE
    backend = _backend(settings)
    outcome = await backend.interactive_login(
        AUTH_PLATFORMS["tiktok"], user_data_dir=profile, timeout_s=1, attach=True
    )
    assert outcome.status == SessionStatus.ACTIVE
    assert FakeChromeLauncher.spawned == []
    assert FakeCdpConnector.last_endpoint == "http://127.0.0.1:9333"


@pytest.mark.asyncio
async def test_locked_profile_with_cdp_is_reused(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    from spectre_osint.browser.chrome import ensure_chrome_profile

    profile = ensure_chrome_profile(settings, "tiktok")
    (profile / "SingletonLock").write_text("locked")
    write_devtools_active_port(profile, 9333)
    FakeBrowserBackend.login_status["tiktok"] = SessionStatus.ACTIVE
    outcome = await _backend(settings).interactive_login(
        AUTH_PLATFORMS["tiktok"], user_data_dir=profile, timeout_s=1
    )
    assert outcome.status == SessionStatus.ACTIVE
    assert FakeChromeLauncher.spawned == []


@pytest.mark.asyncio
async def test_locked_profile_without_cdp_is_locked(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    from spectre_osint.browser.chrome import ensure_chrome_profile

    profile = ensure_chrome_profile(settings, "tiktok")
    (profile / "SingletonLock").write_text("locked")
    FakeChromeLauncher.write_devtools_on_spawn = False
    FakeChromeLauncher.wait_ok = False
    outcome = await _backend(settings).interactive_login(
        AUTH_PLATFORMS["tiktok"], user_data_dir=profile, timeout_s=1
    )
    assert outcome.status == SessionStatus.CHROME_PROFILE_LOCKED
    assert FakeChromeLauncher.spawned == []
    assert "previous WSL launch" in (outcome.detail or "")


@pytest.mark.asyncio
async def test_attach_missing_endpoint(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    from spectre_osint.browser.chrome import ensure_chrome_profile

    profile = ensure_chrome_profile(settings, "x")
    FakeChromeLauncher.write_devtools_on_spawn = False
    outcome = await _backend(settings).interactive_login(
        AUTH_PLATFORMS["x"], user_data_dir=profile, timeout_s=1, attach=True
    )
    assert outcome.status == SessionStatus.CDP_UNAVAILABLE
    assert FakeChromeLauncher.spawned == []


@pytest.mark.asyncio
async def test_windows_cdp_launch_failure_and_helper_retry(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    FakeChromeLauncher.write_devtools_on_spawn = False
    FakeChromeLauncher.write_devtools_on_helper = True
    FakeChromeLauncher.wait_ok = True
    FakeBrowserBackend.login_status["tiktok"] = SessionStatus.ACTIVE
    from spectre_osint.browser.chrome import ensure_chrome_profile

    profile = ensure_chrome_profile(settings, "tiktok")
    outcome = await _backend(settings).interactive_login(
        AUTH_PLATFORMS["tiktok"], user_data_dir=profile, timeout_s=1
    )
    assert FakeChromeLauncher.helper_spawned == 1
    assert outcome.status == SessionStatus.ACTIVE
    spawned = FakeChromeLauncher.spawned[0]
    assert "--remote-debugging-port=0" in spawned


def test_cleanup_after_launch_failure(tmp_path: Path, monkeypatch) -> None:
    from spectre_osint.browser import chrome as chrome_mod
    from spectre_osint.browser.chrome import LAUNCH_PID_FILE, ensure_chrome_profile

    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    (profile / LAUNCH_PID_FILE).write_text("999001\n", encoding="ascii")
    calls: list[list[str]] = []

    def run(argv: list[str], timeout: float = 8.0) -> tuple[int, bytes, bytes]:
        calls.append(list(argv))
        return 0, b"", b""

    monkeypatch.setattr(chrome_mod, "_find_windows_exe", lambda names, fb: Path("/fake/powershell.exe"))
    monkeypatch.setattr(chrome_mod, "run_capture_bytes", run)
    assert stop_spectre_launched_chrome(profile) is True
    assert calls
    assert "Stop-Process" in calls[0][-1]
    assert "999001" in calls[0][-1]
    assert not (profile / LAUNCH_PID_FILE).exists()


def test_helper_script_has_no_secrets_and_refuses_personal_profile(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    ps1 = write_windows_chrome_launcher(settings)
    text = ps1.read_text(encoding="utf-8")
    assert "Start-Process" in text
    assert "password" not in text.lower() or "No passwords" in text
    assert "cookie" not in text.lower() or "No cookies" in text
    assert "User Data" in text
    assert "127.0.0.1" in text
    assert "--remote-debugging-port=0" in text
    cmd = ps1.with_suffix(".cmd")
    if not cmd.exists():
        cmd = ps1.with_name("Start-SpectreChrome.cmd")
    assert cmd.is_file()
    wrapper = cmd.read_text(encoding="utf-8")
    assert "password" not in wrapper.lower() or "No passwords" in wrapper


def test_cli_attach_flag(tmp_path: Path, monkeypatch) -> None:
    from tests.conftest import strip_ansi

    monkeypatch.setenv("SPECTRE_AUTH_DIR", str(tmp_path / "auth"))
    monkeypatch.setenv("SPECTRE_BROWSER_PROFILES_DIR", str(tmp_path / "browser-profiles"))
    monkeypatch.setenv("SPECTRE_CHROME_PROFILES_DIR", str(tmp_path / "chrome-profiles"))
    monkeypatch.setenv("SPECTRE_BROWSER_BACKEND", "fake")
    monkeypatch.setenv("SPECTRE_KEYRING", "false")
    from spectre_osint.core.config import reload_settings

    reload_settings()
    help_login = runner.invoke(app, ["auth", "login", "--help"])
    assert "--attach" in strip_ansi(help_login.stdout)
    result = runner.invoke(app, ["--no-banner", "auth", "login", "tiktok", "--browser", "chrome", "--attach"])
    assert result.exit_code == 1
    assert "CDP_UNAVAILABLE" in result.stdout or "attach" in result.stdout.lower()


def test_websocket_matches_current_devtools_endpoint() -> None:
    endpoint = DevToolsEndpoint(port=60584, websocket_path="/devtools/browser/58f745f1-b8a0-42e7-ac80-9233dcbaf06a")
    version = {
        "Browser": "Chrome/151.0.0.0",
        "webSocketDebuggerUrl": "ws://127.0.0.1:60584/devtools/browser/58f745f1-b8a0-42e7-ac80-9233dcbaf06a",
    }
    assert websocket_matches_devtools_endpoint(version, endpoint) is True
    stale = DevToolsEndpoint(port=54642, websocket_path="/devtools/browser/old")
    assert websocket_matches_devtools_endpoint(version, stale) is False
    assert websocket_matches_devtools_endpoint({"webSocketDebuggerUrl": "ws://192.168.1.9:60584/devtools/browser/x"}, endpoint) is False
    assert websocket_matches_devtools_endpoint({}, endpoint) is False


def test_stale_devtools_file_discarded_from_spectre_profile(tmp_path: Path) -> None:
    from spectre_osint.browser.chrome import DEVTOOLS_ACTIVE_PORT, ensure_chrome_profile

    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    write_devtools_active_port(profile, 54642, "/devtools/browser/old")
    stale = snapshot_spectre_devtools_active_port(profile)
    assert stale.exists is True
    assert stale.port == 54642
    assert discard_stale_devtools_active_port(profile) is True
    assert not (profile / DEVTOOLS_ACTIVE_PORT).exists()


def test_discard_stale_devtools_refuses_personal_profile(tmp_path: Path) -> None:
    personal = tmp_path / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
    personal.mkdir(parents=True)
    (personal / "DevToolsActivePort").write_text("54642\n/ws\n")
    with pytest.raises(PathSafetyError):
        snapshot_spectre_devtools_active_port(personal)
    with pytest.raises(PathSafetyError):
        discard_stale_devtools_active_port(personal)


def test_wait_cdp_ready_follows_port_change_54642_to_60584(tmp_path: Path) -> None:
    from spectre_osint.browser.chrome import ensure_chrome_profile

    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    write_devtools_active_port(profile, 54642, "/devtools/browser/old")
    stale = snapshot_spectre_devtools_active_port(profile)
    seen: list[int] = []

    def ready_check(endpoint: DevToolsEndpoint) -> bool:
        seen.append(endpoint.port)
        return endpoint.port == 60584

    ticks = {"n": 0}

    def sleeper(_seconds: float) -> None:
        ticks["n"] += 1
        if ticks["n"] == 1:
            write_devtools_active_port(
                profile, 60584, "/devtools/browser/58f745f1-b8a0-42e7-ac80-9233dcbaf06a"
            )

    found = wait_for_spectre_cdp_ready(
        profile,
        timeout_s=2.0,
        ignore=stale,
        ready_check=ready_check,
        sleeper=sleeper,
    )
    assert found is not None
    assert found.port == 60584
    assert 54642 not in seen
    assert seen == [60584]


def test_wait_cdp_ready_dead_port_not_frozen_without_ignore(tmp_path: Path) -> None:
    from spectre_osint.browser.chrome import ensure_chrome_profile

    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    write_devtools_active_port(profile, 54642, "/devtools/browser/old")
    seen: list[int] = []

    def ready_check(endpoint: DevToolsEndpoint) -> bool:
        seen.append(endpoint.port)
        return endpoint.port == 60584

    ticks = {"n": 0}

    def sleeper(_seconds: float) -> None:
        ticks["n"] += 1
        if ticks["n"] == 1:
            write_devtools_active_port(
                profile, 60584, "/devtools/browser/58f745f1-b8a0-42e7-ac80-9233dcbaf06a"
            )

    found = wait_for_spectre_cdp_ready(profile, timeout_s=2.0, ready_check=ready_check, sleeper=sleeper)
    assert found is not None
    assert found.port == 60584
    assert seen[0] == 54642
    assert 60584 in seen


def test_wait_cdp_ready_skips_malformed_then_accepts_valid(tmp_path: Path) -> None:
    from spectre_osint.browser.chrome import DEVTOOLS_ACTIVE_PORT, ensure_chrome_profile

    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    (profile / DEVTOOLS_ACTIVE_PORT).write_text("not-a-port\n/ws\n", encoding="utf-8")

    def ready_check(endpoint: DevToolsEndpoint) -> bool:
        return endpoint.port == 9411

    ticks = {"n": 0}

    def sleeper(_seconds: float) -> None:
        ticks["n"] += 1
        if ticks["n"] == 1:
            write_devtools_active_port(profile, 9411, "/devtools/browser/ok")

    found = wait_for_spectre_cdp_ready(profile, timeout_s=2.0, ready_check=ready_check, sleeper=sleeper)
    assert found is not None
    assert found.port == 9411


def test_wait_cdp_ready_delayed_file(tmp_path: Path) -> None:
    from spectre_osint.browser.chrome import ensure_chrome_profile

    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")

    def ready_check(endpoint: DevToolsEndpoint) -> bool:
        return endpoint.port == 9411

    ticks = {"n": 0}

    def sleeper(_seconds: float) -> None:
        ticks["n"] += 1
        if ticks["n"] == 1:
            write_devtools_active_port(profile, 9411, "/devtools/browser/delayed")

    found = wait_for_spectre_cdp_ready(profile, timeout_s=2.0, ready_check=ready_check, sleeper=sleeper)
    assert found is not None
    assert found.port == 9411


@pytest.mark.asyncio
async def test_launch_follows_stale_54642_to_live_60584(tmp_path: Path, monkeypatch) -> None:
    """Exact race: stale dead 54642 is present; Chrome later writes 60584; connect uses 60584."""
    from spectre_osint.browser import chrome as chrome_mod
    from spectre_osint.browser.chrome import ensure_chrome_profile

    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    write_devtools_active_port(profile, 54642, "/devtools/browser/old")
    FakeChromeLauncher.live_ports = {60584}
    FakeChromeLauncher.write_devtools_on_spawn = False
    FakeChromeLauncher.devtools_port = 60584
    FakeBrowserBackend.login_status["tiktok"] = SessionStatus.ACTIVE
    monkeypatch.setattr(chrome_mod, "discard_stale_devtools_active_port", lambda *_a, **_k: False)

    def sleeper(_seconds: float) -> None:
        write_devtools_active_port(
            profile, 60584, "/devtools/browser/58f745f1-b8a0-42e7-ac80-9233dcbaf06a"
        )

    monkeypatch.setattr(chrome_mod.time, "sleep", sleeper)
    outcome = await _backend(settings).interactive_login(
        AUTH_PLATFORMS["tiktok"], user_data_dir=profile, timeout_s=2
    )
    assert outcome.status == SessionStatus.ACTIVE
    assert FakeChromeLauncher.spawned
    assert FakeCdpConnector.last_endpoint == "http://127.0.0.1:60584"


@pytest.mark.asyncio
async def test_stale_dead_devtools_is_removed_then_new_port_used(tmp_path: Path) -> None:
    from spectre_osint.browser.chrome import DEVTOOLS_ACTIVE_PORT, ensure_chrome_profile

    settings = _settings(tmp_path)
    profile = ensure_chrome_profile(settings, "tiktok")
    write_devtools_active_port(profile, 54642, "/devtools/browser/old")
    FakeChromeLauncher.live_ports = {60584}
    FakeChromeLauncher.devtools_port = 60584
    FakeChromeLauncher.write_devtools_on_spawn = True
    FakeBrowserBackend.login_status["tiktok"] = SessionStatus.ACTIVE
    outcome = await _backend(settings).fetch_public_cdp(
        AUTH_PLATFORMS["tiktok"],
        "https://www.tiktok.com/@alice_osint",
        {},
    )
    assert outcome.status != SessionStatus.WINDOWS_CDP_LAUNCH_FAILED.value
    assert FakeChromeLauncher.spawned
    assert FakeCdpConnector.last_endpoint == "http://127.0.0.1:60584"
    current = (profile / DEVTOOLS_ACTIVE_PORT).read_text(encoding="utf-8")
    assert "60584" in current
    assert "54642" not in current


@pytest.mark.asyncio
async def test_auth_service_attach(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    from spectre_osint.browser.chrome import ensure_chrome_profile

    profile = ensure_chrome_profile(settings, "tiktok")
    write_devtools_active_port(profile, 9333)
    FakeBrowserBackend.login_status["tiktok"] = SessionStatus.ACTIVE
    service = AuthService(settings)
    result = await service.login("tiktok", browser="chrome", attach=True)
    assert result.status == SessionStatus.ACTIVE
