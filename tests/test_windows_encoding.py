"""Windows/WSL process output must never be decoded as implicit UTF-8."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from typer.testing import CliRunner

from spectre_osint.browser import chrome as chrome_mod
from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.chrome import (
    _coerce_path,
    _parse_windows_home_output,
    _userprofile_via_cmd,
    decode_windows_bytes,
    run_capture_bytes,
    to_windows_path,
    windows_userprofile,
    windows_userprofile_from_host,
)
from spectre_osint.cli.commands import app
from spectre_osint.core.config import Settings

runner = CliRunner()


def _settings(tmp_path: Path, *, chrome_profiles_dir: Path | None = None) -> Settings:
    s = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        auth_dir=tmp_path / "auth",
        browser_profiles_dir=tmp_path / "browser-profiles",
        chrome_profiles_dir=chrome_profiles_dir,
        browser_backend="fake",
        keyring_enabled=False,
    )
    s.ensure_dirs()
    return s


def test_run_capture_bytes_never_uses_text_true() -> None:
    source = inspect.getsource(run_capture_bytes)
    assert "text=False" in source
    assert "text=True" not in source
    cmd_src = inspect.getsource(_userprofile_via_cmd)
    assert "text=True" not in cmd_src
    host_src = inspect.getsource(windows_userprofile_from_host)
    assert "text=True" not in host_src


def test_decode_utf8_stdout() -> None:
    assert "C:\\Users\\Operador" in decode_windows_bytes(b"C:\\Users\\Operador\r\n")


def test_decode_cp1252_stdout() -> None:
    raw = "C:\\Users\\José\r\n".encode("cp1252")
    assert "José" in decode_windows_bytes(raw)


def test_decode_cp850_oem_stdout() -> None:
    raw = "C:\\Users\\José\r\n".encode("cp850")
    assert decode_windows_bytes(raw).startswith("C:\\Users\\")
    assert "Jos" in decode_windows_bytes(raw)


def test_decode_stderr_non_utf8_does_not_raise() -> None:
    junk = bytes([0xC6, 0x92, 0xE3, 0x0D, 0x0A])
    text = decode_windows_bytes(junk)
    assert isinstance(text, str)


def test_decode_invalid_bytes_never_raises() -> None:
    blob = bytes(range(256)) + b"\xff\xfe\x00\xc6"
    text = decode_windows_bytes(blob)
    assert isinstance(text, str)
    assert decode_windows_bytes(None) == ""
    assert decode_windows_bytes(b"") == ""


def test_parse_home_ignores_oem_stderr() -> None:
    stdout = b"C:\\Users\\Operador\r\n"
    stderr = bytes([0xC6, 0x0D, 0x0A])
    path = _parse_windows_home_output(stdout, stderr)
    assert path is not None
    assert path == Path("/mnt/c/Users/Operador") or str(path).endswith("Operador")


def test_wsl_path_conversion_non_ascii(monkeypatch) -> None:
    monkeypatch.setattr(chrome_mod, "is_windows", lambda: False)
    converted = _coerce_path("C:\\Users\\José")
    assert converted.as_posix() == "/mnt/c/Users/José"
    win = to_windows_path(Path("/mnt/c/Users/José/.spectre/chrome/x"))
    assert win == "C:\\Users\\José\\.spectre\\chrome\\x"


def test_to_windows_path_normalization() -> None:
    # A) /mnt/c/... -> C:\...
    assert to_windows_path(Path("/mnt/c/Users/TestOperator/file.txt")) == "C:\\Users\\TestOperator\\file.txt"
    # B) \mnt\c\... -> C:\...
    assert to_windows_path("\\mnt\\c\\Users\\TestOperator\\file.txt") == "C:\\Users\\TestOperator\\file.txt"
    # C) drive D
    assert to_windows_path(Path("/mnt/d/data/file.txt")) == "D:\\data\\file.txt"
    # D) Unicode José
    assert to_windows_path(Path("/mnt/c/Users/José/.spectre/chrome/x")) == "C:\\Users\\José\\.spectre\\chrome\\x"
    # E) C:\... remains native
    assert to_windows_path("C:\\Users\\TestOperator\\file.txt") == "C:\\Users\\TestOperator\\file.txt"
    # F) /home/... is not falsely converted
    assert to_windows_path("/home/user/file.txt") == "/home/user/file.txt"


def _force_cmd_only(monkeypatch) -> None:
    monkeypatch.setattr(chrome_mod, "is_wsl", lambda: True)
    monkeypatch.setattr(chrome_mod, "is_windows", lambda: False)

    def find(names: tuple[str, ...], fallbacks: tuple[str, ...]) -> Path | None:
        if "powershell.exe" in names:
            return None
        if "cmd.exe" in names:
            return Path("/mnt/c/Windows/System32/cmd.exe")
        return None

    monkeypatch.setattr(chrome_mod, "_find_windows_exe", find)


def test_cmd_utf8_userprofile(monkeypatch) -> None:
    _force_cmd_only(monkeypatch)

    def run(argv: list[str], timeout: float = 5.0) -> tuple[int, bytes, bytes]:
        return 0, b"C:\\Users\\Operador\r\n", b""

    monkeypatch.setattr(chrome_mod, "run_capture_bytes", run)
    path = windows_userprofile_from_host()
    assert path == Path("/mnt/c/Users/Operador")


def test_cmd_cp1252_and_oem_stderr(monkeypatch) -> None:
    _force_cmd_only(monkeypatch)

    def run(argv: list[str], timeout: float = 5.0) -> tuple[int, bytes, bytes]:
        stdout = "C:\\Users\\José\r\n".encode("cp1252")
        stderr = bytes([0xC6, 0x92, 0x0D, 0x0A])
        return 0, stdout, stderr

    monkeypatch.setattr(chrome_mod, "run_capture_bytes", run)
    path = _userprofile_via_cmd()
    assert path is not None
    assert "José" in str(path)


def test_cmd_cp850_oem(monkeypatch) -> None:
    _force_cmd_only(monkeypatch)

    def run(argv: list[str], timeout: float = 5.0) -> tuple[int, bytes, bytes]:
        return 0, "C:\\Users\\José\r\n".encode("cp850"), b"\xc6\r\n"

    monkeypatch.setattr(chrome_mod, "run_capture_bytes", run)
    path = windows_userprofile_from_host()
    assert path is not None
    assert "Users" in path.as_posix()


def test_powershell_utf8_preferred(monkeypatch) -> None:
    monkeypatch.setattr(chrome_mod, "is_wsl", lambda: True)
    monkeypatch.setattr(chrome_mod, "is_windows", lambda: False)
    calls: list[list[str]] = []

    def find(names: tuple[str, ...], fallbacks: tuple[str, ...]) -> Path | None:
        if "powershell.exe" in names:
            return Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
        return Path("/mnt/c/Windows/System32/cmd.exe")

    def run(argv: list[str], timeout: float = 5.0) -> tuple[int, bytes, bytes]:
        calls.append(list(argv))
        if "powershell.exe" in argv[0].lower() or "powershell" in argv[0].lower():
            return 0, b"C:\\Users\\Operador\n", b""
        raise AssertionError("cmd.exe should not run when PowerShell succeeds")

    monkeypatch.setattr(chrome_mod, "_find_windows_exe", find)
    monkeypatch.setattr(chrome_mod, "run_capture_bytes", run)
    path = windows_userprofile_from_host()
    assert path == Path("/mnt/c/Users/Operador")
    assert any("GetFolderPath" in " ".join(c) for c in calls)


def test_subprocess_failure_returns_fallback(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(chrome_mod, "is_wsl", lambda: True)
    monkeypatch.setattr(chrome_mod, "is_windows", lambda: False)
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.delenv("SPECTRE_WINDOWS_USERPROFILE", raising=False)
    monkeypatch.setattr(chrome_mod, "windows_userprofile_from_host", lambda: None)
    monkeypatch.setattr(chrome_mod, "_wsl_users_fallback", lambda: Path("/mnt/c/Users/Fallback"))
    settings = _settings(tmp_path, chrome_profiles_dir=None)
    settings.windows_userprofile = None
    assert windows_userprofile(settings) == Path("/mnt/c/Users/Fallback")


def test_run_capture_bytes_failure_none(monkeypatch) -> None:
    def boom(*_a, **_k):
        raise OSError("nope")

    monkeypatch.setattr(chrome_mod.subprocess, "run", boom)
    assert run_capture_bytes(["cmd.exe"]) is None

    def decode_boom(*_a, **_k):
        raise UnicodeDecodeError("utf-8", b"\xc6", 0, 1, "reason")

    monkeypatch.setattr(chrome_mod.subprocess, "run", decode_boom)
    assert run_capture_bytes(["cmd.exe"]) is None


def test_windows_userprofile_swallows_unicode_error(monkeypatch) -> None:
    monkeypatch.setattr(chrome_mod, "is_wsl", lambda: True)
    monkeypatch.setattr(chrome_mod, "is_windows", lambda: False)
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.delenv("SPECTRE_WINDOWS_USERPROFILE", raising=False)

    def explode() -> Path | None:
        raise UnicodeDecodeError("utf-8", b"\xc6", 0, 1, "cmd")

    monkeypatch.setattr(chrome_mod, "windows_userprofile_from_host", explode)
    monkeypatch.setattr(chrome_mod, "_wsl_users_fallback", lambda: Path("/mnt/c/Users/Safe"))
    settings = Settings(windows_userprofile=None, chrome_profiles_dir=None)
    assert windows_userprofile(settings) == Path("/mnt/c/Users/Safe")


def test_auth_clear_idempotent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTRE_AUTH_DIR", str(tmp_path / "auth"))
    monkeypatch.setenv("SPECTRE_BROWSER_PROFILES_DIR", str(tmp_path / "browser-profiles"))
    monkeypatch.setenv("SPECTRE_CHROME_PROFILES_DIR", str(tmp_path / "chrome-profiles"))
    monkeypatch.setenv("SPECTRE_BROWSER_BACKEND", "fake")
    monkeypatch.setenv("SPECTRE_KEYRING", "false")
    from spectre_osint.core.config import reload_settings

    reload_settings()
    first = runner.invoke(app, ["--no-banner", "auth", "clear", "x"])
    assert first.exit_code == 0
    assert "Local SPECTRE session cleared." in first.stdout
    assert "Browser profile removed or already absent." in first.stdout
    assert "Personal Chrome untouched." in first.stdout
    second = runner.invoke(app, ["--no-banner", "auth", "clear", "tiktok"])
    assert second.exit_code == 0
    assert "Local SPECTRE session cleared." in second.stdout
    third = runner.invoke(app, ["--no-banner", "auth", "clear", "x"])
    assert third.exit_code == 0


@pytest.mark.asyncio
async def test_chrome_login_and_clear_survive_oem_cmd(tmp_path: Path, monkeypatch) -> None:
    """Same root cause as auth clear / CHROME_CDP_SESSION: cmd.exe OEM bytes."""
    monkeypatch.setattr(chrome_mod, "is_wsl", lambda: True)
    monkeypatch.setattr(chrome_mod, "is_windows", lambda: False)
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.delenv("SPECTRE_WINDOWS_USERPROFILE", raising=False)

    def find(names: tuple[str, ...], fallbacks: tuple[str, ...]) -> Path | None:
        if "powershell.exe" in names:
            return Path("/fake/powershell.exe")
        return Path("/fake/cmd.exe")

    def run(argv: list[str], timeout: float = 5.0) -> tuple[int, bytes, bytes]:
        stdout = "C:\\Users\\Operador\r\n".encode("cp1252")
        stderr = bytes([0xC6, 0x92, 0x0D, 0x0A])
        return 0, stdout, stderr

    monkeypatch.setattr(chrome_mod, "_find_windows_exe", find)
    monkeypatch.setattr(chrome_mod, "run_capture_bytes", run)
    settings = _settings(tmp_path, chrome_profiles_dir=None)
    settings.windows_userprofile = None
    home = windows_userprofile(settings)
    assert home == Path("/mnt/c/Users/Operador")
    isolated = _settings(tmp_path, chrome_profiles_dir=tmp_path / "chrome-profiles")
    service = AuthService(isolated)
    service.logout("tiktok")
    service.logout("x")
    profile = await service.login("tiktok", browser="chrome")
    assert profile.status is not None
    service.logout("tiktok")
