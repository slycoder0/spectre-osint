"""Phase 3A: `_cli_fail` prints a friendly, translated message per error type.

Never `str(exc)`: `SSRFBlocked` carries the blocked IP and host, httpx errors carry the
request URL, `ValidationError` carries the input, `OSError` carries report paths named
after the target. The terminal gets the error type (and `exc_label` when it helps).
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from spectre_osint.cli import commands
from spectre_osint.cli.commands import app
from spectre_osint.cli.errors import error_message
from spectre_osint.core.exceptions import (
    AuthError,
    CacheError,
    PathSafetyError,
    ProviderNotConfigured,
    ProviderUnavailable,
    RateLimitExceeded,
    SessionExpired,
    SSRFBlocked,
    TlsVerificationError,
    ValidationError,
)
from spectre_osint.core.i18n import set_language

runner = CliRunner()

SECRET_HOST = "alice-osint.example"
SECRET_IP = "10.20.30.40"
SECRET_URL = f"https://{SECRET_HOST}/u/alice_osint"


def _provider_unavailable_from_connect_error() -> ProviderUnavailable:
    try:
        try:
            raise httpx.ConnectError(f"connection failed for {SECRET_URL}")
        except httpx.ConnectError as inner:
            raise ProviderUnavailable(f"demo unavailable: {inner}") from inner
    except ProviderUnavailable as outer:
        return outer


CASES: list[tuple[BaseException, str, str]] = [
    (SSRFBlocked(f"blocked resolved address(es) {SECRET_IP} for {SECRET_HOST}"), "SSRF", "SSRF"),
    (ValidationError(f"Invalid email: alice@{SECRET_HOST}"), "--help", "--help"),
    (RateLimitExceeded(f"demo circuit open ({SECRET_HOST})"), "rate limit", "limite de requisições"),
    (TlsVerificationError(f"certificate verify failed for {SECRET_HOST}"), "TLS", "TLS"),
    (_provider_unavailable_from_connect_error(), "ConnectError", "ConnectError"),
    (httpx.ReadTimeout(f"timed out reading {SECRET_URL}"), "ReadTimeout", "ReadTimeout"),
    (ProviderNotConfigured(f"key missing for {SECRET_HOST}"), "spectre doctor", "spectre doctor"),
    (PathSafetyError(f"artifact escaped reports dir: C:/reports/{SECRET_HOST}.html"), "safety", "segurança"),
    (SessionExpired(f"session for {SECRET_HOST} expired"), "SessionExpired", "SessionExpired"),
    (AuthError(f"auth failed for {SECRET_HOST}"), "spectre auth status", "spectre auth status"),
    (CacheError(f"cache row for {SECRET_HOST} broken"), "CacheError", "CacheError"),
]


@pytest.mark.parametrize(("exc", "en_marker", "pt_marker"), CASES, ids=lambda v: type(v).__name__ if isinstance(v, BaseException) else None)
def test_error_message_names_the_error_type_never_its_text(exc: BaseException, en_marker: str, pt_marker: str) -> None:
    set_language("en")
    english = error_message(exc)
    set_language("pt-BR")
    portuguese = error_message(exc)
    for message in (english, portuguese):
        assert SECRET_HOST not in message
        assert SECRET_IP not in message
        assert "alice" not in message
        assert str(exc) not in message
    assert en_marker in english
    assert pt_marker in portuguese
    assert english != portuguese, "translated"


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SPECTRE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SPECTRE_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("SPECTRE_LOGS_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("SPECTRE_DATABASE_URL", f"sqlite:///{tmp_path / 't.db'}")
    from spectre_osint.core.config import reload_settings
    from spectre_osint.core.database import reset_engine

    reload_settings()
    reset_engine()
    yield
    reset_engine()
    reload_settings()


def _raise(exc: BaseException):
    async def fake(_request, **_kwargs):
        raise exc

    return fake


@pytest.mark.parametrize("lang", ["en", "pt-BR"])
def test_ssrf_block_does_not_print_the_ip_or_host(isolated, monkeypatch, lang) -> None:
    exc = SSRFBlocked(f"blocked resolved address(es) {SECRET_IP} for {SECRET_HOST}")
    monkeypatch.setattr(commands, "run_investigation", _raise(exc))
    result = runner.invoke(app, ["--lang", lang, "username", "alice_osint"])
    assert result.exit_code == 1
    assert SECRET_IP not in result.stderr
    assert SECRET_HOST not in result.stderr
    assert result.stderr.startswith("Error: " if lang == "en" else "Erro: ")
    assert "SSRF" in result.stderr
    assert result.stdout.strip() == ""


def test_connect_error_does_not_print_the_url(isolated, monkeypatch) -> None:
    monkeypatch.setattr(commands, "run_investigation", _raise(_provider_unavailable_from_connect_error()))
    result = runner.invoke(app, ["username", "alice_osint"])
    assert result.exit_code == 1
    assert SECRET_URL not in result.stderr
    assert SECRET_HOST not in result.stderr
    assert "ConnectError" in result.stderr


def test_raw_httpx_error_is_a_friendly_message_not_a_traceback(isolated, monkeypatch) -> None:
    monkeypatch.setattr(commands, "run_investigation", _raise(httpx.ConnectError(f"boom {SECRET_URL}")))
    result = runner.invoke(app, ["username", "alice_osint"])
    assert result.exit_code == 1
    assert SECRET_HOST not in result.stderr
    assert "Traceback" not in result.stderr
    assert "ConnectError" in result.stderr


def test_filesystem_error_does_not_print_the_report_path(isolated, monkeypatch) -> None:
    exc = PermissionError(13, "Access is denied", f"C:/reports/{SECRET_HOST}.html")
    monkeypatch.setattr(commands, "run_investigation", _raise(exc))
    result = runner.invoke(app, ["--lang", "pt-BR", "username", "alice_osint"])
    assert result.exit_code == 1
    assert SECRET_HOST not in result.stderr
    assert "PermissionError" in result.stderr
    assert "spectre doctor" in result.stderr
    assert result.stderr.startswith("Erro: ")


def test_bootstrap_storage_error_is_translated(isolated, monkeypatch) -> None:
    def broken(*_args, **_kwargs):
        raise PermissionError(13, "denied", f"C:/logs/{SECRET_HOST}")

    monkeypatch.setattr(commands, "configure_cli_logging", broken)
    result = runner.invoke(app, ["--lang", "pt-BR", "username", "alice_osint"])
    assert result.exit_code == 1
    assert SECRET_HOST not in result.stderr
    assert "PermissionError" in result.stderr
    assert "SPECTRE_DATA_DIR" in result.stderr
    assert result.stderr.startswith("Erro: ")


def test_bootstrap_database_error_is_translated(isolated, monkeypatch) -> None:
    from sqlalchemy.exc import OperationalError

    def broken(*_args, **_kwargs):
        raise OperationalError(f"INSERT INTO cases VALUES ('{SECRET_HOST}')", {}, Exception("disk I/O error"))

    monkeypatch.setattr(commands, "init_db", broken)
    result = runner.invoke(app, ["username", "alice_osint"])
    assert result.exit_code == 1
    assert SECRET_HOST not in result.stderr
    assert "INSERT" not in result.stderr
    assert "OperationalError" in result.stderr
    assert "SPECTRE_DATABASE_URL" in result.stderr


def test_cli_fail_never_formats_str_exc() -> None:
    """Static guard: every `_cli_fail(...)` argument is built from catalog text."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(commands))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_cli_fail"
    ]
    assert len(calls) >= 6
    for call in calls:
        for sub in ast.walk(call):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                assert sub.func.id not in {"str", "repr", "format"}, ast.unparse(call)
            assert not isinstance(sub, ast.JoinedStr), ast.unparse(call)
