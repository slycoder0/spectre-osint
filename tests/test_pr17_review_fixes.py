"""Regressions for the independent review of PR #17 (B2-06)."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from spectre_osint.cli import commands
from spectre_osint.cli.commands import app
from spectre_osint.cli.display import print_result
from spectre_osint.cli.render import clean_text
from spectre_osint.core import result_cache as result_cache_mod
from spectre_osint.core.config import Settings, reload_settings
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.logger import LOG_FILENAME, get_logger
from spectre_osint.core.result_cache import RESULT_SCHEMA_VERSION, ResultCache
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from tests.conftest import strip_ansi

runner = CliRunner()


def _result(target_type: EntityType, findings: list[Finding], target: str = "alice_osint") -> InvestigationResult:
    return InvestigationResult(
        case_id="c",
        case_name="review",
        target=target,
        target_type=target_type,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[Entity.create(target_type, target, "user", Confidence.CONFIRMED)],
        findings=findings,
    )


def _sweep() -> Finding:
    return Finding(
        module="username",
        title="Username sweep",
        status=FindingStatus.FOUND,
        summary="Checked 0 public sites",
        data={"checked": 0},
    )


# 1. Zero site findings must still print the compact view and its unverified line. ------------


def test_username_result_with_only_the_sweep_finding_stays_compact(capsys) -> None:
    print_result(_result(EntityType.USERNAME, [_sweep()]))
    out = strip_ansi(capsys.readouterr().out)
    assert out.splitlines()[0] == "alice_osint — 0 profiles found (sites checked: 0)"
    assert "[?] 0 not verified" in out.splitlines()
    assert "Findings" not in out


def test_sweep_finding_alone_triggers_the_compact_view_whatever_the_target_type(capsys) -> None:
    print_result(_result(EntityType.PERSON, [_sweep()], target="Alice Example"))
    assert "[?] 0 not verified" in strip_ansi(capsys.readouterr().out).splitlines()


def test_email_and_domain_keep_the_legacy_table(capsys) -> None:
    finding = Finding(module="email", title="Format", status=FindingStatus.FOUND, summary="valid format")
    print_result(_result(EntityType.EMAIL, [finding], target="alice@example.test"))
    out = strip_ansi(capsys.readouterr().out)
    assert "Findings" in out
    assert "not verified" not in out


# 2. First-open race: a stale reader must not delete rows another process just wrote. -----------


def _settings(tmp_path: Path) -> Settings:
    settings = Settings(
        _env_file=None,
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
    )
    settings.ensure_dirs()
    return settings


class _InterleavingConnection:
    """Runs `hook` right after the first `PRAGMA user_version` read returns."""

    def __init__(self, conn: sqlite3.Connection, hook: Any) -> None:
        self._conn = conn
        self._hook = hook

    def execute(self, sql: str, *args: Any) -> Any:
        cursor = self._conn.execute(sql, *args)
        if self._hook is not None and sql.strip().upper() == "PRAGMA USER_VERSION":
            hook, self._hook = self._hook, None
            rows = cursor.fetchall()
            hook()
            return _Rows(rows)
        return cursor

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


class _Rows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None


def test_first_open_race_does_not_delete_a_row_written_by_another_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    path = settings.cache_dir / "results.sqlite"
    with sqlite3.connect(path) as legacy:  # an unversioned cache: user_version 0
        legacy.execute(
            "CREATE TABLE results (key TEXT PRIMARY KEY, kind TEXT NOT NULL, provider TEXT NOT NULL, "
            "subject TEXT NOT NULL, access_mode TEXT NOT NULL, value TEXT NOT NULL, "
            "checked_at TEXT NOT NULL, expires_at REAL NOT NULL)"
        )
    key = ResultCache.make_key("username", "GitHub", "alice_osint", "ANONYMOUS_PUBLIC")
    pending: list[bool] = []
    real_connect = sqlite3.connect

    def other_process_finishes_its_init_and_writes() -> None:
        def write() -> None:
            with real_connect(path, timeout=0.05) as other:
                other.execute(f"PRAGMA user_version = {RESULT_SCHEMA_VERSION}")
                other.execute(
                    "INSERT OR REPLACE INTO results VALUES (?, 'username', 'GitHub', 'alice_osint', "
                    "'ANONYMOUS_PUBLIC', '{\"check_status\": \"CONFIRMED\"}', 'now', ?)",
                    (key, time.time() + 600),
                )

        try:
            write()
        except sqlite3.OperationalError:
            pending.append(True)  # locked by our transaction: it writes once we commit
            return
        pending.append(False)

    def connect(*args: Any, **kwargs: Any) -> Any:
        return _InterleavingConnection(real_connect(*args, **kwargs), other_process_finishes_its_init_and_writes)

    monkeypatch.setattr(result_cache_mod.sqlite3, "connect", connect)
    cache = ResultCache(settings)
    monkeypatch.setattr(result_cache_mod.sqlite3, "connect", real_connect)
    if pending == [True]:
        with real_connect(path) as other:
            other.execute(
                "INSERT OR REPLACE INTO results VALUES (?, 'username', 'GitHub', 'alice_osint', "
                "'ANONYMOUS_PUBLIC', '{\"check_status\": \"CONFIRMED\"}', 'now', ?)",
                (key, time.time() + 600),
            )
    try:
        hit = cache.get("username", "GitHub", "alice_osint", "ANONYMOUS_PUBLIC")
        assert hit is not None, "the other process's fresh row was deleted"
    finally:
        cache.close()


# 3 and 4. --verbose / --debug reach every command, whatever SPECTRE_LOG_LEVEL says. -------------


@pytest.fixture
def logs_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SPECTRE_LOGS_DIR", str(tmp_path / "logs"))
    reload_settings()
    return tmp_path / "logs"


def test_debug_flag_reaches_auth_commands(logs_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def status_rows(_self: Any) -> list[dict[str, Any]]:
        get_logger("spectre.auth").debug("auth-status-debug-probe")
        return []

    monkeypatch.setattr("spectre_osint.browser.auth.AuthService.status_rows", status_rows)
    quiet = runner.invoke(app, ["auth", "status"])
    assert quiet.exit_code == 0, quiet.output
    assert "auth-status-debug-probe" not in quiet.stderr
    loud = runner.invoke(app, ["--debug", "auth", "status"])
    assert loud.exit_code == 0, loud.output
    assert "auth-status-debug-probe" in loud.stderr


def test_verbose_shows_info_even_when_the_file_level_is_warning(
    logs_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SPECTRE_LOG_LEVEL", "WARNING")
    reload_settings()

    async def fake(request: Any, **_kwargs: Any) -> InvestigationResult:
        get_logger("spectre.http").info("verbose-info-probe")
        get_logger("spectre.http").warning("verbose-warning-probe")
        return _result(EntityType.USERNAME, [_sweep()], target=request.target)

    monkeypatch.setattr(commands, "run_investigation", fake)
    result = runner.invoke(app, ["--verbose", "username", "alice_osint"])
    assert result.exit_code == 0, result.output
    assert "verbose-info-probe" in result.stderr
    log = (logs_dir / LOG_FILENAME).read_text(encoding="utf-8")
    assert "verbose-warning-probe" in log
    assert "verbose-info-probe" not in log, "the log file keeps SPECTRE_LOG_LEVEL"


# 5. Unicode line and paragraph separators never split a rendered line. --------------------------


def test_clean_text_flattens_unicode_line_separators() -> None:
    assert clean_text("Alice Example") == "Alice Example"
    assert clean_text("Alice Example") == "Alice Example"
