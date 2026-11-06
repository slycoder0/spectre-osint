"""Log sinks and target data (B2-07): file name, tracebacks, safety net, legacy logs.

- New logs go to `spectre-osint.log`; `spectre.log` from earlier versions (which may hold
  target data) is never opened, rewritten or deleted, and `spectre doctor` points at it.
- Tracebacks keep their frames but never the exception message.
- Registered target values are scrubbed from the message, not from the level / logger
  name, and the record itself is left untouched for other handlers.
- Third-party loggers that echo request URLs (httpx, httpcore) are capped at WARNING.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from spectre_osint.cli import doctor as doctor_mod
from spectre_osint.cli.commands import app
from spectre_osint.cli.doctor import OK, OPTIONAL, render_doctor, run_doctor
from spectre_osint.core.i18n import set_language
from spectre_osint.core.logger import (
    LEGACY_LOG_FILENAMES,
    LOG_FILENAME,
    get_logger,
    legacy_log_files,
    setup_logging,
)
from spectre_osint.core.redaction import (
    clear_target_values,
    register_target_values,
    target_ref,
    target_scope,
)


@pytest.fixture(autouse=True)
def _restore_spectre_logger():
    logger = logging.getLogger("spectre")
    saved = (list(logger.handlers), logger.level, logger.propagate)
    clear_target_values()
    yield
    for handler in logger.handlers:
        if handler not in saved[0]:
            handler.close()
    logger.handlers[:] = saved[0]
    logger.setLevel(saved[1])
    logger.propagate = saved[2]
    clear_target_values()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_new_logs_go_to_a_new_file_and_the_legacy_file_is_untouched(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    legacy = logs / "spectre.log"
    legacy.write_text("2026-01-01 | INFO | spectre.http | url=https://github.com/alice_osint\n", encoding="utf-8")
    before = (legacy.read_bytes(), legacy.stat().st_mtime_ns)

    setup_logging("INFO", logs)
    get_logger("spectre.http").warning("provider=demo status=429")

    assert LOG_FILENAME == "spectre-osint.log"
    assert "status=429" in _read(logs / LOG_FILENAME)
    assert (legacy.read_bytes(), legacy.stat().st_mtime_ns) == before


def test_legacy_log_files_lists_only_existing_old_logs_and_creates_nothing(tmp_path: Path) -> None:
    missing = tmp_path / "nowhere"
    assert legacy_log_files(missing) == []
    assert not missing.exists()
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / LOG_FILENAME).write_text("new\n", encoding="utf-8")
    assert legacy_log_files(logs) == []
    for name in LEGACY_LOG_FILENAMES:
        (logs / name).write_text("old\n", encoding="utf-8")
    assert legacy_log_files(logs) == [logs / name for name in LEGACY_LOG_FILENAMES]


def test_tracebacks_keep_frames_but_withhold_exception_messages(tmp_path: Path) -> None:
    setup_logging("DEBUG", tmp_path / "logs")
    user = "alice" + "_osint"  # kept out of the source line the traceback prints
    try:
        try:
            raise KeyError(user)
        except KeyError as inner:
            raise ValueError(f"cannot parse https://github.com/{user} for {user}@example.com") from inner
    except ValueError:
        get_logger("spectre.pipeline").debug("progress callback failed", exc_info=True)
    text = _read(tmp_path / "logs" / LOG_FILENAME)
    assert "progress callback failed" in text
    assert "Traceback (most recent call last)" in text
    assert "ValueError" in text and "KeyError" in text
    assert "test_tracebacks_keep_frames_but_withhold_exception_messages" in text
    assert "alice" not in text


def test_safety_net_scrubs_registered_values_from_the_message_only(tmp_path: Path) -> None:
    register_target_values("warning_alice", "Alice Example")
    setup_logging("INFO", tmp_path / "logs")
    seen: list[logging.LogRecord] = []

    class Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record)

    logging.getLogger("spectre").addHandler(Keep())
    get_logger("spectre.username").warning("leaky user=%s name=%s", "WARNING_ALICE", "alice example")
    text = _read(tmp_path / "logs" / LOG_FILENAME)
    assert "| WARNING |" in text
    assert f"user={target_ref('warning_alice')}" in text
    assert "alice" not in text.casefold()
    assert seen and seen[0].getMessage() == "leaky user=WARNING_ALICE name=alice example"


def test_safety_net_scrubs_tracebacks_too(tmp_path: Path) -> None:
    register_target_values("alice_osint")
    setup_logging("DEBUG", tmp_path / "logs")

    # A frame whose *source line* names the value as a standalone word (the safety net
    # only replaces delimited occurrences; an identifier that merely contains it is code).
    def helper() -> None:
        raise RuntimeError("boom")  # looked up alice_osint

    try:
        helper()
    except RuntimeError:
        get_logger("spectre").debug("failed", exc_info=True)
    assert "alice_osint" not in _read(tmp_path / "logs" / LOG_FILENAME)


@pytest.mark.parametrize("console_level", [None, "INFO"], ids=["file-only", "file-and-terminal"])
def test_a_malformed_log_call_never_prints_its_arguments(
    console_level: str | None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Python's Handler.handleError prints "Message: ... Arguments: (...)" on stderr."""
    sentinel = "https://github.com/" + "alice" + "_osint"
    setup_logging("INFO", tmp_path / "logs", console_level=console_level)
    get_logger("spectre.canary").warning("%s failed: %s", sentinel)  # one argument short
    err = capsys.readouterr().err
    assert "alice_osint" not in err
    assert "Arguments" not in err
    assert "SPECTRE logging error in spectre.canary: TypeError" in err


def test_third_party_warnings_go_to_the_log_file_redacted_and_never_raw_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A library logger outside `spectre.*` has no handler; with none on the root either,
    Python's last-resort handler prints its WARNINGs raw on stderr."""
    monkeypatch.setattr(logging.getLogger(), "handlers", [])  # production: no root handler
    setup_logging("INFO", tmp_path / "logs")
    library = logging.getLogger("thirdparty.lib")
    with target_scope():
        register_target_values("alice_osint")
        library.warning("lib saw https://github.com/%s token=SPECTRE_CANARY_SECRET_abc123", "alice_osint")
        library.info("lib chatter about alice_osint")
    err = capsys.readouterr().err
    assert "alice_osint" not in err
    assert "SPECTRE_CANARY_SECRET" not in err
    text = _read(tmp_path / "logs" / LOG_FILENAME)
    assert "| WARNING | thirdparty.lib | lib saw https://github.com/t:" in text
    assert "alice_osint" not in text
    assert "SPECTRE_CANARY_SECRET_abc123" not in text
    assert "lib chatter" not in text  # below WARNING


def test_url_echoing_third_party_loggers_are_capped_at_warning(tmp_path: Path) -> None:
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.NOTSET)
    setup_logging("DEBUG", tmp_path / "logs", console_level="DEBUG")
    for name in ("httpx", "httpcore"):
        assert logging.getLogger(name).getEffectiveLevel() >= logging.WARNING
        assert not logging.getLogger(name).isEnabledFor(logging.INFO)


def test_crash_tracebacks_never_print_local_variables() -> None:
    """A crash's Rich traceback with locals would print `target`, inputs and settings.
    Typer 0.27 defaults to False; the CLI pins it so an upgrade cannot flip it."""
    assert app.pretty_exceptions_show_locals is False
    assert app.pretty_exceptions_short is True


# --- doctor --------------------------------------------------------------------------------


def _legacy_checks(report: dict) -> list[dict[str, str]]:
    return [item for item in report["checks"] if item["label"] == "Legacy logs"]


def test_doctor_reports_no_legacy_logs(settings) -> None:
    (checks,) = [_legacy_checks(run_doctor(settings))]
    assert len(checks) == 1
    assert checks[0]["state"] == OK
    assert checks[0]["value"] == "none"
    set_language("en")
    assert "Legacy logs" not in render_doctor(run_doctor(settings))


def test_doctor_points_at_legacy_logs_without_touching_them(settings) -> None:
    legacy = Path(settings.logs_dir) / "spectre.log"
    legacy.write_text("old line with alice_osint\n", encoding="utf-8")
    before = legacy.stat().st_mtime_ns
    report = run_doctor(settings)
    (check,) = _legacy_checks(report)
    assert check["state"] == OPTIONAL
    assert check["group"] == "security"
    assert check["value"] == str(legacy)
    assert check["hint"]
    set_language("en")
    text = render_doctor(report)
    assert f"Legacy logs: {legacy} — " in text
    assert "may contain target data" in text
    assert "alice_osint" not in text
    set_language("pt-BR")
    assert "pode conter dados do alvo" in render_doctor(report)
    assert legacy.exists() and legacy.stat().st_mtime_ns == before
    assert report["ready"] is True


def test_cli_doctor_shows_the_legacy_log_line(settings, monkeypatch: pytest.MonkeyPatch) -> None:
    (Path(settings.logs_dir) / "spectre.log").write_text("old\n", encoding="utf-8")
    monkeypatch.setattr("spectre_osint.cli.doctor.run_doctor", lambda: run_doctor(settings))
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "Legacy logs" in result.stdout
    assert os.fspath(Path(settings.logs_dir) / "spectre.log") in result.stdout


def test_doctor_tables_know_the_new_strings() -> None:
    assert "Legacy logs" in doctor_mod._LABEL_KEYS
    assert any("target data" in hint for hint in doctor_mod._HINT_KEYS)
