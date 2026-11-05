"""Logs go to the log file only; the terminal gets them only on --verbose / --debug (B2-06)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from spectre_osint.core.logger import get_logger, setup_logging


def _console_handlers() -> list[logging.Handler]:
    return [
        handler
        for handler in logging.getLogger("spectre").handlers
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler)
    ]


@pytest.fixture(autouse=True)
def _restore_spectre_logger():
    logger = logging.getLogger("spectre")
    saved = (list(logger.handlers), logger.level, logger.propagate)
    yield
    logger.handlers[:] = saved[0]
    logger.setLevel(saved[1])
    logger.propagate = saved[2]


def test_default_setup_writes_the_file_and_not_the_terminal(tmp_path: Path, capsys) -> None:
    setup_logging("INFO", tmp_path / "logs")
    get_logger("spectre.http").warning("provider=demo host=example.test status=429")
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""
    assert _console_handlers() == []
    text = (tmp_path / "logs" / "spectre.log").read_text(encoding="utf-8")
    assert "status=429" in text


def test_console_level_opt_in_prints_to_stderr(tmp_path: Path, capsys) -> None:
    setup_logging("DEBUG", tmp_path / "logs", console_level="DEBUG")
    get_logger("spectre.http").debug("debug line for the operator")
    captured = capsys.readouterr()
    assert "debug line for the operator" in captured.err
    assert captured.out == ""


def test_console_level_filters_below_threshold(tmp_path: Path, capsys) -> None:
    setup_logging("DEBUG", tmp_path / "logs", console_level="INFO")
    log = get_logger("spectre.http")
    log.debug("hidden debug line")
    log.info("visible info line")
    captured = capsys.readouterr()
    assert "visible info line" in captured.err
    assert "hidden debug line" not in captured.err
    text = (tmp_path / "logs" / "spectre.log").read_text(encoding="utf-8")
    assert "hidden debug line" in text


def test_reconfiguring_without_console_removes_the_terminal_handler(tmp_path: Path, capsys) -> None:
    setup_logging("INFO", tmp_path / "logs", console_level="INFO")
    setup_logging("INFO", tmp_path / "logs")
    assert _console_handlers() == []
    get_logger("spectre").warning("after reconfigure")
    assert capsys.readouterr().err == ""


def test_repeated_console_setup_keeps_a_single_terminal_handler(tmp_path: Path) -> None:
    setup_logging("INFO", tmp_path / "logs", console_level="INFO")
    setup_logging("INFO", tmp_path / "logs", console_level="DEBUG")
    assert len(_console_handlers()) == 1


def test_terminal_handler_follows_the_current_stderr(tmp_path: Path, capsys) -> None:
    """CLI runners swap sys.stderr per invocation; a handler bound to an old stream would
    write to a closed file. The handler must always use the live sys.stderr."""
    setup_logging("INFO", tmp_path / "logs", console_level="INFO")
    capsys.readouterr()
    get_logger("spectre").warning("first")
    assert "first" in capsys.readouterr().err
    get_logger("spectre").warning("second")
    assert "second" in capsys.readouterr().err


def test_spectre_logger_has_a_null_handler_before_setup() -> None:
    """Without it, Python's last-resort handler prints WARNINGs to stderr whenever a
    command runs without `setup_logging()` (doctor, for example)."""
    assert any(isinstance(h, logging.NullHandler) for h in logging.getLogger("spectre").handlers)


def test_terminal_handler_still_redacts_secrets(tmp_path: Path, capsys) -> None:
    setup_logging("INFO", tmp_path / "logs", console_level="INFO")
    get_logger("spectre").warning("token=SPECTRE_CANARY_SECRET_abc123")
    err = capsys.readouterr().err
    assert "SPECTRE_CANARY_SECRET_abc123" not in err
