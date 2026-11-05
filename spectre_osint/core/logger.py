"""Structured logging. API keys are never written.

Logs go to `<logs_dir>/spectre.log`. The terminal gets log lines only when the operator
asks for them (`--verbose` -> INFO, `--debug` -> DEBUG, both on stderr); by default the
terminal shows results, never logs (B2-06).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TextIO

from spectre_osint.core.redaction import redact_text

ROOT_LOGGER = "spectre"

# Library etiquette: with no configured handler, records are dropped instead of reaching
# Python's last-resort handler, which would print WARNINGs to stderr (doctor runs
# without `setup_logging()`).
logging.getLogger(ROOT_LOGGER).addHandler(logging.NullHandler())


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact_text(str(v)) for k, v in record.args.items()}
            else:
                record.args = tuple(
                    redact_text(a) if isinstance(a, str) else a for a in record.args
                )
        original = super().format(record)
        return redact_text(original)


class _CurrentStderrHandler(logging.StreamHandler):
    """Writes to whatever `sys.stderr` is *now*, never to the stream seen at creation.

    CLI runners and test harnesses replace `sys.stderr` per invocation; a handler bound
    to an earlier object would write to a closed file.
    """

    def __init__(self) -> None:
        super().__init__(sys.stderr)

    @property
    def stream(self) -> TextIO:
        return sys.stderr

    @stream.setter
    def stream(self, _value: TextIO) -> None:
        return None


def _is_console_handler(handler: logging.Handler) -> bool:
    return isinstance(handler, logging.StreamHandler) and not isinstance(
        handler, logging.FileHandler
    )


def setup_logging(
    level: str = "INFO",
    logs_dir: Path | None = None,
    *,
    console_level: str | None = None,
) -> logging.Logger:
    """Configure the `spectre` logger. Idempotent; safe to call once per command.

    `level` is what reaches the log file. `console_level` adds a stderr handler at that
    threshold; None (the default) means no terminal output, and removes a terminal
    handler left by an earlier call in the same process. The logger itself sits at the
    more verbose of the two, so `--verbose` shows INFO even when the file is at WARNING,
    while each handler keeps its own threshold.
    """
    file_level = _level(level)
    logger = logging.getLogger(ROOT_LOGGER)
    logger.setLevel(min(file_level, _level(console_level)) if console_level else file_level)
    logger.propagate = False

    formatter = RedactingFormatter(
        fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    for handler in list(logger.handlers):
        if _is_console_handler(handler):
            logger.removeHandler(handler)
    if console_level:
        console = _CurrentStderrHandler()
        console.setLevel(_level(console_level))
        console.setFormatter(formatter)
        logger.addHandler(console)

    if logs_dir is not None:
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = logs_dir / "spectre.log"
        file_handler: logging.FileHandler | None = None
        for handler in logger.handlers:
            if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename) == log_path.resolve():
                file_handler = handler
                break
        if file_handler is None:
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        file_handler.setLevel(file_level)

    return logger


def _level(name: str | None) -> int:
    return int(getattr(logging, str(name or "INFO").upper(), logging.INFO))


def get_logger(name: str = ROOT_LOGGER) -> logging.Logger:
    return logging.getLogger(name)
