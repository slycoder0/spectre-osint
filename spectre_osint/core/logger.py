"""Structured logging. API keys are never written; target data is never written (B2-07).

Logs go to `<logs_dir>/spectre-osint.log`. The terminal gets log lines only when the
operator asks for them (`--verbose` -> INFO, `--debug` -> DEBUG, both on stderr); by
default the terminal shows results, never logs (B2-06).

Versions before B2-07 wrote `<logs_dir>/spectre.log`, which may contain usernames,
profile URLs and other target data. That file is never opened, rewritten or deleted
here; `legacy_log_files()` lets `spectre doctor` point at it so the operator can decide.

What the formatter guarantees for every sink (file and terminal):

- secrets are masked (`redact_text`);
- tracebacks keep their frames but never the exception message (`str(exc)` of httpx,
  pydantic or OSError carries URLs, payload values and report paths);
- the investigation's registered target values are replaced by their `target_ref` in the
  message and traceback (a safety net behind the call-site rule; see `core/redaction.py`);
- a malformed call (`logger.warning("%s: %s", url)`) reports one line naming the logger
  and the error class, never Python's "Message: ... Arguments: (...)" dump;
- WARNING+ records of third-party libraries reach the log file through the same
  formatter, never raw on stderr; httpx / httpcore stay capped at WARNING.
"""

from __future__ import annotations

import logging
import sys
import traceback
from pathlib import Path
from types import TracebackType
from typing import TextIO

from spectre_osint.core.redaction import exc_label, redact_text, scrub_target_values

ROOT_LOGGER = "spectre"
LOG_FILENAME = "spectre-osint.log"
# Written by versions that could log target data. Never touched; reported by the doctor.
LEGACY_LOG_FILENAMES = ("spectre.log",)
# Third-party loggers that put full request URLs (and so usernames / investigated hosts)
# in INFO / DEBUG records. Capped so they stay silent even if a root handler appears.
_URL_ECHOING_LOGGERS = ("httpx", "httpcore")

# Library etiquette: with no configured handler, records are dropped instead of reaching
# Python's last-resort handler, which would print WARNINGs to stderr (doctor runs
# without `setup_logging()`).
logging.getLogger(ROOT_LOGGER).addHandler(logging.NullHandler())

_ExcInfo = tuple[type[BaseException], BaseException, TracebackType | None] | tuple[None, None, None]


def format_exception_without_messages(ei: _ExcInfo) -> str:
    """A traceback with every frame and exception class, and no exception message."""
    exc = ei[1]
    if exc is None:
        return ""
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        if current.__cause__ is not None:
            current = current.__cause__
        elif not current.__suppress_context__:
            current = current.__context__
        else:
            current = None
    parts: list[str] = []
    for index, item in enumerate(reversed(chain)):
        if index:
            parts.append("\nThe above exception led to the following one:\n\n")
        parts.append("Traceback (most recent call last):\n")
        parts.extend(traceback.format_tb(item.__traceback__))
        kind = type(item)
        name = kind.__qualname__ if kind.__module__ == "builtins" else f"{kind.__module__}.{kind.__qualname__}"
        parts.append(f"{name}: <message withheld>\n")
    return "".join(parts).rstrip("\n")


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
        # Never reuse a traceback another formatter cached with its messages in it.
        record.exc_text = (
            scrub_target_values(self.formatException(record.exc_info)) if record.exc_info else None
        )
        # Scrub the message only: level, logger name and time stay readable even when a
        # target value happens to look like "info" or "spectre". The record is restored
        # afterwards so other handlers see what the call site logged.
        saved_msg, saved_args = record.msg, record.args
        try:
            record.msg = scrub_target_values(record.getMessage())
            record.args = None
            formatted = super().format(record)
        finally:
            record.msg, record.args = saved_msg, saved_args
        return redact_text(formatted)

    def formatException(self, ei: _ExcInfo) -> str:  # noqa: N802 — logging API name
        return format_exception_without_messages(ei)


def legacy_log_files(logs_dir: Path) -> list[Path]:
    """Log files left by earlier versions (they may contain target data). Read-only."""
    base = Path(logs_dir)
    return [base / name for name in LEGACY_LOG_FILENAMES if (base / name).is_file()]


class _QuietHandlerErrors:
    """`handleError` that names the logger and the error class, and nothing else.

    Python's `Handler.handleError` prints the record's message *and its arguments* to
    stderr when formatting fails (`logger.warning("%s failed: %s", url)`), which is the
    target data a malformed call site was about to log. One line, no traceback.
    """

    def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802 — logging API name
        if not logging.raiseExceptions or sys.stderr is None:
            return
        try:
            print("SPECTRE logging error in", record.name + ":", exc_label(sys.exc_info()[1]), file=sys.stderr)
        except Exception:  # noqa: BLE001, S110 — the error report must never raise
            pass


class _SpectreFileHandler(_QuietHandlerErrors, logging.FileHandler):
    """The log file handler."""


class _CurrentStderrHandler(_QuietHandlerErrors, logging.StreamHandler):
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


class _ThirdPartyToLogFile(_QuietHandlerErrors, logging.Handler):
    """On the root logger: WARNING+ records of other libraries go to SPECTRE's log file.

    Without a handler on the root, Python's last-resort handler prints them raw on stderr
    (a library warning can quote the URL it fetched). Here they pass through the
    `RedactingFormatter` of the file handler instead, and never reach the terminal.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)

    def emit(self, record: logging.LogRecord) -> None:
        if record.name == ROOT_LOGGER or record.name.startswith(ROOT_LOGGER + "."):
            return  # SPECTRE's own records have their handlers already
        for handler in logging.getLogger(ROOT_LOGGER).handlers:
            if isinstance(handler, logging.FileHandler) and record.levelno >= handler.level:
                handler.handle(record)


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
    for name in _URL_ECHOING_LOGGERS:
        noisy = logging.getLogger(name)
        if noisy.level < logging.WARNING:
            noisy.setLevel(logging.WARNING)
    root = logging.getLogger()
    if not any(isinstance(handler, _ThirdPartyToLogFile) for handler in root.handlers):
        root.addHandler(_ThirdPartyToLogFile())

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
        log_path = logs_dir / LOG_FILENAME
        file_handler: logging.FileHandler | None = None
        for handler in logger.handlers:
            if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename) == log_path.resolve():
                file_handler = handler
                break
        if file_handler is None:
            file_handler = _SpectreFileHandler(log_path, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        file_handler.setLevel(file_level)

    return logger


def _level(name: str | None) -> int:
    return int(getattr(logging, str(name or "INFO").upper(), logging.INFO))


def get_logger(name: str = ROOT_LOGGER) -> logging.Logger:
    return logging.getLogger(name)
