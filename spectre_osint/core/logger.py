"""Structured logging. API keys are never written."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from spectre_osint.core.redaction import redact_text


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


def setup_logging(level: str = "INFO", logs_dir: Path | None = None) -> logging.Logger:
    logger = logging.getLogger("spectre")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    formatter = RedactingFormatter(
        fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler) for h in logger.handlers):
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(formatter)
        logger.addHandler(console)

    if logs_dir is not None:
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = logs_dir / "spectre.log"
        already = False
        for handler in logger.handlers:
            if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename) == log_path.resolve():
                already = True
                break
        if not already:
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "spectre") -> logging.Logger:
    return logging.getLogger(name)
