from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr

from spectre_osint.core.cache import ResponseCache
from spectre_osint.core.config import Settings
from spectre_osint.core.logger import setup_logging
from spectre_osint.core.redaction import redact_mapping, redact_text

CANARY = "SPECTRE_CANARY_SECRET_9f3a2c1b"


def test_redaction_strips_canary_and_query_key() -> None:
    assert CANARY not in redact_text(f"token={CANARY}")
    assert CANARY not in redact_text(f"https://api.example/?key={CANARY}&q=1")
    payload = redact_mapping({"api_key": CANARY, "nested": {"Authorization": CANARY}})
    assert CANARY not in str(payload)


def test_cache_and_logs_never_store_canary(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        virustotal_api_key=SecretStr(CANARY),
    )
    settings.ensure_dirs()
    cache = ResponseCache(settings)
    cache.set("k", {"url": f"https://x?key={CANARY}", "api_key": CANARY}, ttl=60)
    stored = cache.get("k")
    cache.close()
    blob = (settings.cache_dir / "cache.sqlite").read_bytes()
    assert CANARY.encode() not in blob
    assert stored is not None
    assert CANARY not in str(stored)
    logger = setup_logging("INFO", settings.logs_dir)
    logger.info("using key %s", CANARY)
    log_text = (settings.logs_dir / "spectre.log").read_text(encoding="utf-8")
    assert CANARY not in log_text
