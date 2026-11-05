"""Versioned OSINT result cache: a payload derived by older code is never served.

Regression for the PR #17 report: `spectre username torvalds` run inside the repo showed
page titles ("torvalds - Codeberg.org", "Contact @torvalds", ...) as observed names. The
rows had been written by pre-B2-03B2 code; `ResultCache` keyed entries only by
`kind|provider|subject|access_mode`, so the stale `Finding.data` (top-level
`display_name` and an `observed.display_name` from `html_title` without `rejected_by`)
was served verbatim for the whole 6 h username TTL. Fixtures here rebuild that exact
row: the legacy table, the legacy key formula and the legacy payload shape.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from spectre_osint.core import result_cache as result_cache_mod
from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, InvestigationResult, utcnow
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.result_cache import RESULT_SCHEMA_VERSION, ResultCache
from spectre_osint.core.types import AccessMode, CacheState, Confidence, EntityType
from spectre_osint.modules.username.catalog import SiteDefinition
from spectre_osint.modules.username.engine import _check_site
from spectre_osint.services.views import build_username_view

HANDLE = "alice_osint"
PLATFORM = "Codeberg Synthetic"
MODE = AccessMode.ANONYMOUS_PUBLIC.value
TITLE = f"{HANDLE} - Codeberg.org"

_LEGACY_TABLE = (
    "CREATE TABLE IF NOT EXISTS results ("
    "key TEXT PRIMARY KEY, kind TEXT NOT NULL, provider TEXT NOT NULL, "
    "subject TEXT NOT NULL, access_mode TEXT NOT NULL, "
    "value TEXT NOT NULL, checked_at TEXT NOT NULL, expires_at REAL NOT NULL)"
)


def _settings(tmp_path: Path) -> Settings:
    settings = Settings(
        _env_file=None,
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
        http_max_retries=1,
    )
    settings.ensure_dirs()
    return settings


def _legacy_key(kind: str, provider: str, subject: str, access_mode: str) -> str:
    return hashlib.sha256(f"{kind}|{provider}|{subject}|{access_mode}".encode()).hexdigest()


def _pre_fix_payload() -> dict[str, Any]:
    """The shape pre-B2-03B2 enrichment cached: title as an active name, original inverted."""
    stamp = "2026-11-05T14:44:33.549501+00:00"
    return {
        "platform": PLATFORM,
        "site": PLATFORM,
        "username": HANDLE,
        "profile_url": f"https://codeberg.example/{HANDLE}",
        "final_url": f"https://codeberg.example/{HANDLE}",
        "display_name": TITLE,
        "observed": {
            "display_name": {
                "value": TITLE,
                "original": HANDLE,
                "source": "html_title",
                "observed_at": stamp,
                "provider_slug": "codeberg_synthetic",
                "source_method": "HTML",
                "source_url": f"https://codeberg.example/{HANDLE}",
            }
        },
        "check_status": "LIKELY",
        "verification_status": "LIKELY",
        "status": "LIKELY",
        "confidence": "MEDIUM",
        "checked_at": "2026-11-05T14:44:33.605560+00:00",
        "access_mode": MODE,
        "cache_state": "LIVE",
    }


def _write_legacy_row(settings: Settings, payload: dict[str, Any], *, ttl: float = 21600) -> Path:
    path = settings.cache_dir / "results.sqlite"
    with sqlite3.connect(path) as conn:
        conn.execute(_LEGACY_TABLE)
        conn.execute(
            "INSERT OR REPLACE INTO results(key, kind, provider, subject, access_mode, value, checked_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _legacy_key("username", PLATFORM, HANDLE, MODE),
                "username",
                PLATFORM,
                HANDLE,
                MODE,
                json.dumps(payload),
                str(payload["checked_at"]),
                time.time() + ttl,
            ),
        )
    return path


def _row_count(path: Path) -> int:
    with sqlite3.connect(path) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM results").fetchone()[0])


def _user_version(path: Path) -> int:
    with sqlite3.connect(path) as conn:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])


# --- the cache layer --------------------------------------------------------------------


def test_unversioned_legacy_row_is_never_served(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _write_legacy_row(settings, _pre_fix_payload())
    cache = ResultCache(settings)
    try:
        assert cache.get("username", PLATFORM, HANDLE, MODE) is None
    finally:
        cache.close()


def test_opening_the_cache_purges_rows_from_another_schema(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    path = _write_legacy_row(settings, _pre_fix_payload())
    assert _row_count(path) == 1
    ResultCache(settings).close()
    assert _row_count(path) == 0
    assert _user_version(path) == RESULT_SCHEMA_VERSION


def test_entries_survive_reopening_within_the_same_schema(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    cache = ResultCache(settings)
    cache.set("username", PLATFORM, HANDLE, {"check_status": "CONFIRMED"}, access_mode=MODE)
    cache.close()
    reopened = ResultCache(settings)
    try:
        hit = reopened.get("username", PLATFORM, HANDLE, MODE)
        assert hit is not None and hit.payload["check_status"] == "CONFIRMED"
    finally:
        reopened.close()


def test_bumping_the_schema_version_invalidates_existing_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    cache = ResultCache(settings)
    cache.set("username", PLATFORM, HANDLE, {"check_status": "CONFIRMED"}, access_mode=MODE)
    cache.close()
    monkeypatch.setattr(result_cache_mod, "RESULT_SCHEMA_VERSION", RESULT_SCHEMA_VERSION + 1)
    bumped = ResultCache(settings)
    try:
        assert bumped.get("username", PLATFORM, HANDLE, MODE) is None
        assert bumped.status() == []
    finally:
        bumped.close()


def test_schema_and_package_versions_are_part_of_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    base = ResultCache.make_key("username", PLATFORM, HANDLE, MODE)
    assert base != _legacy_key("username", PLATFORM, HANDLE, MODE)
    monkeypatch.setattr(result_cache_mod, "RESULT_SCHEMA_VERSION", RESULT_SCHEMA_VERSION + 1)
    assert ResultCache.make_key("username", PLATFORM, HANDLE, MODE) != base
    monkeypatch.setattr(result_cache_mod, "RESULT_SCHEMA_VERSION", RESULT_SCHEMA_VERSION)
    monkeypatch.setattr(result_cache_mod, "PACKAGE_VERSION", "9.9.9")
    assert ResultCache.make_key("username", PLATFORM, HANDLE, MODE) != base


def test_expired_rows_are_purged_on_open(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    cache = ResultCache(settings)
    cache.set("username", PLATFORM, HANDLE, {"check_status": "CONFIRMED"}, access_mode=MODE, ttl=-60)
    cache.close()
    path = settings.cache_dir / "results.sqlite"
    assert _row_count(path) == 1
    ResultCache(settings).close()
    assert _row_count(path) == 0


# --- end to end through the username engine ---------------------------------------------------


def _site() -> dict[str, Any]:
    return SiteDefinition.model_validate(
        {
            "name": PLATFORM,
            "category": "Development",
            "profile_url": "https://codeberg.example/{username}",
            "check_method": "generic_html",
            "confidence_strategy": "multi_signal",
            "expected_status": [200],
            "not_found_status": [404],
            "profile_markers": ["user-profile"],
            "success_patterns": ["user-profile"],
        }
    ).to_dict()


@pytest.mark.asyncio
async def test_stale_pre_fix_finding_is_rechecked_and_its_title_rejected(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _write_legacy_row(settings, _pre_fix_payload())
    calls: list[str] = []
    body = (
        f"<html><head><title>{TITLE}</title></head>"
        f'<body><div class="user-profile">{HANDLE}</div></body></html>'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text=body)

    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    cache = ResultCache(settings)
    entity = Entity.create(EntityType.USERNAME, HANDLE, "t", Confidence.CONFIRMED)
    try:
        res = await _check_site(entity, _site(), http, asyncio.Semaphore(2), result_cache=cache)
    finally:
        await http.close()
        cache.close()

    data = res["finding"].data
    assert calls, "the stale cached row must not short-circuit the live check"
    assert data["cache_state"] == CacheState.LIVE.value
    assert data["display_name"] is None
    assert data["observed"]["display_name"]["rejected_by"] == "page_title_unverified"
    assert data["observed"]["display_name"]["original"] == TITLE

    result = InvestigationResult(
        case_id="c",
        case_name="cache-regression",
        target=HANDLE,
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        findings=[res["finding"]],
    )
    assert build_username_view(result).names == ()
