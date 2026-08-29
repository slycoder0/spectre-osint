from __future__ import annotations

import time
from pathlib import Path

from spectre_osint.core.config import Settings
from spectre_osint.core.result_cache import ResultCache

COOKIE = "TESTCOOKIE_NOT_A_REAL_SESSION"


def _cache(tmp_path: Path) -> ResultCache:
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        cache_username_ttl=21600,
        cache_dns_ttl=600,
    )
    settings.ensure_dirs()
    return ResultCache(settings)


def test_ttl_hit_miss_refresh(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.set("username", "Instagram", "alice_osint", {"check_status": "LIKELY", "ok": 1}, ttl=2)
    hit = cache.get("username", "Instagram", "alice_osint")
    assert hit is not None
    assert hit.payload["check_status"] == "LIKELY"
    miss = cache.get("username", "GitHub", "nobody")
    assert miss is None
    cache.set("dns", "dns", "example.com", {"a": ["93.184.216.34"]}, ttl=1)
    time.sleep(1.1)
    assert cache.get("dns", "dns", "example.com") is None
    cache.close()


def test_provider_invalidation_and_no_cookies(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.set(
        "username",
        "Instagram",
        "alice_osint",
        {"check_status": "LIKELY", "cookie": COOKIE, "Authorization": "Bearer xyz", "ok": True},
        access_mode="AUTHENTICATED_PUBLIC",
    )
    hit = cache.get("username", "Instagram", "alice_osint", "AUTHENTICATED_PUBLIC")
    assert hit is not None
    assert COOKIE not in str(hit.payload)
    assert "Authorization" not in hit.payload
    assert "cookie" not in hit.payload
    raw = (tmp_path / "data" / "cache" / "results.sqlite").read_bytes()
    assert COOKIE.encode() not in raw
    assert b"Bearer xyz" not in raw
    deleted = cache.clear("Instagram")
    assert deleted >= 1
    assert cache.get("username", "Instagram", "alice_osint", "AUTHENTICATED_PUBLIC") is None
    cache.set("username", "GitHub", "octocat", {"check_status": "CONFIRMED"})
    cache.clear()
    assert cache.get("username", "GitHub", "octocat") is None
    cache.close()


def test_ttl_mapping(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    assert cache.ttl_for("username") == 21600
    assert cache.ttl_for("dns") == 600
    assert cache.ttl_for("rdap") == 86400
    assert cache.ttl_for("crtsh") == 21600
    assert cache.ttl_for("wayback") == 21600
    assert cache.ttl_for("health") == 900
    cache.close()
