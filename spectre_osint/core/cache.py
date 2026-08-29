"""SQLite JSON cache. Replaces diskcache (CVE-2025-69872 / GHSA-w8v5-vhqr-4h9v).

Values are stored as JSON only — never pickle — so a poisoned cache file cannot
execute code. The cache directory is created mode 0700.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.redaction import redact_mapping


class ResponseCache:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.settings.cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.settings.cache_dir.chmod(0o700)
        except OSError:
            pass
        self._path = Path(self.settings.cache_dir) / "cache.sqlite"
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS kv ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at REAL NOT NULL)"
        )
        self._conn.commit()

    @staticmethod
    def make_key(provider: str, method: str, url: str, extra: str = "") -> str:
        material = f"{provider}|{method}|{url}|{extra}".encode()
        return hashlib.sha256(material).hexdigest()

    def get(self, key: str) -> Any | None:
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT value, expires_at FROM kv WHERE key = ?", (key,)
            ).fetchone()
            if not row:
                return None
            value, expires_at = row
            if expires_at < now:
                self._conn.execute("DELETE FROM kv WHERE key = ?", (key,))
                self._conn.commit()
                return None
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        expire = ttl if ttl is not None else self.settings.cache_default_ttl
        payload = redact_mapping(value)
        encoded = json.dumps(payload, default=str, ensure_ascii=False)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO kv(key, value, expires_at) VALUES (?, ?, ?)",
                (key, encoded, time.time() + expire),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
