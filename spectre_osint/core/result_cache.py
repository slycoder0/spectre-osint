"""OSINT result cache. Separate from HTTP cache and from auth session storage.

Never stores cookies, Authorization headers or Playwright storage_state.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.redaction import redact_mapping, strip_auth_material
from spectre_osint.core.types import CacheState


@dataclass
class CachedResult:
    kind: str
    provider: str
    subject: str
    payload: dict[str, Any]
    checked_at: str
    access_mode: str
    age_seconds: float
    cache_state: CacheState = CacheState.CACHED


class ResultCache:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.settings.cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.settings.cache_dir.chmod(0o700)
        except OSError:
            pass
        self._path = Path(self.settings.cache_dir) / "results.sqlite"
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS results ("
            "key TEXT PRIMARY KEY, kind TEXT NOT NULL, provider TEXT NOT NULL, "
            "subject TEXT NOT NULL, access_mode TEXT NOT NULL, "
            "value TEXT NOT NULL, checked_at TEXT NOT NULL, expires_at REAL NOT NULL)"
        )
        self._conn.commit()

    def ttl_for(self, kind: str, provider: str = "") -> int:
        kind_l = kind.lower()
        provider_l = provider.lower()
        if kind_l in {"username", "profile"} or provider_l in {
            "instagram",
            "facebook",
            "threads",
            "tiktok",
            "x",
            "twitch",
        }:
            return self.settings.cache_username_ttl
        if kind_l == "dns":
            return self.settings.cache_dns_ttl
        if kind_l == "rdap":
            return self.settings.cache_rdap_ttl
        if kind_l in {"crtsh", "crt.sh", "certificate"}:
            return self.settings.cache_crtsh_ttl
        if kind_l == "wayback":
            return self.settings.cache_wayback_ttl
        if kind_l == "health":
            return self.settings.cache_health_ttl
        return self.settings.cache_default_ttl

    @staticmethod
    def make_key(kind: str, provider: str, subject: str, access_mode: str = "") -> str:
        material = f"{kind}|{provider}|{subject}|{access_mode}".encode()
        return hashlib.sha256(material).hexdigest()

    def get(self, kind: str, provider: str, subject: str, access_mode: str = "") -> CachedResult | None:
        key = self.make_key(kind, provider, subject, access_mode)
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT value, checked_at, expires_at, access_mode FROM results WHERE key = ?",
                (key,),
            ).fetchone()
            if not row:
                return None
            value, checked_at, expires_at, stored_mode = row
            if expires_at < now:
                self._conn.execute("DELETE FROM results WHERE key = ?", (key,))
                self._conn.commit()
                return None
            try:
                payload = json.loads(value)
            except json.JSONDecodeError:
                return None
            payload = strip_auth_material(payload)
            age = _age_seconds(str(checked_at), now)
            return CachedResult(
                kind=kind,
                provider=provider,
                subject=subject,
                payload=payload if isinstance(payload, dict) else {"value": payload},
                checked_at=str(checked_at),
                access_mode=str(stored_mode or access_mode),
                age_seconds=age,
                cache_state=CacheState.CACHED,
            )

    def set(
        self,
        kind: str,
        provider: str,
        subject: str,
        payload: Any,
        *,
        access_mode: str = "",
        ttl: int | None = None,
        checked_at: str | None = None,
    ) -> None:
        cleaned = strip_auth_material(redact_mapping(payload))
        encoded = json.dumps(cleaned, default=str, ensure_ascii=False)
        expire = ttl if ttl is not None else self.ttl_for(kind, provider)
        when = checked_at or datetime.now(UTC).isoformat()
        key = self.make_key(kind, provider, subject, access_mode)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO results("
                "key, kind, provider, subject, access_mode, value, checked_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (key, kind, provider, subject, access_mode, encoded, when, time.time() + expire),
            )
            self._conn.commit()

    def clear(self, provider: str | None = None) -> int:
        with self._lock:
            if provider:
                cur = self._conn.execute(
                    "DELETE FROM results WHERE lower(provider) = lower(?)", (provider,)
                )
            else:
                cur = self._conn.execute("DELETE FROM results")
            self._conn.commit()
            return int(cur.rowcount or 0)

    def status(self) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, provider, subject, access_mode, checked_at, expires_at "
                "FROM results ORDER BY kind, provider"
            ).fetchall()
        out: list[dict[str, Any]] = []
        for kind, provider, subject, access_mode, checked_at, expires_at in rows:
            remaining = max(0, int(expires_at - now))
            out.append(
                {
                    "kind": kind,
                    "provider": provider,
                    "subject": subject,
                    "access_mode": access_mode,
                    "checked_at": checked_at,
                    "ttl_remaining": remaining,
                    "expired": expires_at < now,
                }
            )
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _age_seconds(checked_at: str, now: float) -> float:
    try:
        dt = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
        return max(0.0, now - dt.timestamp())
    except (TypeError, ValueError):
        return 0.0
