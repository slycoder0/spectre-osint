"""Per-host/provider rate limiting, backoff, cooldown, and run-local circuit breaker."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict


def compute_backoff(
    attempt: int,
    *,
    retry_after: float | None = None,
    jitter: float = 0.0,
    cap: float = 30.0,
) -> float:
    """Exponential backoff with optional Retry-After and jitter. Never unbounded."""
    limit = max(0.0, float(cap))
    if retry_after is not None:
        return min(max(0.0, float(retry_after)), limit)
    delay = (2 ** max(0, attempt)) + max(0.0, float(jitter))
    return min(delay, limit)


class RateLimiter:
    """Minimum interval between calls, keyed by host when known (else provider)."""

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}
        self._last: dict[str, float] = defaultdict(float)
        self._intervals: dict[str, float] = {
            "default": 0.25,
            "username": 0.5,
            "crtsh": 1.0,
            "rdap": 0.5,
            "virustotal": 1.0,
            "abuseipdb": 1.0,
            "shodan": 1.0,
            "hibp": 1.6,
            "github": 0.5,
            "wayback": 0.8,
        }

    def set_interval(self, provider: str, seconds: float) -> None:
        self._intervals[provider] = seconds

    def _lock_for(self, key: str) -> asyncio.Lock:
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    @staticmethod
    def key(provider: str, host: str | None = None) -> str:
        host_l = (host or "").strip().lower()
        if host_l:
            return f"host:{host_l}"
        return f"provider:{(provider or 'default').strip().lower() or 'default'}"

    def interval_for(self, provider: str, host: str | None = None, override: float | None = None) -> float:
        if override is not None:
            return max(0.0, float(override))
        host_l = (host or "").strip().lower()
        if host_l and host_l in self._intervals:
            return self._intervals[host_l]
        if provider in self._intervals:
            return self._intervals[provider]
        return self._intervals["default"]

    async def acquire(
        self,
        provider: str,
        host: str | None = None,
        interval: float | None = None,
    ) -> None:
        key = self.key(provider, host)
        wait = self.interval_for(provider, host, interval)
        lock = self._lock_for(key)
        async with lock:
            now = time.monotonic()
            wait_for = self._last[key] + wait - now
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last[key] = time.monotonic()


class HostCooldown:
    """Short in-process pause after a host rate-limit. Not a result cache."""

    def __init__(self) -> None:
        self._until: dict[str, float] = {}
        self._reason: dict[str, str] = {}

    def set(self, host: str, seconds: float, reason: str = "rate_limit") -> None:
        key = (host or "").strip().lower()
        if not key:
            return
        self._until[key] = time.monotonic() + max(0.0, float(seconds))
        self._reason[key] = reason

    def remaining(self, host: str) -> float:
        key = (host or "").strip().lower()
        if not key:
            return 0.0
        left = self._until.get(key, 0.0) - time.monotonic()
        return left if left > 0 else 0.0

    def reason(self, host: str) -> str:
        return self._reason.get((host or "").strip().lower(), "")


class HostCircuitBreaker:
    """Open a host for the rest of this HttpClient/investigation after repeated failures."""

    def __init__(self, threshold: int = 3) -> None:
        self.threshold = max(1, int(threshold))
        self._failures: dict[str, int] = defaultdict(int)
        self._open: dict[str, str] = {}

    def allow(self, host: str) -> str | None:
        """Return the open reason, or None if the host may be called."""
        key = (host or "").strip().lower()
        if not key:
            return None
        return self._open.get(key)

    def record_success(self, host: str) -> None:
        key = (host or "").strip().lower()
        if not key:
            return
        self._failures[key] = 0
        self._open.pop(key, None)

    def record_failure(self, host: str, reason: str) -> bool:
        """Record a failure. Returns True if the circuit just opened or is already open."""
        key = (host or "").strip().lower()
        if not key:
            return False
        if key in self._open:
            return True
        self._failures[key] += 1
        if self._failures[key] >= self.threshold:
            self._open[key] = reason or "unavailable"
            return True
        return False

    def open_circuit(self, host: str, reason: str) -> None:
        """Immediately open the circuit for a host for the rest of this investigation run."""
        key = (host or "").strip().lower()
        if key:
            self._open[key] = reason or "unavailable"

    def is_open(self, host: str) -> bool:
        return self.allow(host) is not None


class GlobalConcurrency:
    """Process-wide cap on in-flight HTTP/provider work."""

    def __init__(self, limit: int = 8) -> None:
        self._limit = max(1, limit)
        self._sem: asyncio.Semaphore | None = None

    @property
    def limit(self) -> int:
        return self._limit

    def semaphore(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(self._limit)
        return self._sem
