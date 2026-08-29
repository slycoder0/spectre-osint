"""Host-isolated rate limits, retry/backoff, circuit breaker, unofficial HTTP 600."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path

import httpx
import pytest

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.exceptions import (
    ProviderUnavailable,
    RateLimitExceeded,
    UnofficialHttpStatus,
)
from spectre_osint.core.http_client import UNOFFICIAL_HTTP_MIN, HttpClient, parse_retry_after
from spectre_osint.core.rate_limit import RateLimiter, compute_backoff
from spectre_osint.core.result_cache import ResultCache
from spectre_osint.core.types import Confidence, EntityType, UsernameCheckStatus
from spectre_osint.modules.username import engine as username_engine
from spectre_osint.modules.username.engine import analyze_username


def _settings(tmp_path: Path, **kwargs: object) -> Settings:
    values: dict[str, object] = {
        "data_dir": tmp_path / "data",
        "reports_dir": tmp_path / "reports",
        "logs_dir": tmp_path / "logs",
        "database_url": f"sqlite:///{tmp_path / 't.db'}",
        "ssrf_enabled": False,
        "http_max_retries": 3,
        "http_retry_budget": 20,
        "http_max_backoff": 30,
        "http_circuit_failures": 3,
        "max_concurrency": 8,
    }
    values.update(kwargs)
    s = Settings(**values)  # type: ignore[arg-type]
    s.ensure_dirs()
    return s


def _client(tmp_path: Path, handler, **kwargs: object) -> tuple[HttpClient, list[float]]:
    sleeps: list[float] = []

    async def sleeper(seconds: float) -> None:
        sleeps.append(float(seconds))

    settings = _settings(tmp_path)
    http = HttpClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleeper=sleeper,
        jitter_fn=lambda: 0.0,
        **kwargs,  # type: ignore[arg-type]
    )
    return http, sleeps


@pytest.mark.asyncio
async def test_429_retry_after_seconds(tmp_path: Path) -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        if hits["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "5"}, text="slow")
        return httpx.Response(200, text="ok")

    http, sleeps = _client(tmp_path, handler)
    try:
        response = await http.get("https://reddit.com/u/x", provider="Reddit", min_interval=0)
        assert response.status_code == 200
        assert hits["n"] == 2
        assert sleeps == [5.0]
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_429_retry_after_http_date(tmp_path: Path) -> None:
    hits = {"n": 0}
    when = datetime.now(UTC) + timedelta(seconds=7)

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        if hits["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": format_datetime(when)}, text="slow")
        return httpx.Response(200, text="ok")

    http, sleeps = _client(tmp_path, handler)
    try:
        response = await http.get("https://reddit.com/u/x", provider="Reddit", min_interval=0)
        assert response.status_code == 200
        assert hits["n"] == 2
        assert sleeps
        assert 5.0 <= sleeps[0] <= 9.0
        parsed = parse_retry_after(format_datetime(when))
        assert parsed is not None
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_429_without_retry_after_uses_backoff(tmp_path: Path) -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        if hits["n"] == 1:
            return httpx.Response(429, text="slow")
        return httpx.Response(200, text="ok")

    http, sleeps = _client(tmp_path, handler)
    try:
        await http.get("https://pinterest.com/u/x", provider="Pinterest", min_interval=0)
        assert hits["n"] == 2
        assert sleeps == [compute_backoff(0, jitter=0.0, cap=30.0)]
    finally:
        await http.close()


def test_backoff_jitter_is_controllable() -> None:
    assert compute_backoff(0, jitter=0.25, cap=30.0) == 1.25
    assert compute_backoff(1, jitter=0.25, cap=30.0) == 2.25
    assert compute_backoff(0, retry_after=5, jitter=9, cap=30.0) == 5.0
    assert compute_backoff(8, jitter=0, cap=4.0) == 4.0


@pytest.mark.asyncio
async def test_500_retries_then_200(tmp_path: Path) -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        if hits["n"] == 1:
            return httpx.Response(500, text="err")
        return httpx.Response(200, text="ok")

    http, sleeps = _client(tmp_path, handler)
    try:
        response = await http.get("https://gitlab.com/x", provider="GitLab", min_interval=0)
        assert response.status_code == 200
        assert hits["n"] == 2
        assert sleeps == [1.0]
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_repeated_503_opens_circuit(tmp_path: Path) -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(503, text="down")

    http, _sleeps = _client(tmp_path, handler)
    try:
        with pytest.raises(ProviderUnavailable):
            await http.get("https://npmjs.com/x", provider="npm", min_interval=0)
        first = hits["n"]
        assert first >= 3
        with pytest.raises(ProviderUnavailable, match="circuit open"):
            await http.get("https://npmjs.com/x", provider="npm", min_interval=0)
        assert hits["n"] == first
        assert http.circuit.is_open("npmjs.com")
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_404_is_not_retried(tmp_path: Path) -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(404, text="missing")

    http, sleeps = _client(tmp_path, handler)
    try:
        response = await http.get("https://github.com/nope", provider="GitHub", min_interval=0)
        assert response.status_code == 404
        assert hits["n"] == 1
        assert sleeps == []
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_timeout_is_not_not_found(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("nope")

    http, _sleeps = _client(tmp_path, handler)
    try:
        with pytest.raises(ProviderUnavailable, match="timeout"):
            await http.get("https://example.com/u", provider="Example", min_interval=0)
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_host_a_rate_limit_does_not_block_host_b(tmp_path: Path) -> None:
    hits = {"reddit": 0, "github": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host or ""
        if "reddit" in host:
            hits["reddit"] += 1
            return httpx.Response(429, headers={"Retry-After": "0"}, text="slow")
        hits["github"] += 1
        return httpx.Response(200, text="ok")

    settings = _settings(tmp_path, http_max_retries=1)
    http = HttpClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleeper=lambda _s: asyncio.sleep(0),
        jitter_fn=lambda: 0.0,
    )
    try:
        with pytest.raises(RateLimitExceeded):
            await http.get("https://www.reddit.com/user/x", provider="Reddit", min_interval=0)
        ok = await http.get("https://github.com/x", provider="GitHub", min_interval=0)
        assert ok.status_code == 200
        assert hits["github"] == 1
        assert hits["reddit"] >= 1
        assert not http.circuit.is_open("github.com")
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_rate_limiter_host_keys_are_isolated() -> None:
    limiter = RateLimiter()
    limiter.set_interval("reddit.com", 5.0)
    limiter.set_interval("github.com", 0.0)
    started = asyncio.get_event_loop().time()
    await limiter.acquire("Reddit", host="reddit.com")
    await limiter.acquire("GitHub", host="github.com")
    elapsed = asyncio.get_event_loop().time() - started
    assert elapsed < 1.0


@pytest.mark.asyncio
async def test_username_concurrency_cap(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path, max_concurrency=3)
    fake = _CountingHttp(settings)
    monkeypatch.setattr(
        username_engine,
        "load_sites",
        lambda: [
            {
                "name": f"Site{i}",
                "category": "Social",
                "profile_url": f"https://site{i}.example/{'{username}'}",
                "check_method": "generic_html",
                "enabled": True,
                "rate_limit": 0,
            }
            for i in range(9)
        ],
    )
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    await analyze_username(
        entity,
        fake,  # type: ignore[arg-type]
        concurrency=3,
        result_cache=ResultCache(settings),
        auth_service=object(),
    )
    assert fake.max_inflight <= 3
    assert fake.max_inflight >= 1


@pytest.mark.asyncio
async def test_username_cancel_cleans_up(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    started = asyncio.Event()

    class SlowHttp:
        def __init__(self) -> None:
            self.settings = settings

        async def get(self, url: str, **kwargs: object) -> object:
            started.set()
            await asyncio.sleep(30)
            raise AssertionError(url)

    monkeypatch.setattr(
        username_engine,
        "load_sites",
        lambda: [
            {
                "name": "Slow",
                "category": "Social",
                "profile_url": "https://slow.example/{username}",
                "check_method": "generic_html",
                "enabled": True,
            }
        ],
    )
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    task = asyncio.create_task(
        analyze_username(
            entity,
            SlowHttp(),  # type: ignore[arg-type]
            concurrency=1,
            result_cache=ResultCache(settings),
            auth_service=object(),
        )
    )
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_refresh_skips_result_cache_but_not_host_cooldown(tmp_path: Path) -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(429, headers={"Retry-After": "30"}, text="slow")

    settings = _settings(tmp_path, http_max_retries=1)
    http = HttpClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleeper=lambda _s: asyncio.sleep(0),
        jitter_fn=lambda: 0.0,
    )
    cache = ResultCache(settings)
    try:
        with pytest.raises(RateLimitExceeded):
            await http.get("https://reddit.com/u/x", provider="Reddit", use_cache=False, min_interval=0)
        first = hits["n"]
        with pytest.raises(RateLimitExceeded, match="cooldown"):
            await http.get("https://reddit.com/u/x", provider="Reddit", use_cache=False, min_interval=0)
        assert hits["n"] == first
        assert cache.get("username", "Reddit", "alice_osint") is None
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_rate_limit_is_not_cached_as_not_found(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path, http_max_retries=1)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0"}, text="slow")

    http = HttpClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleeper=lambda _s: asyncio.sleep(0),
        jitter_fn=lambda: 0.0,
    )
    monkeypatch.setattr(
        username_engine,
        "load_sites",
        lambda: [
            {
                "name": "Reddit",
                "category": "Social",
                "profile_url": "https://www.reddit.com/user/{username}",
                "check_method": "generic_html",
                "enabled": True,
                "rate_limit": 0,
            }
        ],
    )
    cache = ResultCache(settings)
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    try:
        bundle = await analyze_username(entity, http, concurrency=1, result_cache=cache, auth_service=object())
        finding = bundle["findings"][1] if bundle["findings"][0].title == "Username sweep" else bundle["findings"][0]
        if finding.title == "Username sweep":
            finding = next(f for f in bundle["findings"] if f.title == "Reddit")
        assert finding.data["check_status"] == UsernameCheckStatus.RATE_LIMITED.value
        assert finding.data["check_status"] != UsernameCheckStatus.NOT_FOUND.value
        assert cache.get("username", "Reddit", "alice_osint", "ANONYMOUS_PUBLIC") is None
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_unofficial_http_600_is_not_synthesized_or_429(tmp_path: Path) -> None:
    assert UNOFFICIAL_HTTP_MIN == 600

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(600, text="unofficial peer status")

    http, sleeps = _client(tmp_path, handler)
    try:
        with pytest.raises(UnofficialHttpStatus) as err:
            await http.get("https://example.com/x", provider="Example", min_interval=0)
        assert err.value.status_code == 600
        assert "unofficial HTTP 600" in str(err.value)
        assert sleeps == []
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_duckduckgo_host_outage_fails_fast_on_subsequent_providers_same_run(tmp_path: Path) -> None:
    calls = {"ddg": 0, "github": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host or ""
        if "duckduckgo.com" in host:
            calls["ddg"] += 1
            raise httpx.ConnectTimeout("connection timed out", request=request)
        if "github.com" in host:
            calls["github"] += 1
            return httpx.Response(200, json={"total_count": 1, "items": []})
        return httpx.Response(404, text="not found")

    settings = _settings(tmp_path, http_max_retries=1)
    http = HttpClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleeper=lambda _s: asyncio.sleep(0),
        jitter_fn=lambda: 0.0,
    )
    try:
        # 1. First consumer (duckduckgo-html) experiences timeout
        with pytest.raises(ProviderUnavailable, match="timeout"):
            await http.get(
                "https://html.duckduckgo.com/html/?q=alice",
                provider="duckduckgo-html",
                min_interval=0,
            )
        assert calls["ddg"] == 1

        # 2. Subsequent consumer (public-documents) to the same host must fail fast with circuit open (no handler calls)
        with pytest.raises(ProviderUnavailable, match="circuit open"):
            await http.get(
                "https://html.duckduckgo.com/html/?q=alice+filetype:pdf",
                provider="public-documents",
                min_interval=0,
            )
        assert calls["ddg"] == 1  # No additional network attempt paid

        # 3. Another host (github-search) is not affected and succeeds normally
        response = await http.get(
            "https://api.github.com/search/issues?q=alice",
            provider="github-search",
            min_interval=0,
        )
        assert response.status_code == 200
        assert calls["github"] == 1

        # 4. A clean new client / execution context is NOT permanently blocked
        http_new = HttpClient(
            settings,
            transport=httpx.MockTransport(handler),
            sleeper=lambda _s: asyncio.sleep(0),
            jitter_fn=lambda: 0.0,
        )
        try:
            assert not http_new.circuit.is_open("html.duckduckgo.com")
        finally:
            await http_new.close()
    finally:
        await http.close()


class _CountingHttp:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.inflight = 0
        self.max_inflight = 0

    async def get(self, url: str, **kwargs: object) -> object:
        from spectre_osint.core.http_client import HttpResponse

        del kwargs
        self.inflight += 1
        self.max_inflight = max(self.max_inflight, self.inflight)
        await asyncio.sleep(0.05)
        self.inflight -= 1
        return HttpResponse(url=url, status_code=200, headers={}, text="<html><title>Home</title></html>")
