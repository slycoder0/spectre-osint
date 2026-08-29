from __future__ import annotations

import httpx
import pytest

from spectre_osint.core.config import Settings
from spectre_osint.core.exceptions import (
    ProviderUnavailable,
    RateLimitExceeded,
    TlsVerificationError,
)
from spectre_osint.core.http_client import HttpClient, parse_retry_after


def test_parse_retry_after_seconds() -> None:
    assert parse_retry_after("2") == 2.0
    assert parse_retry_after(None) is None


def test_parse_retry_after_http_date() -> None:
    from datetime import UTC, datetime, timedelta
    from email.utils import format_datetime

    when = datetime.now(UTC) + timedelta(seconds=8)
    delay = parse_retry_after(format_datetime(when))
    assert delay is not None
    assert 6.0 <= delay <= 10.0


@pytest.mark.asyncio
async def test_retries_429_then_succeeds(tmp_path) -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        if hits["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"}, text="slow")
        return httpx.Response(200, json={"ok": True})

    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
        http_max_retries=3,
        http_retry_budget=5,
    )
    settings.ensure_dirs()
    client = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        response = await client.get("https://example.com/api", provider="test")
        assert response.status_code == 200
        assert hits["n"] == 2
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_5xx_exhausted(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="bad")

    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
        http_max_retries=2,
        http_retry_budget=2,
    )
    settings.ensure_dirs()
    client = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(ProviderUnavailable):
            await client.get("https://example.com/api", provider="test")
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_timeout(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("nope")

    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
        http_max_retries=1,
    )
    settings.ensure_dirs()
    client = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(ProviderUnavailable):
            await client.get("https://example.com/api", provider="test")
    finally:
        await client.close()


def test_rate_limit_carries_retry_after() -> None:
    err = RateLimitExceeded("nope", retry_after="7")
    assert err.retry_after == "7"


@pytest.mark.asyncio
async def test_tls_verification_hostname_mismatch_not_retried(tmp_path) -> None:
    import ssl

    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        ssl_err = ssl.SSLCertVerificationError(
            1,
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'sub.example.com'",
        )
        raise httpx.ConnectError("SSL connection failed", request=request) from ssl_err

    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
        http_max_retries=3,
        http_retry_budget=10,
    )
    settings.ensure_dirs()
    client = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(TlsVerificationError) as exc_info:
            await client.get("https://sub.example.com/profile", provider="Tumblr")
        assert hits["n"] == 1
        assert "TLS certificate verification failed" in str(exc_info.value)
        assert isinstance(exc_info.value, ProviderUnavailable)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_transient_connect_error_is_retried(tmp_path) -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        if hits["n"] == 1:
            raise httpx.ConnectError("Connection reset by peer", request=request)
        return httpx.Response(200, json={"ok": True})

    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
        http_max_retries=3,
        http_retry_budget=5,
    )
    settings.ensure_dirs()
    client = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        response = await client.get("https://example.com/api", provider="test")
        assert response.status_code == 200
        assert hits["n"] == 2
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_tls_verification_remains_enabled_by_default(tmp_path) -> None:
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    client = HttpClient(settings)
    try:
        # Verify that verification was not disabled (e.g. verify=False)
        assert getattr(client._client, "_verify", None) is not False
    finally:
        await client.close()
