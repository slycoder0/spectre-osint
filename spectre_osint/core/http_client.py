"""Shared async HTTP client: timeout, retry, cache, UA rotation, SSRF, redaction."""

from __future__ import annotations

import email.utils
import random
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from spectre_osint.core.cache import ResponseCache
from spectre_osint.core.config import BUNDLED_DATA_DIR, Settings, get_settings
from spectre_osint.core.exceptions import (
    ProviderUnavailable,
    RateLimitExceeded,
    SSRFBlocked,
    TlsVerificationError,
    UnofficialHttpStatus,
)
from spectre_osint.core.logger import get_logger
from spectre_osint.core.rate_limit import (
    GlobalConcurrency,
    HostCircuitBreaker,
    HostCooldown,
    RateLimiter,
    compute_backoff,
)
from spectre_osint.core.redaction import redact_mapping, redact_text
from spectre_osint.core.ssrf import MAX_REDIRECTS, SSRFPolicy

logger = get_logger("spectre.http")

# RFC 9110 status codes are 100-599. SPECTRE never synthesizes codes >= 600.
UNOFFICIAL_HTTP_MIN = 600
RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})


def _is_tls_verification_error(exc: BaseException) -> bool:
    """True when an exception (or any error in its cause chain) is a deterministic TLS/cert error."""
    visited: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, (ssl.SSLCertVerificationError, ssl.CertificateError)):
            return True
        msg = str(current).lower()
        if any(
            phrase in msg
            for phrase in (
                "certificate verify failed",
                "certificateverifyfailed",
                "hostname mismatch",
                "certificate_verify_failed",
                "self-signed certificate",
                "self signed certificate",
                "certificate has expired",
                "unable to get local issuer certificate",
                "certificate is not valid",
                "tlsv1_alert_unknown_ca",
            )
        ):
            return True
        current = current.__cause__ or current.__context__
    return False


def request_host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def load_user_agents(path: Path | None = None) -> list[str]:
    ua_path = path or (BUNDLED_DATA_DIR / "user_agents.txt")
    if not ua_path.exists():
        return ["SPECTRE-OSINT/0.1-alpha (+passive-osint)"]
    lines = [line.strip() for line in ua_path.read_text(encoding="utf-8").splitlines()]
    return [line for line in lines if line and not line.startswith("#")]


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    text = value.strip()
    if text.isdigit():
        return min(float(text), 60.0)
    try:
        dt = email.utils.parsedate_to_datetime(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        delay = (dt - datetime.now(UTC)).total_seconds()
        return min(max(delay, 0.0), 60.0)
    except (TypeError, ValueError, OverflowError, IndexError):
        return None


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    json_data: Any | None = None
    from_cache: bool = False
    elapsed_ms: int = 0
    history: list[str] = field(default_factory=list)


class HttpClient:
    def __init__(
        self,
        settings: Settings | None = None,
        cache: ResponseCache | None = None,
        rate_limiter: RateLimiter | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Any | None = None,
        sleeper: Any | None = None,
        jitter_fn: Any | None = None,
        circuit: HostCircuitBreaker | None = None,
        cooldown: HostCooldown | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.cache = cache or ResponseCache(self.settings)
        self.rate_limiter = rate_limiter or RateLimiter()
        self.circuit = circuit or HostCircuitBreaker(self.settings.http_circuit_failures)
        self.cooldown = cooldown or HostCooldown()
        self._sleeper = sleeper
        self._jitter_fn = jitter_fn
        self.user_agents = load_user_agents()
        self._concurrency = GlobalConcurrency(self.settings.max_concurrency)
        self.ssrf = SSRFPolicy(
            allow_private=self.settings.allow_private_targets,
            resolver=resolver,
        )
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.http_timeout),
            follow_redirects=False,
            headers={"Accept": "text/html,application/json;q=0.9,*/*;q=0.8"},
            max_redirects=MAX_REDIRECTS,
            transport=transport,
        )

    def pick_ua(self) -> str:
        if not self.user_agents:
            return self.settings.user_agent
        if random.random() < 0.35:
            return random.choice(self.user_agents)
        return self.settings.user_agent

    async def close(self) -> None:
        await self._client.aclose()
        self.cache.close()

    async def request(
        self,
        method: str,
        url: str,
        *,
        provider: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        data: Any | None = None,
        follow_redirects: bool = True,
        cache_ttl: int | None = None,
        use_cache: bool = True,
        accept_statuses: set[int] | None = None,
        ssrf: bool | None = None,
        min_interval: float | None = None,
    ) -> HttpResponse:
        cache_key = self.cache.make_key(
            provider, method, url, str(params or "") + str(json_body or "")
        )
        if use_cache and method.upper() == "GET":
            cached = self.cache.get(cache_key)
            if cached:
                cached["from_cache"] = True
                return HttpResponse(**cached)

        logical = url
        history: list[str] = []
        protect = self.settings.ssrf_enabled if ssrf is None else ssrf
        hops = MAX_REDIRECTS if follow_redirects else 0
        last: HttpResponse | None = None
        for _hop in range(hops + 1):
            last = await self._request_with_retries(
                method,
                logical,
                provider=provider,
                headers=headers,
                params=params,
                json_body=json_body,
                data=data,
                accept_statuses=accept_statuses,
                protect=protect,
                min_interval=min_interval,
            )
            last.history = list(history)
            if (
                follow_redirects
                and last.status_code in {301, 302, 303, 307, 308}
                and last.headers.get("location")
            ):
                nxt = self.ssrf.next_url(logical, last.headers["location"])
                history.append(nxt)
                logical = nxt
                if method.upper() == "HEAD":
                    method = "HEAD"
                elif last.status_code in {301, 302, 303}:
                    method = "GET"
                params = None
                json_body = None
                data = None
                continue
            break
        else:
            raise ProviderUnavailable(f"{provider} too many redirects")

        assert last is not None
        if use_cache and method.upper() == "GET" and 200 <= last.status_code < 400:
            ttl = cache_ttl if cache_ttl is not None else self.settings.cache_default_ttl
            self.cache.set(cache_key, last.__dict__, ttl=ttl)
        return last

    def _jitter(self) -> float:
        if self._jitter_fn is not None:
            return float(self._jitter_fn())
        return random.uniform(0, 0.5)

    async def _sleep_for(self, seconds: float) -> None:
        delay = max(0.0, float(seconds))
        if delay <= 0:
            return
        sleeper = self._sleeper if self._sleeper is not None else _sleep
        await sleeper(delay)

    async def _request_with_retries(
        self,
        method: str,
        url: str,
        *,
        provider: str,
        headers: dict[str, str] | None,
        params: dict[str, Any] | None,
        json_body: Any | None,
        data: Any | None,
        accept_statuses: set[int] | None,
        protect: bool,
        min_interval: float | None = None,
    ) -> HttpResponse:
        host = request_host(url)
        if host:
            open_reason = self.circuit.allow(host)
            if open_reason:
                logger.warning("provider=%s host=%s circuit=open reason=%s", provider, host, open_reason)
                if open_reason == "rate_limit":
                    raise RateLimitExceeded(f"{provider} circuit open ({host})", retry_after=None)
                raise ProviderUnavailable(f"{provider} circuit open ({host}): {open_reason}")
            cooled = self.cooldown.remaining(host)
            if cooled > 0:
                logger.debug(
                    "provider=%s host=%s cooldown=%.2fs reason=%s",
                    provider,
                    host,
                    cooled,
                    self.cooldown.reason(host) or "rate_limit",
                )
                raise RateLimitExceeded(
                    f"{provider} host cooldown ({host})",
                    retry_after=str(int(cooled)),
                )
        idempotent = method.upper() in {"GET", "HEAD"}
        attempts = max(1, self.settings.http_max_retries if idempotent else 1)
        budget_end = time.monotonic() + self.settings.http_retry_budget
        cap = float(self.settings.http_max_backoff)
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                response = await self._send_once(
                    method,
                    url,
                    provider=provider,
                    headers=headers,
                    params=params,
                    json_body=json_body,
                    data=data,
                    accept_statuses=accept_statuses,
                    protect=protect,
                    min_interval=min_interval,
                )
                if host:
                    self.circuit.record_success(host)
                return response
            except SSRFBlocked:
                raise
            except TlsVerificationError as exc:
                last_error = exc
                if host:
                    self.circuit.record_failure(host, "tls_verification")
                    self.circuit.open_circuit(host, "tls_verification")
                raise
            except UnofficialHttpStatus as exc:
                last_error = exc
                if host:
                    self.circuit.record_failure(host, "unofficial_status")
                    self.circuit.open_circuit(host, "unofficial_status")
                raise
            except RateLimitExceeded as exc:
                last_error = exc
                if host:
                    self.circuit.record_failure(host, "rate_limit")
                delay = compute_backoff(
                    attempt,
                    retry_after=parse_retry_after(exc.retry_after),
                    jitter=self._jitter(),
                    cap=cap,
                )
                remaining = budget_end - time.monotonic()
                if attempt + 1 >= attempts or remaining <= 0:
                    if host:
                        self.cooldown.set(host, min(delay, cap) if delay else 1.0, "rate_limit")
                    raise
                delay = min(delay, remaining)
                logger.debug(
                    "provider=%s host=%s attempt=%s status=429 retry_after=%s backoff=%.2f",
                    provider,
                    host or "-",
                    attempt + 1,
                    exc.retry_after or "-",
                    delay,
                )
                await self._sleep_for(delay)
            except ProviderUnavailable as exc:
                last_error = exc
                if host:
                    self.circuit.record_failure(host, "unavailable")
                delay = compute_backoff(attempt, jitter=self._jitter(), cap=cap)
                remaining = budget_end - time.monotonic()
                if attempt + 1 >= attempts or remaining <= 0:
                    if host:
                        reason = "timeout" if "timeout" in str(exc).lower() else "unavailable"
                        self.circuit.open_circuit(host, reason)
                    raise
                delay = min(delay, remaining)
                logger.debug(
                    "provider=%s host=%s attempt=%s status=unavailable retry_after=- backoff=%.2f",
                    provider,
                    host or "-",
                    attempt + 1,
                    delay,
                )
                await self._sleep_for(delay)
        assert last_error is not None
        if host and isinstance(last_error, (ProviderUnavailable, TlsVerificationError)):
            reason = "timeout" if "timeout" in str(last_error).lower() else "unavailable"
            if isinstance(last_error, TlsVerificationError):
                reason = "tls_verification"
            self.circuit.open_circuit(host, reason)
        raise last_error

    async def _send_once(
        self,
        method: str,
        url: str,
        *,
        provider: str,
        headers: dict[str, str] | None,
        params: dict[str, Any] | None,
        json_body: Any | None,
        data: Any | None,
        accept_statuses: set[int] | None,
        protect: bool,
        min_interval: float | None = None,
    ) -> HttpResponse:
        host = request_host(url)
        await self.rate_limiter.acquire(provider, host=host or None, interval=min_interval)
        merged = {"User-Agent": self.pick_ua()}
        if headers:
            merged.update(headers)
        request_url = url
        extensions: dict[str, Any] = {}
        if protect:
            pinned, original_host, _ips = await self.ssrf.pin(url)
            request_url = pinned
            parsed = urlparse(url)
            host_header = original_host
            if parsed.port:
                host_header = f"{original_host}:{parsed.port}"
            merged.setdefault("Host", host_header)
            if parsed.scheme == "https":
                extensions["sni_hostname"] = original_host

        async with self._concurrency.semaphore():
            try:
                kwargs: dict[str, Any] = {}
                if extensions:
                    kwargs["extensions"] = extensions
                response = await self._client.request(
                    method,
                    request_url,
                    headers=merged,
                    params=params,
                    json=json_body,
                    data=data,
                    follow_redirects=False,
                    **kwargs,
                )
            except httpx.TimeoutException as exc:
                logger.warning(
                    "HTTP timeout provider=%s url=%s err=%s",
                    provider,
                    redact_text(url),
                    redact_text(str(exc)),
                )
                raise ProviderUnavailable(f"{provider} timeout") from exc
            except (ssl.SSLError, ssl.CertificateError) as exc:
                if _is_tls_verification_error(exc):
                    logger.warning(
                        "TLS certificate verification failed provider=%s url=%s err=%s",
                        provider,
                        redact_text(url),
                        redact_text(str(exc)),
                    )
                    raise TlsVerificationError(
                        f"{provider} TLS certificate verification failed: {redact_text(str(exc))}"
                    ) from exc
                logger.warning(
                    "SSL error provider=%s url=%s err=%s",
                    provider,
                    redact_text(url),
                    redact_text(str(exc)),
                )
                raise ProviderUnavailable(f"{provider} unavailable: {redact_text(str(exc))}") from exc
            except (httpx.HTTPError, UnicodeError) as exc:
                if _is_tls_verification_error(exc):
                    logger.warning(
                        "TLS certificate verification failed provider=%s url=%s err=%s",
                        provider,
                        redact_text(url),
                        redact_text(str(exc)),
                    )
                    raise TlsVerificationError(
                        f"{provider} TLS certificate verification failed: {redact_text(str(exc))}"
                    ) from exc
                logger.warning(
                    "HTTP error provider=%s url=%s err=%s",
                    provider,
                    redact_text(url),
                    redact_text(str(exc)),
                )
                raise ProviderUnavailable(f"{provider} unavailable: {redact_text(str(exc))}") from exc

        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "")
            logger.warning(
                "provider=%s host=%s status=429 retry_after=%s",
                provider,
                host or "-",
                retry_after or "-",
            )
            raise RateLimitExceeded(
                f"{provider} rate limited (Retry-After={retry_after})",
                retry_after=retry_after or None,
            )
        if response.status_code >= UNOFFICIAL_HTTP_MIN or response.status_code < 100:
            # Not synthesized: a peer/proxy sent a non-RFC status. Not 429, not NOT_FOUND.
            logger.warning(
                "provider=%s host=%s unofficial HTTP %s (peer/proxy; not synthesized)",
                provider,
                host or "-",
                response.status_code,
            )
            raise UnofficialHttpStatus(
                f"{provider} unofficial HTTP {response.status_code}",
                status_code=response.status_code,
            )
        if response.status_code in {408, 500, 502, 503, 504}:
            logger.debug(
                "provider=%s host=%s attempt=- status=%s retry_after=- backoff=-",
                provider,
                host or "-",
                response.status_code,
            )
            raise ProviderUnavailable(f"{provider} HTTP {response.status_code}")

        json_data = None
        content_type = response.headers.get("content-type", "")
        if "json" in content_type:
            try:
                json_data = response.json()
            except ValueError:
                json_data = None
        elif response.text.lstrip().startswith(("{", "[")):
            try:
                json_data = response.json()
            except ValueError:
                json_data = None

        payload = HttpResponse(
            url=url,
            status_code=response.status_code,
            headers={k: v for k, v in response.headers.items() if k.lower() not in {"set-cookie"}},
            text=response.text[:200_000],
            json_data=redact_mapping(json_data) if json_data is not None else None,
            from_cache=False,
            elapsed_ms=_elapsed_ms(response),
        )

        accepted = accept_statuses or set(range(200, 500))
        if payload.status_code not in accepted and (
            payload.status_code >= 500 or payload.status_code in RETRYABLE_STATUS
        ):
            raise ProviderUnavailable(f"{provider} HTTP {payload.status_code}")
        return payload

    async def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HttpResponse:
        kwargs.setdefault("use_cache", False)
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HttpResponse:
        kwargs.setdefault("use_cache", False)
        return await self.request("POST", url, **kwargs)


def _elapsed_ms(response: httpx.Response) -> int:
    try:
        elapsed = response.elapsed
    except RuntimeError:
        return 0
    if elapsed is None:
        return 0
    return int(elapsed.total_seconds() * 1000)


async def _sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)
