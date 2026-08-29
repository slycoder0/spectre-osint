"""Public search backends. No Google HTML scraping, no CAPTCHA bypass."""

from __future__ import annotations

from typing import Any, Protocol
from urllib.parse import urljoin, urlparse

from spectre_osint.core.config import Settings
from spectre_osint.core.http_client import HttpClient, HttpResponse
from spectre_osint.core.logger import get_logger
from spectre_osint.modules.mentions.providers import RawMention, default_mention_providers

logger = get_logger("spectre.search")

_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "localhost.localdomain"})


class SearchProvider(Protocol):
    name: str

    def available(self, settings: Settings) -> bool:
        ...

    async def search(
        self,
        query: str,
        *,
        http: HttpClient,
        settings: Settings,
        limit: int,
    ) -> list[RawMention]:
        ...


def _text(value: object, *, limit: int = 240) -> str:
    return " ".join(str(value or "").split())[:limit]


def _note_stats(provider: object, *, raw: int, parsed: int) -> None:
    provider.last_raw = int(raw)  # type: ignore[attr-defined]
    provider.last_parsed = int(parsed)  # type: ignore[attr-defined]


def searxng_origin(settings: Settings) -> str:
    raw = str(getattr(settings, "searxng_url", None) or "").strip().rstrip("/")
    return raw


def is_loopback_searxng(url: str) -> bool:
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").lower().strip("[]")
    return host in _LOCAL_HOSTS


class SearxngProvider:
    name = "searxng"

    def available(self, settings: Settings) -> bool:
        origin = searxng_origin(settings)
        return bool(origin) and is_loopback_searxng(origin)

    async def search(
        self,
        query: str,
        *,
        http: HttpClient,
        settings: Settings,
        limit: int,
    ) -> list[RawMention]:
        origin = searxng_origin(settings)
        if not origin:
            _note_stats(self, raw=0, parsed=0)
            return []
        if not is_loopback_searxng(origin):
            logger.info("SearXNG ignored: URL must be loopback http(s)")
            _note_stats(self, raw=0, parsed=0)
            return []
        endpoint = urljoin(origin + "/", "search")
        response: HttpResponse = await http.get(
            endpoint,
            provider=self.name,
            params={"q": query, "format": "json"},
            ssrf=False,
            follow_redirects=False,
            use_cache=True,
        )
        payload = response.json_data if isinstance(response.json_data, dict) else {}
        raw_results = payload.get("results")
        rows: list[Any] = raw_results if isinstance(raw_results, list) else []
        out: list[RawMention] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url") or row.get("href") or "")
            if not url:
                continue
            out.append(
                RawMention(
                    provider=self.name,
                    title=_text(row.get("title"), limit=180),
                    url=url,
                    snippet=_text(row.get("content") or row.get("snippet"), limit=240),
                )
            )
            if len(out) >= max(1, limit):
                break
        _note_stats(self, raw=len(rows), parsed=len(out))
        return out


class MentionSearchAdapter:
    """Expose mention backends as search providers without changing their matchers."""

    def __init__(self, backend: Any) -> None:
        self.backend = backend
        self.name = str(getattr(backend, "name", "search"))

    def available(self, settings: Settings) -> bool:
        check = getattr(self.backend, "available", None)
        if callable(check):
            try:
                return bool(check(settings))
            except Exception:  # noqa: BLE001
                return False
        return True

    async def search(
        self,
        query: str,
        *,
        http: HttpClient,
        settings: Settings,
        limit: int,
    ) -> list[RawMention]:
        return await self.backend.search(query, http=http, settings=settings, limit=limit)


def default_search_providers() -> list[SearchProvider]:
    providers: list[SearchProvider] = [SearxngProvider()]
    for backend in default_mention_providers():
        providers.append(MentionSearchAdapter(backend))
    return providers
