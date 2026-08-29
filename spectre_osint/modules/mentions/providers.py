"""Pluggable public-mention search backends. No CAPTCHA bypass."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import parse_qs, unquote, urlparse

from bs4 import BeautifulSoup

from spectre_osint.core.config import Settings
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.logger import get_logger

logger = get_logger("spectre.mentions")


@dataclass
class RawMention:
    provider: str
    title: str
    url: str
    snippet: str = ""
    author: str = ""
    published_at: str = ""


class MentionProvider(Protocol):
    name: str

    async def search(
        self,
        query: str,
        *,
        http: HttpClient,
        settings: Settings,
        limit: int,
    ) -> list[RawMention]:
        ...


def _text(value: Any, *, limit: int = 240) -> str:
    return " ".join(str(value or "").split())[:limit]


def _note_stats(provider: Any, *, raw: int, parsed: int) -> None:
    provider.last_raw = int(raw)
    provider.last_parsed = int(parsed)


class HnAlgoliaProvider:
    name = "hn-algolia"
    endpoint = "https://hn.algolia.com/api/v1/search"

    async def search(
        self,
        query: str,
        *,
        http: HttpClient,
        settings: Settings,
        limit: int,
    ) -> list[RawMention]:
        del settings
        response = await http.get(
            self.endpoint,
            provider=self.name,
            params={"query": query, "hitsPerPage": max(1, min(limit * 4, 20))},
        )
        hits = (response.json_data or {}).get("hits") if isinstance(response.json_data, dict) else None
        raw_rows = list(hits or [])
        out: list[RawMention] = []
        for hit in raw_rows:
            if not isinstance(hit, dict):
                continue
            object_id = str(hit.get("objectID") or "")
            url = (
                f"https://news.ycombinator.com/item?id={object_id}"
                if object_id
                else str(hit.get("url") or "")
            )
            out.append(
                RawMention(
                    provider=self.name,
                    title=_text(hit.get("title") or hit.get("story_title"), limit=180),
                    url=url or str(hit.get("url") or ""),
                    snippet=_text(hit.get("story_text") or hit.get("comment_text"), limit=240),
                    author=_text(hit.get("author"), limit=80),
                    published_at=str(hit.get("created_at") or ""),
                )
            )
        _note_stats(self, raw=len(raw_rows), parsed=len(out))
        return out


class DuckDuckGoHtmlProvider:
    name = "duckduckgo-html"
    endpoint = "https://html.duckduckgo.com/html/"

    async def search(
        self,
        query: str,
        *,
        http: HttpClient,
        settings: Settings,
        limit: int,
    ) -> list[RawMention]:
        del settings
        response = await http.get(
            self.endpoint,
            provider=self.name,
            params={"q": query},
        )
        soup = BeautifulSoup(response.text or "", "html.parser")
        rows = soup.select(".result")
        out: list[RawMention] = []
        for row in rows:
            link = row.select_one("a.result__a")
            if link is None:
                continue
            href = _ddg_unwrap(str(link.get("href") or ""))
            snippet_el = row.select_one(".result__snippet")
            out.append(
                RawMention(
                    provider=self.name,
                    title=_text(link.get_text(" ", strip=True), limit=180),
                    url=href,
                    snippet=_text(snippet_el.get_text(" ", strip=True) if snippet_el else "", limit=240),
                )
            )
            if len(out) >= limit * 2:
                break
        _note_stats(self, raw=len(rows), parsed=len(out))
        return out


class GitHubSearchProvider:
    name = "github-search"
    endpoint = "https://api.github.com/search/issues"

    async def search(
        self,
        query: str,
        *,
        http: HttpClient,
        settings: Settings,
        limit: int,
    ) -> list[RawMention]:
        headers = {"Accept": "application/vnd.github+json"}
        token = settings.github_token.get_secret_value() if settings.github_token else ""
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = await http.get(
            self.endpoint,
            provider=self.name,
            headers=headers,
            params={"q": f"{query} in:title,body", "per_page": max(1, min(limit, 10))},
        )
        items = (response.json_data or {}).get("items") if isinstance(response.json_data, dict) else None
        raw_rows = list(items or [])
        out: list[RawMention] = []
        for item in raw_rows:
            if not isinstance(item, dict):
                continue
            user = item.get("user") if isinstance(item.get("user"), dict) else {}
            out.append(
                RawMention(
                    provider=self.name,
                    title=_text(item.get("title"), limit=180),
                    url=str(item.get("html_url") or ""),
                    snippet=_text(item.get("body"), limit=240),
                    author=_text(user.get("login") if isinstance(user, dict) else "", limit=80),
                    published_at=str(item.get("created_at") or ""),
                )
            )
        _note_stats(self, raw=len(raw_rows), parsed=len(out))
        return out


class RedditSearchProvider:
    name = "reddit-search"
    endpoint = "https://www.reddit.com/search.json"

    async def search(
        self,
        query: str,
        *,
        http: HttpClient,
        settings: Settings,
        limit: int,
    ) -> list[RawMention]:
        del settings
        response = await http.get(
            self.endpoint,
            provider=self.name,
            params={"q": query, "limit": max(1, min(limit, 10)), "sort": "relevance"},
        )
        data = response.json_data if isinstance(response.json_data, dict) else {}
        children = (data.get("data") or {}).get("children") if isinstance(data.get("data"), dict) else None
        raw_rows = list(children or [])
        out: list[RawMention] = []
        for child in raw_rows:
            if not isinstance(child, dict):
                continue
            raw_post = child.get("data")
            if not isinstance(raw_post, dict):
                continue
            permalink = str(raw_post.get("permalink") or "")
            url = (
                f"https://www.reddit.com{permalink}"
                if permalink.startswith("/")
                else str(raw_post.get("url") or "")
            )
            out.append(
                RawMention(
                    provider=self.name,
                    title=_text(raw_post.get("title"), limit=180),
                    url=url,
                    snippet=_text(raw_post.get("selftext") or raw_post.get("title"), limit=240),
                    author=_text(raw_post.get("author"), limit=80),
                    published_at=str(raw_post.get("created_utc") or ""),
                )
            )
        _note_stats(self, raw=len(raw_rows), parsed=len(out))
        return out


class GoogleCseProvider:
    name = "google-cse"
    endpoint = "https://www.googleapis.com/customsearch/v1"

    def available(self, settings: Settings) -> bool:
        return bool(settings.secret_present("google_api_key") and settings.google_cse_id)

    async def search(
        self,
        query: str,
        *,
        http: HttpClient,
        settings: Settings,
        limit: int,
    ) -> list[RawMention]:
        if not self.available(settings):
            _note_stats(self, raw=0, parsed=0)
            return []
        response = await http.get(
            self.endpoint,
            provider=self.name,
            params={
                "key": settings.google_api_key.get_secret_value() if settings.google_api_key else "",
                "cx": settings.google_cse_id,
                "q": query,
                "num": max(1, min(limit, 10)),
            },
        )
        items = (response.json_data or {}).get("items") if isinstance(response.json_data, dict) else None
        raw_rows = list(items or [])
        out: list[RawMention] = []
        for item in raw_rows:
            if not isinstance(item, dict):
                continue
            out.append(
                RawMention(
                    provider=self.name,
                    title=_text(item.get("title"), limit=180),
                    url=str(item.get("link") or ""),
                    snippet=_text(item.get("snippet"), limit=240),
                )
            )
        _note_stats(self, raw=len(raw_rows), parsed=len(out))
        return out


def _ddg_unwrap(href: str) -> str:
    raw = str(href or "").strip()
    if raw.startswith("//"):
        raw = "https:" + raw
    parsed = urlparse(raw)
    qs = parse_qs(parsed.query)
    if qs.get("uddg"):
        return unquote(qs["uddg"][0])
    return raw


class PublicDocumentProvider:
    """Public indexed documents via DuckDuckGo HTML. No Google scrape."""

    name = "public-documents"

    def __init__(self) -> None:
        self._web = DuckDuckGoHtmlProvider()

    async def search(
        self,
        query: str,
        *,
        http: HttpClient,
        settings: Settings,
        limit: int,
    ) -> list[RawMention]:
        hits = await self._web.search(
            f"{query} (filetype:pdf OR filetype:doc OR filetype:docx)",
            http=http,
            settings=settings,
            limit=limit,
        )
        rewritten = [
            RawMention(
                provider=self.name,
                title=hit.title,
                url=hit.url,
                snippet=hit.snippet,
                author=hit.author,
                published_at=hit.published_at,
            )
            for hit in hits
        ]
        _note_stats(
            self,
            raw=int(getattr(self._web, "last_raw", len(hits)) or 0),
            parsed=int(getattr(self._web, "last_parsed", len(rewritten)) or 0),
        )
        return rewritten


def default_mention_providers() -> list[MentionProvider]:
    return [
        DuckDuckGoHtmlProvider(),
        HnAlgoliaProvider(),
        GitHubSearchProvider(),
        RedditSearchProvider(),
        PublicDocumentProvider(),
        GoogleCseProvider(),
    ]
