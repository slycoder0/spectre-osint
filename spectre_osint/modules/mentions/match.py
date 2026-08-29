"""Conservative PUBLIC_MENTION acceptance. Search hits are never enough."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlparse

_USER_BOUND = r"(?<![A-Za-z0-9_]){value}(?![A-Za-z0-9_])"


@dataclass(frozen=True)
class MentionMatch:
    query: str
    kind: str
    matched_value: str
    matched_field: str
    match_type: str
    excerpt: str


def _fold(value: str) -> str:
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", text).strip()


def _excerpt(text: str, needle: str, *, width: int = 90) -> str:
    raw = re.sub(r"\s+", " ", str(text or "")).strip()
    if not raw:
        return ""
    lowered = raw.lower()
    target = needle.lower()
    idx = lowered.find(target)
    if idx < 0:
        return raw[: width * 2]
    start = max(0, idx - width // 2)
    end = min(len(raw), idx + len(needle) + width // 2)
    snippet = raw[start:end]
    if start:
        snippet = "…" + snippet
    if end < len(raw):
        snippet = snippet + "…"
    return snippet


def _fields(title: str, snippet: str, url: str, author: str = "") -> dict[str, str]:
    return {
        "title": str(title or ""),
        "snippet": str(snippet or ""),
        "url": str(url or ""),
        "author": str(author or ""),
    }


def _username_in_url(username: str, url: str) -> bool:
    parsed = urlparse(url)
    path = (parsed.path or "").rstrip("/").lower()
    parts = [p.lstrip("@") for p in path.split("/") if p]
    handle = username.lower().lstrip("@")
    if handle in parts:
        return True
    query = (parsed.query or "").lower()
    return any(
        chunk.split("=", 1)[-1] == handle
        for chunk in query.split("&")
        if "=" in chunk and chunk.split("=", 1)[0] in {"id", "user", "username", "u"}
    )


def match_username(username: str, *, title: str, snippet: str, url: str, author: str = "") -> MentionMatch | None:
    handle = str(username or "").strip().lstrip("@")
    if len(handle) < 3:
        return None
    pattern = re.compile(_USER_BOUND.format(value=re.escape(handle)), re.I)
    fields = _fields(title, snippet, url, author)
    if _username_in_url(handle, fields["url"]):
        return MentionMatch(
            query=handle,
            kind="username",
            matched_value=handle,
            matched_field="url",
            match_type="url_path_segment",
            excerpt=_excerpt(fields["url"], handle),
        )
    for field, text in fields.items():
        if field == "url":
            continue
        if pattern.search(text):
            return MentionMatch(
                query=handle,
                kind="username",
                matched_value=handle,
                matched_field=field,
                match_type="exact_token",
                excerpt=_excerpt(text, handle),
            )
    return None


def match_name(name: str, *, title: str, snippet: str, url: str, author: str = "") -> MentionMatch | None:
    folded = _fold(name)
    tokens = [tok for tok in folded.lower().split(" ") if tok]
    if len(tokens) < 2:
        return None
    phrase = " ".join(tokens)
    fields = _fields(title, snippet, url, author)
    for field, text in fields.items():
        hay = _fold(text).lower()
        if phrase in hay:
            return MentionMatch(
                query=name,
                kind="name",
                matched_value=name.strip(),
                matched_field=field,
                match_type="full_name",
                excerpt=_excerpt(text, name.strip()),
            )
    return None


def match_email(email: str, *, title: str, snippet: str, url: str, author: str = "") -> MentionMatch | None:
    addr = str(email or "").strip().lower()
    if "@" not in addr or "." not in addr.split("@")[-1]:
        return None
    pattern = re.compile(re.escape(addr), re.I)
    fields = _fields(title, snippet, url, author)
    for field, text in fields.items():
        if pattern.search(text):
            return MentionMatch(
                query=addr,
                kind="email",
                matched_value=addr,
                matched_field=field,
                match_type="exact_email",
                excerpt=_excerpt(text, addr),
            )
    return None


def match_domain(domain: str, *, title: str, snippet: str, url: str, author: str = "") -> MentionMatch | None:
    host = str(domain or "").strip().lower().removeprefix("www.")
    if "." not in host or " " in host:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    found_host = (parsed.hostname or "").lower().removeprefix("www.")
    if found_host == host or found_host.endswith("." + host):
        return MentionMatch(
            query=host,
            kind="domain",
            matched_value=host,
            matched_field="url",
            match_type="exact_host",
            excerpt=found_host or host,
        )
    host_pattern = re.compile(rf"(?<![A-Za-z0-9-])(?:www\.)?{re.escape(host)}(?![A-Za-z0-9-])", re.I)
    fields = _fields(title, snippet, url, author)
    for field, text in fields.items():
        if field == "url":
            continue
        if host_pattern.search(text):
            return MentionMatch(
                query=host,
                kind="domain",
                matched_value=host,
                matched_field=field,
                match_type="exact_host",
                excerpt=_excerpt(text, host),
            )
    return None


def match_input(
    value: str,
    kind: str,
    *,
    title: str,
    snippet: str,
    url: str,
    author: str = "",
) -> MentionMatch | None:
    kind = (kind or "username").lower()
    if kind == "username":
        return match_username(value, title=title, snippet=snippet, url=url, author=author)
    if kind == "name":
        return match_name(value, title=title, snippet=snippet, url=url, author=author)
    if kind == "email":
        return match_email(value, title=title, snippet=snippet, url=url, author=author)
    if kind in {"domain", "url", "website"}:
        host = value
        if "://" in value or "/" in value:
            host = (urlparse(value if "://" in value else f"https://{value}").hostname or value)
        return match_domain(host, title=title, snippet=snippet, url=url, author=author)
    return None
