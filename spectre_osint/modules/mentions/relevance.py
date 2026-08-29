"""PUBLIC_MENTION relevance. Does not change match acceptance or identity."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from spectre_osint.modules.mentions.match import match_domain, match_email, match_username

DIRECT = "DIRECT"
ASSOCIATED = "ASSOCIATED"
AMBIGUOUS = "AMBIGUOUS"

_DIRECT_REASONS = {
    "exact_token": "exact_username",
    "url_path_segment": "username_path",
    "exact_email": "exact_email",
    "exact_host": "exact_domain",
}

PROVIDER_LABELS = {
    "duckduckgo-html": "DuckDuckGo",
    "google-cse": "Google CSE",
    "hn-algolia": "Hacker News",
    "github-search": "GitHub",
    "reddit-search": "Reddit",
    "public-documents": "Public documents",
}


def provider_label(name: str) -> str:
    key = str(name or "").strip()
    return PROVIDER_LABELS.get(key, key or "unknown")


def lead_host(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    return (parsed.hostname or raw).lower().removeprefix("www.")


def normalize_case_inputs(raw: dict[str, Any] | None) -> dict[str, list[str]]:
    data = dict(raw or {})
    usernames = [str(item).strip().lstrip("@") for item in (data.get("usernames") or []) if str(item).strip()]
    names = [str(item).strip() for item in (data.get("names") or []) if str(item).strip()]
    emails = [str(item).strip() for item in (data.get("emails") or []) if str(item).strip()]
    domains = [lead_host(str(item)) for item in (data.get("domains") or [])]
    return {
        "usernames": [item for item in usernames if item],
        "names": [item for item in names if item],
        "emails": [item for item in emails if item],
        "domains": [item for item in domains if item],
    }


def _page_has_username(handle: str, *, title: str, snippet: str, url: str, author: str) -> bool:
    return match_username(handle, title=title, snippet=snippet, url=url, author=author) is not None


def _page_has_email(email: str, *, title: str, snippet: str, url: str, author: str) -> bool:
    return match_email(email, title=title, snippet=snippet, url=url, author=author) is not None


def _page_has_domain(domain: str, *, title: str, snippet: str, url: str, author: str) -> bool:
    host = lead_host(domain)
    if not host:
        return False
    return match_domain(host, title=title, snippet=snippet, url=url, author=author) is not None


def associated_evidence(
    *,
    title: str,
    snippet: str,
    url: str,
    author: str = "",
    case_inputs: dict[str, Any] | None = None,
) -> list[tuple[str, str]]:
    """Independent case inputs that also appear on this page. Not operator co-typing."""
    leads = normalize_case_inputs(case_inputs)
    found: list[tuple[str, str]] = []
    page = {"title": title, "snippet": snippet, "url": url, "author": author}
    for handle in leads["usernames"]:
        if _page_has_username(handle, **page):
            found.append(("name_plus_username", handle))
    for email in leads["emails"]:
        if _page_has_email(email, **page):
            found.append(("name_plus_email", email))
    for domain in leads["domains"]:
        if _page_has_domain(domain, **page):
            found.append(("name_plus_domain", domain))
    return found


def classify_mention(
    kind: str,
    match_type: str,
    *,
    title: str,
    snippet: str,
    url: str,
    author: str = "",
    case_inputs: dict[str, Any] | None = None,
) -> tuple[str, str, list[str]]:
    """Return (DIRECT|ASSOCIATED|AMBIGUOUS, reason, associated_values)."""
    reason = _DIRECT_REASONS.get(match_type)
    if reason is not None:
        return DIRECT, reason, []
    kind = (kind or "").lower()
    if kind == "username":
        return DIRECT, "exact_username", []
    if kind == "email":
        return DIRECT, "exact_email", []
    if kind in {"domain", "url", "website"}:
        return DIRECT, "exact_domain", []
    extras = associated_evidence(
        title=title, snippet=snippet, url=url, author=author, case_inputs=case_inputs
    )
    if extras:
        labels = [item[0] for item in extras]
        values = [item[1] for item in extras]
        return ASSOCIATED, labels[0], values
    if match_type == "full_name" or kind == "name":
        return AMBIGUOUS, "full_name_only", []
    return AMBIGUOUS, "unknown", []
