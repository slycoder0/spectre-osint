"""Conservative discovered-profile classification. Search hits are never CONFIRMED."""

from __future__ import annotations

from urllib.parse import urlparse

from spectre_osint.modules.mentions.match import match_username
from spectre_osint.modules.mentions.relevance import DIRECT, classify_mention

PROFILE_PATH_HINTS = (
    "/users/",
    "/user/",
    "/u/",
    "/profile/",
    "/profiles/",
    "/p/",
    "/id/",
    "/member/",
    "/members/",
    "/author/",
    "/people/",
    "/channel/",
    "/c/",
    "/in/",
)
PROFILE_WORDS = ("profile", "followers", "following", "posts", "joined", "bio")


def _host(url: str) -> str:
    return (urlparse(str(url or "")).hostname or "").lower().removeprefix("www.")


def _path(url: str) -> str:
    return (urlparse(str(url or "")).path or "").lower()


def username_in_path(username: str, url: str) -> bool:
    handle = str(username or "").strip().lstrip("@").lower()
    if len(handle) < 3:
        return False
    parts = [part.lstrip("@") for part in _path(url).split("/") if part]
    return handle in parts


def looks_like_profile_url(url: str) -> bool:
    path = _path(url)
    if not path or path in {"/", ""}:
        return False
    if "/@" in path or path.startswith("/@"):
        return True
    return any(hint.strip() in path for hint in PROFILE_PATH_HINTS)


def classify_discovered_profile(
    *,
    url: str,
    title: str,
    snippet: str,
    username: str,
    known_hosts: set[str] | None = None,
) -> tuple[bool, str]:
    """Return (is_candidate, relevance). Never upgrades to CONFIRMED."""
    handle = str(username or "").strip().lstrip("@")
    if not handle:
        return False, ""
    matched = match_username(handle, title=title, snippet=snippet, url=url)
    if matched is None:
        return False, ""
    in_path = username_in_path(handle, url)
    host = _host(url)
    known = host in {item.lower().removeprefix("www.") for item in (known_hosts or set())}
    snippet_l = f"{title} {snippet}".lower()
    profile_word = any(word in snippet_l for word in PROFILE_WORDS)
    if in_path and (profile_word or known or looks_like_profile_url(url)):
        relevance, _, _ = classify_mention("username", matched.match_type, title=title, snippet=snippet, url=url)
        return True, relevance or DIRECT
    if in_path:
        return True, DIRECT
    return False, ""
