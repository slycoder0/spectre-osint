"""Conservative discovered-profile classification. Search hits are never CONFIRMED."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from spectre_osint.modules.mentions.match import match_username
from spectre_osint.modules.mentions.relevance import DIRECT, classify_mention
from spectre_osint.modules.username.matching import (
    EXACT_MATCH,
    SIMILAR_CANDIDATE,
    UNRELATED,
    classify_username_match,
)

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
_HANDLE_RE = re.compile(r"(?<![A-Za-z0-9_])@([A-Za-z0-9_]{3,32})\b")


class DiscoveredProfile(tuple):
    """Tuple subclass returning (is_candidate, relevance) while exposing match metadata."""

    _match_type: str
    _observed_username: str
    _requested_username: str

    def __new__(
        cls,
        is_candidate: bool,
        relevance: str,
        match_type: str = EXACT_MATCH,
        observed_username: str = "",
        requested_username: str = "",
    ) -> DiscoveredProfile:
        instance = super().__new__(cls, (is_candidate, relevance))
        instance._match_type = match_type
        instance._observed_username = observed_username
        instance._requested_username = requested_username
        return instance

    @property
    def is_candidate(self) -> bool:
        return self[0]

    @property
    def relevance(self) -> str:
        return self[1]

    @property
    def match_type(self) -> str:
        return self._match_type

    @property
    def observed_username(self) -> str:
        return self._observed_username

    @property
    def requested_username(self) -> str:
        return self._requested_username


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


def extract_candidate_handle(url: str, requested_username: str = "") -> str:
    """Extract potential profile handle from URL path."""
    path = _path(url)
    parts = [part.lstrip("@") for part in path.split("/") if part]
    if not parts:
        return ""
    # Check path hints (e.g. /u/handle, /users/handle, /profile/handle)
    for i, part in enumerate(parts):
        if f"/{part}/" in PROFILE_PATH_HINTS or f"/{part}" in PROFILE_PATH_HINTS:
            if i + 1 < len(parts):
                return parts[i + 1]
    # Check @handle in path
    for raw_part in path.split("/"):
        if raw_part.startswith("@") and len(raw_part) > 1:
            return raw_part.lstrip("@")
    # Check exact match in parts
    req_norm = requested_username.strip().lstrip("@").lower()
    if req_norm and req_norm in [p.lower() for p in parts]:
        return next(p for p in parts if p.lower() == req_norm)
    # Check similar match in parts
    if req_norm:
        for p in parts:
            if classify_username_match(req_norm, p) in {EXACT_MATCH, SIMILAR_CANDIDATE}:
                return p
    if parts and len(parts[0]) >= 3:
        return parts[0]
    return ""


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
) -> DiscoveredProfile:
    """Return DiscoveredProfile(is_candidate, relevance, match_type, observed, requested).

    Never upgrades to CONFIRMED.
    """
    handle = str(username or "").strip().lstrip("@")
    if not handle:
        return DiscoveredProfile(False, "", UNRELATED, "", "")

    observed_handle = extract_candidate_handle(url, requested_username=handle)
    match_type = classify_username_match(handle, observed_handle) if observed_handle else UNRELATED

    # Check title and snippet for handle mentions if URL path is not conclusive
    if match_type == UNRELATED:
        matched = match_username(handle, title=title, snippet=snippet, url=url)
        if matched is not None:
            match_type = EXACT_MATCH
            observed_handle = handle
        else:
            for found_handle in _HANDLE_RE.findall(f"{title} {snippet}"):
                c_type = classify_username_match(handle, found_handle)
                if c_type in {EXACT_MATCH, SIMILAR_CANDIDATE}:
                    match_type = c_type
                    observed_handle = found_handle
                    break

    if match_type == UNRELATED:
        return DiscoveredProfile(False, "", UNRELATED, "", handle)

    host = _host(url)
    known = host in {item.lower().removeprefix("www.") for item in (known_hosts or set())}
    snippet_l = f"{title} {snippet}".lower()
    profile_word = any(word in snippet_l for word in PROFILE_WORDS)
    in_path = bool(observed_handle and username_in_path(observed_handle, url))

    if in_path and (profile_word or known or looks_like_profile_url(url)):
        relevance, _, _ = classify_mention("username", "url_path_segment", title=title, snippet=snippet, url=url)
        return DiscoveredProfile(True, relevance or DIRECT, match_type, observed_handle, handle)
    if in_path:
        return DiscoveredProfile(True, DIRECT, match_type, observed_handle, handle)
    if looks_like_profile_url(url) and (known or profile_word):
        return DiscoveredProfile(True, DIRECT, match_type, observed_handle, handle)
    return DiscoveredProfile(False, "", match_type, observed_handle, handle)
