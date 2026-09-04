"""Public username-page evidence. HTTP 200 and the request URL are never enough."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from spectre_osint.core.logger import get_logger
from spectre_osint.core.types import Confidence, UsernameCheckStatus

# Both helpers live in matching.py so identity.py can reuse the strict URL identity
# test without importing this module's HTML stack.
from spectre_osint.modules.username.matching import (
    username_in_url_identity,
    username_needle,
)

logger = get_logger("spectre.username")


def username_token_in_text(text: str, username: str) -> bool:
    needle = username_needle(username)
    if not needle or not text:
        return False
    hay = text.lower()
    if f"@{needle}" in hay:
        return True
    return re.search(rf"(?<![a-z0-9_.-]){re.escape(needle)}(?![a-z0-9_.-])", hay) is not None


def classify_redirect(requested_url: str, final_url: str, username: str) -> str:
    if not requested_url or not final_url:
        return "same"
    req = urlparse(requested_url)
    fin = urlparse(final_url)
    req_host = (req.hostname or "").lower().removeprefix("www.")
    fin_host = (fin.hostname or "").lower().removeprefix("www.")
    req_path = (req.path or "/").rstrip("/") or "/"
    fin_path = (fin.path or "/").rstrip("/") or "/"
    if req_host == fin_host and req_path == fin_path:
        return "same"
    lowered = f"{fin_path} {fin.query} {final_url}".lower()
    if any(part in lowered for part in ("/login", "/signin", "/sign-in", "accounts/login", "/passport")):
        return "login"
    if any(part in lowered for part in ("/search", "q=", "query=", "/explore")):
        return "search"
    if fin_path in {"", "/"} and not username_in_url_identity(final_url, username):
        return "home"
    if fin_host and req_host and fin_host != req_host:
        return "other"
    return "other"


@dataclass
class PageSignals:
    status_code: int
    username: str
    requested_url: str
    final_url: str
    title: str = ""
    canonical: str = ""
    og_url: str = ""
    og_title: str = ""
    redirect: str = "same"
    identity: list[str] = field(default_factory=list)
    profile_marker: str = ""
    not_found_marker: str = ""
    soft_404_marker: str = ""
    login_marker: str = ""
    captcha_marker: str = ""
    challenge_marker: str = ""
    blocked_marker: str = ""
    jsonld_person: bool = False

    def tags(self) -> list[str]:
        out = list(self.identity)
        if self.profile_marker:
            out.append(f"profile_marker:{self.profile_marker}")
        if self.not_found_marker:
            out.append("not_found_marker")
        if self.soft_404_marker:
            out.append("soft_404_marker")
        if self.login_marker:
            out.append("login_marker")
        if self.redirect and self.redirect != "same":
            out.append(f"redirect_{self.redirect}")
        if not out:
            if username_in_url_identity(self.final_url, self.username):
                out.append("final_url_only")
            else:
                out.append("http_200_not_proof")
        return out


def _attr(html: str, kind: str, name: str) -> str:
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return ""
    if kind == "canonical":
        for link in soup.find_all("link"):
            rel = str(link.get("rel") or "").lower()
            if "canonical" in rel and link.get("href"):
                return str(link.get("href"))[:500]
        return ""
    meta = soup.find("meta", attrs={"property": name}) or soup.find("meta", attrs={"name": name})
    if meta and meta.get("content"):
        return str(meta.get("content"))[:500]
    return ""


def _jsonld_person_mentions(html: str, username: str) -> bool:
    needle = username_needle(username)
    if not needle:
        return False
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return False
    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        raw = script.string or script.get_text() or ""
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        blobs = data if isinstance(data, list) else [data]
        for blob in blobs:
            if not isinstance(blob, dict):
                continue
            types = blob.get("@type") or blob.get("type") or ""
            type_l = " ".join(types if isinstance(types, list) else [str(types)]).lower()
            if "person" not in type_l:
                continue
            if username_token_in_text(json.dumps(blob, ensure_ascii=False), username):
                return True
    return False


def collect_page_signals(
    *,
    status_code: int,
    body: str,
    title: str,
    final_url: str,
    username: str,
    site: dict[str, Any],
    requested_url: str = "",
    canonical_url: str = "",
    og_url: str = "",
    og_title: str = "",
) -> PageSignals:
    html = body or ""
    canonical = canonical_url or _attr(html, "canonical", "")
    og_url_v = og_url or _attr(html, "meta", "og:url")
    og_title_v = og_title or _attr(html, "meta", "og:title")
    title_v = title or ""
    requested = requested_url or final_url
    identity: list[str] = []
    if username_in_url_identity(canonical, username):
        identity.append("canonical_match")
    if username_in_url_identity(og_url_v, username):
        identity.append("og_url_match")
    if username_token_in_text(title_v, username):
        identity.append("title_match")
    if username_token_in_text(og_title_v, username):
        identity.append("og_title_match")
    jsonld = _jsonld_person_mentions(html, username)
    if jsonld:
        identity.append("jsonld_person")
    haystack = f"{title_v} {html[:12000]} {final_url}".lower()
    return PageSignals(
        status_code=status_code,
        username=username,
        requested_url=requested,
        final_url=final_url,
        title=title_v[:200],
        canonical=canonical[:500],
        og_url=og_url_v[:500],
        og_title=og_title_v[:200],
        redirect=classify_redirect(requested, final_url, username),
        identity=identity,
        profile_marker=_pattern_hit(haystack, site.get("profile_markers") or site.get("success_patterns")),
        not_found_marker=_pattern_hit(haystack, site.get("not_found_patterns")) or "",
        soft_404_marker=_pattern_hit(haystack, site.get("soft_404_patterns")) or "",
        login_marker=_pattern_hit(haystack, site.get("login_patterns")) or "",
        captcha_marker=_pattern_hit(haystack, site.get("captcha_patterns")) or "",
        challenge_marker=_pattern_hit(haystack, site.get("challenge_patterns")) or "",
        blocked_marker=_pattern_hit(haystack, site.get("blocked_patterns")) or "",
        jsonld_person=jsonld,
    )


def _pattern_hit(haystack: str, patterns: list[str] | None) -> str:
    for pattern in patterns or []:
        try:
            if re.search(pattern, haystack, re.I):
                return str(pattern)
        except re.error:
            if pattern.lower() in haystack:
                return str(pattern)
    return ""


def _likely(reason: str, tags: list[str], confidence: Confidence) -> tuple[UsernameCheckStatus, str, Confidence]:
    return UsernameCheckStatus.LIKELY, reason, confidence


def classify_pypi(signals: PageSignals, site: dict[str, Any]) -> tuple[UsernameCheckStatus, str, Confidence | None] | None:
    del site
    if signals.redirect == "home":
        return UsernameCheckStatus.NOT_FOUND, "pypi redirected to homepage", None
    if "canonical_match" in signals.identity and (
        "title_match" in signals.identity or "og_title_match" in signals.identity
    ):
        return _likely("pypi profile canonical + title", signals.tags(), Confidence.HIGH)
    return None


def classify_replit(signals: PageSignals, site: dict[str, Any]) -> tuple[UsernameCheckStatus, str, Confidence | None] | None:
    del site
    if signals.redirect in {"home", "search"}:
        return UsernameCheckStatus.NOT_FOUND, f"replit redirect_{signals.redirect}", None
    title = f"{signals.title} {signals.og_title}".lower()
    if title.strip() in {"", "replit", "replit – build software faster"}:
        return UsernameCheckStatus.INCONCLUSIVE, "replit generic shell", Confidence.LOW
    if ("canonical_match" in signals.identity or "og_url_match" in signals.identity) and (
        "title_match" in signals.identity or "og_title_match" in signals.identity
    ):
        return _likely("replit canonical/og:url + title", signals.tags(), Confidence.HIGH)
    return None


def classify_pinterest(signals: PageSignals, site: dict[str, Any]) -> tuple[UsernameCheckStatus, str, Confidence | None] | None:
    del site
    if signals.redirect in {"home", "search", "login"}:
        status = (
            UsernameCheckStatus.LOGIN_REQUIRED if signals.redirect == "login" else UsernameCheckStatus.NOT_FOUND
        )
        return status, f"pinterest redirect_{signals.redirect}", None
    if ("canonical_match" in signals.identity or "og_url_match" in signals.identity) and (
        "title_match" in signals.identity or "og_title_match" in signals.identity
    ):
        return _likely("pinterest profile url + title", signals.tags(), Confidence.HIGH)
    return None


def classify_steam(signals: PageSignals, site: dict[str, Any]) -> tuple[UsernameCheckStatus, str, Confidence | None] | None:
    del site
    path = urlparse(signals.final_url).path.lower()
    if re.search(r"/profiles/\d+", path):
        return UsernameCheckStatus.LIKELY, "steam custom url resolved to /profiles/", Confidence.HIGH
    if signals.redirect == "home":
        return UsernameCheckStatus.NOT_FOUND, "steam redirected to homepage", None
    if ("canonical_match" in signals.identity or "og_url_match" in signals.identity) and (
        "title_match" in signals.identity or "og_title_match" in signals.identity or signals.profile_marker
    ):
        return _likely("steam profile url + title/marker", signals.tags(), Confidence.HIGH)
    return None


def classify_lastfm(signals: PageSignals, site: dict[str, Any]) -> tuple[UsernameCheckStatus, str, Confidence | None] | None:
    del site
    if signals.redirect == "home":
        return UsernameCheckStatus.NOT_FOUND, "last.fm redirected to homepage", None
    if ("canonical_match" in signals.identity or "og_url_match" in signals.identity) and (
        "title_match" in signals.identity or "og_title_match" in signals.identity
    ):
        return _likely("last.fm /user canonical + title", signals.tags(), Confidence.HIGH)
    return None


def classify_telegram(signals: PageSignals, site: dict[str, Any]) -> tuple[UsernameCheckStatus, str, Confidence | None] | None:
    del site
    hay = f"{signals.title} {signals.og_title}".lower()
    has_photo = bool(signals.profile_marker) or "tgme_page_photo" in hay
    # Missing users still get a t.me contact shell; that is not NOT_FOUND.
    if not has_photo:
        return UsernameCheckStatus.INCONCLUSIVE, "telegram contact shell without profile photo", Confidence.LOW
    if "title_match" in signals.identity or "og_title_match" in signals.identity:
        return _likely("telegram tgme_page_photo + username title", signals.tags(), Confidence.MEDIUM)
    return UsernameCheckStatus.INCONCLUSIVE, "telegram photo without username title", Confidence.LOW


PROVIDER_HTML = {
    "PyPI": classify_pypi,
    "Replit": classify_replit,
    "Pinterest": classify_pinterest,
    "Steam": classify_steam,
    "Last.fm": classify_lastfm,
    "Telegram": classify_telegram,
}


def is_generic_page_title(title: str, username: str, site_name: str = "") -> bool:
    """True when a page title is platform branding or generic marketing boilerplate without user name."""
    raw = str(title or "").strip()
    if not raw:
        return True
    if username_token_in_text(raw, username):
        return False
    from spectre_osint.modules.search.novelty import is_generic_display_name

    return is_generic_display_name(raw, username, platform=site_name)


def classify_html_evidence(
    signals: PageSignals,
    site: dict[str, Any],
) -> tuple[UsernameCheckStatus, str, Confidence | None]:
    """Positive HTML classification. Negatives (404/login/captcha) are handled by classify_html."""
    if signals.soft_404_marker:
        return UsernameCheckStatus.NOT_FOUND, "soft_404_marker", None
    if signals.redirect == "login":
        return UsernameCheckStatus.LOGIN_REQUIRED, "redirect_login", None
    spec = str(site.get("name") or "")
    overlay = PROVIDER_HTML.get(spec)
    if overlay is not None:
        result = overlay(signals, site)
        if result is not None:
            return result
    home_policy = str(site.get("redirect_home") or "")
    search_policy = str(site.get("redirect_search") or "")
    if signals.redirect == "home" and home_policy == "not_found" and not signals.identity:
        return UsernameCheckStatus.NOT_FOUND, "redirect_home", None
    if signals.redirect == "search" and search_policy == "not_found" and not signals.identity:
        return UsernameCheckStatus.NOT_FOUND, "redirect_search", None

    strategy = str(site.get("confidence_strategy") or "multi_signal")
    title_id = "title_match" in signals.identity or "og_title_match" in signals.identity
    url_id = "canonical_match" in signals.identity or "og_url_match" in signals.identity
    has_marker = bool(signals.profile_marker)
    generic_title = is_generic_page_title(signals.title or signals.og_title, signals.username, spec)

    if title_id and url_id and not generic_title:
        conf = Confidence.HIGH
        reason = "title + canonical/og:url: " + ",".join(signals.identity)
    elif title_id and not generic_title:
        conf = Confidence.MEDIUM
        reason = "username in title/og:title"
    elif url_id and has_marker and not generic_title:
        conf = Confidence.MEDIUM
        reason = "canonical/og:url + profile marker"
    elif len(signals.identity) >= 2 and not generic_title:
        conf = Confidence.MEDIUM
        reason = "two identity signals: " + ",".join(signals.identity)
    else:
        tags = signals.tags()
        if generic_title and (signals.title or signals.og_title):
            tags.append("generic_platform_title")
        return (
            UsernameCheckStatus.INCONCLUSIVE,
            "HTTP 200 is not proof (" + ",".join(tags) + ")",
            Confidence.LOW,
        )
    if strategy == "never_confirmed":
        reason = reason + " (never_confirmed)"
    return UsernameCheckStatus.LIKELY, reason, conf


def log_provider_evidence(
    site_name: str,
    status: UsernameCheckStatus,
    confidence: Confidence | None,
    signals: PageSignals,
) -> None:
    conf = confidence.value if confidence is not None else "-"
    logger.debug(
        "provider=%s status=%s confidence=%s evidence=%s",
        site_name,
        status.value,
        conf,
        ",".join(signals.tags()) or "none",
    )
