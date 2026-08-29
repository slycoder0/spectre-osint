"""Username presence engine. HTTP 200 is never sufficient for CONFIRMED."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from spectre_osint.core.config import get_settings
from spectre_osint.core.entities import Entity, Finding, Relationship
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import (
    ProviderUnavailable,
    RateLimitExceeded,
    UnofficialHttpStatus,
)
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.logger import get_logger
from spectre_osint.core.redaction import redact_text
from spectre_osint.core.result_cache import ResultCache
from spectre_osint.core.types import (
    AccessMode,
    CacheState,
    Confidence,
    EntityType,
    FindingStatus,
    RelationType,
    UsernameCheckStatus,
)
from spectre_osint.modules.username.catalog import load_catalog
from spectre_osint.modules.username.correlate import link_public_website
from spectre_osint.modules.username.enrichment import enrich_profile, flatten_observed
from spectre_osint.modules.username.evidence import (
    classify_html_evidence,
    collect_page_signals,
    log_provider_evidence,
)
from spectre_osint.modules.username.identity import identity_artifacts

logger = get_logger("spectre.username")

STATUS_TO_FINDING = {
    UsernameCheckStatus.CONFIRMED: FindingStatus.FOUND,
    UsernameCheckStatus.LIKELY: FindingStatus.FOUND,
    UsernameCheckStatus.NOT_FOUND: FindingStatus.NOT_FOUND,
    UsernameCheckStatus.INCONCLUSIVE: FindingStatus.INCONCLUSIVE,
    UsernameCheckStatus.BLOCKED: FindingStatus.BLOCKED,
    UsernameCheckStatus.LOGIN_REQUIRED: FindingStatus.LOGIN_REQUIRED,
    UsernameCheckStatus.RATE_LIMITED: FindingStatus.RATE_LIMITED,
    UsernameCheckStatus.PROVIDER_UNAVAILABLE: FindingStatus.PROVIDER_UNAVAILABLE,
    UsernameCheckStatus.SESSION_EXPIRED: FindingStatus.SESSION_EXPIRED,
    UsernameCheckStatus.CHALLENGE_REQUIRED: FindingStatus.CHALLENGE_REQUIRED,
    UsernameCheckStatus.CAPTCHA_REQUIRED: FindingStatus.CAPTCHA_REQUIRED,
    UsernameCheckStatus.TEMPORARILY_LIMITED: FindingStatus.TEMPORARILY_LIMITED,
    UsernameCheckStatus.OAUTH_BROWSER_REJECTED: FindingStatus.OAUTH_BROWSER_REJECTED,
}

STATUS_TO_CONFIDENCE = {
    UsernameCheckStatus.CONFIRMED: Confidence.CONFIRMED,
    UsernameCheckStatus.LIKELY: Confidence.MEDIUM,
    UsernameCheckStatus.NOT_FOUND: None,
    UsernameCheckStatus.INCONCLUSIVE: Confidence.LOW,
    UsernameCheckStatus.BLOCKED: None,
    UsernameCheckStatus.LOGIN_REQUIRED: None,
    UsernameCheckStatus.RATE_LIMITED: None,
    UsernameCheckStatus.PROVIDER_UNAVAILABLE: None,
    UsernameCheckStatus.SESSION_EXPIRED: None,
    UsernameCheckStatus.CHALLENGE_REQUIRED: None,
    UsernameCheckStatus.CAPTCHA_REQUIRED: None,
    UsernameCheckStatus.TEMPORARILY_LIMITED: None,
    UsernameCheckStatus.OAUTH_BROWSER_REJECTED: None,
}


def load_sites(path: Path | None = None) -> list[dict[str, Any]]:
    catalog = load_catalog(path)
    return catalog.to_dict_list(enabled_only=True)


def _pattern_hit(haystack: str, patterns: list[str] | None) -> str | None:
    for pattern in patterns or []:
        try:
            if re.search(pattern, haystack, re.I):
                return pattern
        except re.error:
            if pattern.lower() in haystack:
                return pattern
    return None


def _dig(data: Any, path: str) -> Any:
    cur: Any = data
    for part in path.split("."):
        if isinstance(cur, list) and part.isdigit():
            idx = int(part)
            if idx >= len(cur):
                return None
            cur = cur[idx]
            continue
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def classify_html(
    *,
    status_code: int,
    body: str,
    title: str,
    final_url: str,
    site: dict[str, Any],
    username: str,
    requested_url: str = "",
    canonical_url: str = "",
    og_url: str = "",
    og_title: str = "",
) -> tuple[UsernameCheckStatus, str, Confidence | None]:
    method = str(site.get("check_method") or "generic_html")
    haystack = f"{title} {body[:12000]} {final_url}".lower()
    expected = set(site.get("expected_status") or [200])
    not_found_status = set(site.get("not_found_status") or [404, 410])

    if status_code == 429:
        return UsernameCheckStatus.RATE_LIMITED, "HTTP 429", None
    if _pattern_hit(haystack, site.get("captcha_patterns")):
        return UsernameCheckStatus.CAPTCHA_REQUIRED, "captcha presented — not solved", None
    if _pattern_hit(haystack, site.get("challenge_patterns")):
        return UsernameCheckStatus.CHALLENGE_REQUIRED, "challenge presented — not bypassed", None
    if status_code in {401, 403} or _pattern_hit(haystack, site.get("blocked_patterns")):
        if _pattern_hit(haystack, site.get("login_patterns")) or method == "login_wall":
            return UsernameCheckStatus.LOGIN_REQUIRED, f"HTTP {status_code} login/wall", None
        return UsernameCheckStatus.BLOCKED, f"HTTP {status_code} blocked", None
    if status_code in not_found_status:
        return UsernameCheckStatus.NOT_FOUND, f"HTTP {status_code}", None
    if status_code >= 500:
        return UsernameCheckStatus.PROVIDER_UNAVAILABLE, f"HTTP {status_code}", None

    if method == "login_wall":
        if _pattern_hit(haystack, site.get("not_found_patterns")):
            return UsernameCheckStatus.NOT_FOUND, "not_found_pattern", None
        return UsernameCheckStatus.LOGIN_REQUIRED, "login wall / no public profile API", None

    if _pattern_hit(haystack, site.get("login_patterns")):
        return UsernameCheckStatus.LOGIN_REQUIRED, "login_pattern", None
    if _pattern_hit(haystack, site.get("not_found_patterns")):
        return UsernameCheckStatus.NOT_FOUND, "soft-404 / not_found_pattern", None

    if status_code not in expected and not (200 <= status_code < 400):
        return UsernameCheckStatus.INCONCLUSIVE, f"HTTP {status_code}", Confidence.LOW

    signals = collect_page_signals(
        status_code=status_code,
        body=body,
        title=title,
        final_url=final_url,
        username=username,
        site=site,
        requested_url=requested_url,
        canonical_url=canonical_url,
        og_url=og_url,
        og_title=og_title,
    )
    status, reason, conf = classify_html_evidence(signals, site)
    log_provider_evidence(str(site.get("name") or "html"), status, conf, signals)
    return status, reason, conf


def username_evidence_report(
    *,
    status_code: int,
    body: str,
    title: str,
    final_url: str,
    site: dict[str, Any],
    username: str,
    canonical_url: str = "",
    og_url: str = "",
    og_title: str = "",
    content_length: int = 0,
) -> dict[str, Any]:
    """Safe diagnostic flags. Never includes body HTML, cookies, or tokens."""
    needle = (username or "").lower().lstrip("@")
    haystack = f"{title} {body[:12000]} {final_url}".lower()
    login_hit = _pattern_hit(haystack, site.get("login_patterns"))
    captcha_hit = _pattern_hit(haystack, site.get("captcha_patterns"))
    challenge_hit = _pattern_hit(haystack, site.get("challenge_patterns"))
    not_found_hit = _pattern_hit(haystack, site.get("not_found_patterns"))
    blocked_hit = _pattern_hit(haystack, site.get("blocked_patterns"))
    success_hit = _pattern_hit(haystack, site.get("success_patterns"))
    in_final = bool(needle) and needle in (urlparse(final_url).path or "").lower()
    in_canonical = bool(needle) and needle in (canonical_url or "").lower()
    in_og_url = bool(needle) and needle in (og_url or "").lower()
    in_title = bool(needle) and needle in (title or "").lower()
    in_og_title = bool(needle) and needle in (og_title or "").lower()
    positive = []
    negative = []
    if success_hit:
        positive.append(f"success_pattern:{success_hit}")
    if in_title:
        positive.append("username_in_title")
    if in_canonical:
        positive.append("username_in_canonical")
    if in_og_url:
        positive.append("username_in_og_url")
    if in_og_title:
        positive.append("username_in_og_title")
    if captcha_hit:
        negative.append(f"captcha:{captcha_hit}")
    if challenge_hit:
        negative.append(f"challenge:{challenge_hit}")
    if login_hit:
        negative.append(f"login_wall:{login_hit}")
    if not_found_hit:
        negative.append(f"not_found:{not_found_hit}")
    if blocked_hit:
        negative.append(f"blocked:{blocked_hit}")
    if not positive and status_code == 200:
        negative.append("http_200_not_proof")
    length = content_length if content_length else len(body or "")
    return {
        "http_status": status_code,
        "final_url": final_url,
        "title": (title or "")[:200],
        "canonical_url": (canonical_url or "")[:500],
        "og_url": (og_url or "")[:500],
        "og_title": (og_title or "")[:200],
        "username_in_final_url": in_final,
        "username_in_canonical": in_canonical,
        "username_in_og_url": in_og_url,
        "username_in_title": in_title,
        "username_in_og_title": in_og_title,
        "login_wall": bool(login_hit),
        "captcha": bool(captcha_hit),
        "challenge": bool(challenge_hit),
        "not_found": bool(not_found_hit),
        "success_pattern": success_hit or "",
        "positive_rules": positive,
        "negative_rules": negative,
        "content_length": int(length),
        "strategy": str(site.get("confidence_strategy") or ""),
        "check_method": str(site.get("check_method") or ""),
    }


def _is_instagram_site(site: dict[str, Any] | None) -> bool:
    raw = str((site or {}).get("auth_platform") or (site or {}).get("name") or "").strip().lower()
    return raw in {"instagram", "ig"}


def _instagram_profile_url_for_username(url: str, username: str) -> bool:
    needle = (username or "").lower().lstrip("@")
    if not needle:
        return False
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if host != "instagram.com":
        return False
    parts = [p.lstrip("@") for p in (parsed.path or "").lower().strip("/").split("/") if p]
    return bool(parts) and parts[0] == needle


def _instagram_title_has_username(text: str, username: str) -> bool:
    needle = (username or "").lower().lstrip("@")
    if not needle:
        return False
    hay = (text or "").lower()
    if f"@{needle}" in hay:
        return True
    return re.search(rf"(?<![a-z0-9_.]){re.escape(needle)}(?![a-z0-9_.])", hay) is not None


def classify_instagram_authenticated_public(
    *,
    username: str,
    requested_url: str,
    final_url: str,
    canonical_url: str = "",
    og_url: str = "",
    og_title: str = "",
    title: str = "",
    body: str = "",
    site: dict[str, Any] | None = None,
) -> tuple[UsernameCheckStatus, str, Confidence] | None:
    """Instagram AUTHENTICATED_PUBLIC overlay. Never CONFIRMED. None = do not override."""
    spec = site or {}
    haystack = f"{title} {og_title} {body[:12000]} {final_url} {canonical_url} {og_url}".lower()
    if _pattern_hit(haystack, spec.get("captcha_patterns")):
        return None
    if _pattern_hit(haystack, spec.get("challenge_patterns")):
        return None
    if _pattern_hit(haystack, spec.get("login_patterns")):
        return None
    if _pattern_hit(haystack, spec.get("not_found_patterns")):
        return None
    if _pattern_hit(haystack, spec.get("blocked_patterns")):
        return None
    if not _instagram_profile_url_for_username(final_url, username):
        return None
    if requested_url and not _instagram_profile_url_for_username(requested_url, username):
        return None
    canonical_ok = _instagram_profile_url_for_username(canonical_url, username)
    og_url_ok = _instagram_profile_url_for_username(og_url, username)
    if not canonical_ok and not og_url_ok:
        return None
    if canonical_url and og_url and canonical_ok != og_url_ok:
        return None
    title_ok = _instagram_title_has_username(og_title, username) or _instagram_title_has_username(title, username)
    if not title_ok:
        return None
    return (
        UsernameCheckStatus.LIKELY,
        "instagram authenticated public metadata (profile url + canonical/og:url + og:title)",
        Confidence.HIGH,
    )


async def analyze_username(
    entity: Entity,
    http: HttpClient,
    *,
    categories: list[str] | None = None,
    concurrency: int = 8,
    refresh: bool = False,
    result_cache: ResultCache | None = None,
    auth_service: Any | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
    include_identity: bool = True,
) -> dict[str, Any]:
    sites = load_sites()
    if categories:
        wanted = {c.lower() for c in categories}
        sites = [s for s in sites if str(s.get("category", "")).lower() in wanted]
    settings = http.settings if hasattr(http, "settings") else get_settings()
    cache = result_cache if result_cache is not None else ResultCache(settings)
    if auth_service is None:
        from spectre_osint.browser.auth import AuthService

        auth_service = AuthService(settings)
    semaphore = asyncio.Semaphore(concurrency)
    completed = 0
    lock = asyncio.Lock()

    def _emit(payload: dict[str, Any]) -> None:
        if progress is None:
            return
        try:
            progress(payload)
        except Exception:  # noqa: BLE001
            logger.debug("username progress callback failed", exc_info=True)

    _emit({
        "phase": "catalog",
        "state": "running",
        "current": 0,
        "total": len(sites),
        "done": 0,
    })

    async def _tracked(site: dict[str, Any]) -> Any:
        nonlocal completed
        item: Any = None
        try:
            item = await _check_site(
                entity,
                site,
                http,
                semaphore,
                refresh=refresh,
                result_cache=cache,
                auth_service=auth_service,
            )
            return item
        finally:
            async with lock:
                completed += 1
                current = completed
            source_name = str(site.get("name") or site.get("platform") or "")
            source_status = ""
            if isinstance(item, dict) and item.get("finding") is not None:
                finding = item["finding"]
                data = finding.data or {}
                source_name = str(data.get("platform") or source_name)
                source_status = str(data.get("check_status") or finding.status.value or "")
            _emit(
                {
                    "phase": "catalog",
                    "state": "running",
                    "current": current,
                    "total": len(sites),
                    "done": current,
                    "provider": source_name,
                    "source": source_name,
                    "message": source_status,
                    "source_status": source_status,
                }
            )

    results = await asyncio.gather(*(_tracked(site) for site in sites), return_exceptions=True)
    _emit({
        "phase": "catalog",
        "state": "completed",
        "current": len(sites),
        "total": len(sites),
        "done": len(sites),
    })
    findings: list[Finding] = []
    extras: list[Entity] = [entity]
    rels: list[Relationship] = []
    evidence = []
    hits = []
    for item in results:
        if not isinstance(item, dict):
            logger.warning("Username site check failed: %s", item)
            continue
        findings.append(item["finding"])
        evidence.extend(item["evidence"])
        extras.extend(item["entities"])
        rels.extend(item["relationships"])
        if item["finding"].status == FindingStatus.FOUND:
            hits.append(item["finding"].data)
    summary = Finding(
        module="username",
        title="Username sweep",
        status=FindingStatus.FOUND if hits else FindingStatus.NOT_FOUND,
        summary=f"{len(hits)} public profiles matched out of {len(sites)} sites",
        data={"hits": hits, "sites_checked": len(sites)},
        confidence=Confidence.MEDIUM if hits else None,
        entity_id=entity.id,
    )
    findings.insert(0, summary)
    artifacts: dict[str, Any] = {
        "findings": [],
        "entities": [],
        "relationships": [],
        "identity_correlation": None,
    }
    if include_identity:
        _emit({"phase": "correlating", "done": completed, "total": len(sites)})
        artifacts = identity_artifacts(findings, entity)
        findings.extend(artifacts["findings"])
        extras.extend(artifacts["entities"])
        rels.extend(artifacts["relationships"])
    return {
        "findings": findings,
        "entities": extras,
        "relationships": rels,
        "evidence": evidence,
        "providers_queried": ["username-sites"],
        "identity_correlation": artifacts["identity_correlation"],
    }


def _username_transport_finding(
    entity: Entity,
    name: str,
    username: str,
    profile_url: str,
    check_status: UsernameCheckStatus,
    finding_status: FindingStatus,
    reason: str,
) -> dict[str, Any]:
    finding = Finding(
        module="username",
        title=name,
        status=finding_status,
        summary=redact_text(f"{check_status.value}: {reason}"),
        data={
            "platform": name,
            "site": name,
            "profile_url": profile_url,
            "username": username,
            "check_status": check_status.value,
            "access_mode": AccessMode.ANONYMOUS_PUBLIC.value,
            "cache_state": CacheState.LIVE.value,
            "reason": reason,
        },
        entity_id=entity.id,
    )
    return {"finding": finding, "evidence": [], "entities": [], "relationships": []}


async def _check_site(
    entity: Entity,
    site: dict[str, Any],
    http: HttpClient,
    semaphore: asyncio.Semaphore,
    *,
    refresh: bool = False,
    result_cache: ResultCache | None = None,
    auth_service: Any | None = None,
) -> dict[str, Any]:
    username = entity.normalized_value
    profile_url = str(site.get("profile_url") or site["url_template"]).format(username=username)
    check_url = str(site.get("check_url") or profile_url).format(username=username)
    name = site["name"]
    method = str(site.get("check_method") or "generic_html")
    requires_auth = bool(site.get("requires_auth", False))
    auth_platform = str(site.get("auth_platform") or "").strip().lower() if requires_auth else ""
    if not refresh and result_cache is not None:
        cached_auth = result_cache.get(
            "username", name, username, AccessMode.AUTHENTICATED_PUBLIC.value
        )
        if (
            cached_auth
            and requires_auth
            and auth_platform
            and auth_service is not None
            and auth_service.has_active(auth_platform)
        ):
            return _bundle_from_cached(entity, cached_auth.payload, cached_auth)
        cached = result_cache.get("username", name, username, AccessMode.ANONYMOUS_PUBLIC.value)
        if cached and cached.payload.get("check_status") != UsernameCheckStatus.LOGIN_REQUIRED.value:
            return _bundle_from_cached(entity, cached.payload, cached)
        if cached and cached.payload.get("check_status") == UsernameCheckStatus.LOGIN_REQUIRED.value:
            if not requires_auth or not auth_platform or auth_service is None or not auth_service.has_active(auth_platform):
                return _bundle_from_cached(entity, cached.payload, cached)
    min_interval = site.get("rate_limit")
    try:
        min_interval_f = float(min_interval) if min_interval is not None else None
    except (TypeError, ValueError):
        min_interval_f = None
    http_method = str(site.get("http_method") or "GET").strip().upper()
    custom_headers = site.get("headers") or None
    async with semaphore:
        try:
            if http_method == "HEAD" and hasattr(http, "head"):
                response = await http.head(
                    check_url,
                    provider=name,
                    headers=custom_headers,
                    follow_redirects=True,
                    use_cache=not refresh,
                    accept_statuses=set(range(200, 600)),
                    min_interval=min_interval_f,
                )
            elif http_method == "GET" and hasattr(http, "get"):
                response = await http.get(
                    check_url,
                    provider=name,
                    headers=custom_headers,
                    follow_redirects=True,
                    use_cache=not refresh,
                    accept_statuses=set(range(200, 600)),
                    min_interval=min_interval_f,
                )
            else:
                response = await http.request(
                    http_method,
                    check_url,
                    provider=name,
                    headers=custom_headers,
                    follow_redirects=True,
                    use_cache=not refresh,
                    accept_statuses=set(range(200, 600)),
                    min_interval=min_interval_f,
                )
        except asyncio.CancelledError:
            raise
        except RateLimitExceeded as exc:
            return _username_transport_finding(
                entity,
                name,
                username,
                profile_url,
                UsernameCheckStatus.RATE_LIMITED,
                FindingStatus.RATE_LIMITED,
                redact_text(str(exc)),
            )
        except UnofficialHttpStatus as exc:
            return _username_transport_finding(
                entity,
                name,
                username,
                profile_url,
                UsernameCheckStatus.PROVIDER_UNAVAILABLE,
                FindingStatus.PROVIDER_UNAVAILABLE,
                f"unofficial HTTP {exc.status_code} (peer/proxy; not synthesized)",
            )
        except ProviderUnavailable as exc:
            return _username_transport_finding(
                entity,
                name,
                username,
                profile_url,
                UsernameCheckStatus.PROVIDER_UNAVAILABLE,
                FindingStatus.PROVIDER_UNAVAILABLE,
                redact_text(str(exc)),
            )
        except Exception as exc:  # noqa: BLE001
            return _username_transport_finding(
                entity,
                name,
                username,
                profile_url,
                UsernameCheckStatus.PROVIDER_UNAVAILABLE,
                FindingStatus.PROVIDER_UNAVAILABLE,
                redact_text(f"{type(exc).__name__}"),
            )

    body = response.text[:50_000]
    title, description, public_name, avatar, website, canonical = _extract_profile_fields(body)
    json_website = None
    json_name = None
    json_bio = None
    json_avatar = None
    json_location = None
    json_ok = False
    data: Any = None

    if method == "json_api":
        data = response.json_data
        if response.status_code in set(site.get("not_found_status") or [404, 410]):
            status, reason, conf = UsernameCheckStatus.NOT_FOUND, f"HTTP {response.status_code}", None
        elif response.status_code == 429:
            status, reason, conf = UsernameCheckStatus.RATE_LIMITED, "HTTP 429", None
        elif response.status_code in {401, 403}:
            status, reason, conf = UsernameCheckStatus.BLOCKED, f"HTTP {response.status_code}", None
        elif response.status_code >= 500 or data is None:
            status, reason, conf = (
                UsernameCheckStatus.PROVIDER_UNAVAILABLE,
                f"HTTP {response.status_code} or invalid JSON",
                None,
            )
        else:
            id_field = site.get("json_id_field") or "login"
            ident = _dig(data, id_field) if isinstance(data, dict) else None
            json_ok = ident is not None
            json_name = None
            for field in site.get("display_name_fields") or ["name", "displayName"]:
                val = _dig(data, field) if isinstance(data, dict) else None
                if val:
                    json_name = str(val)
                    break
            for field in site.get("website_fields") or ["blog", "url", "website"]:
                val = _dig(data, field) if isinstance(data, dict) else None
                if val:
                    json_website = str(val)
                    break
            json_bio = _dig(data, site.get("bio_field") or "bio") if isinstance(data, dict) else None
            json_avatar = (
                _dig(data, site.get("avatar_field") or "avatar_url") if isinstance(data, dict) else None
            )
            json_location = (
                _dig(data, site.get("location_field") or "location") if isinstance(data, dict) else None
            )
            if json_ok:
                status = UsernameCheckStatus.CONFIRMED
                reason = f"JSON identity field {id_field}={ident}"
                conf = Confidence.CONFIRMED
            else:
                status, reason, conf = (
                    UsernameCheckStatus.NOT_FOUND,
                    "JSON 200 without identity field",
                    None,
                )
            logger.debug(
                "provider=%s status=%s confidence=%s evidence=%s",
                name,
                status.value,
                conf.value if conf is not None else "-",
                "json_id" if json_ok else "json_missing_id",
            )
    else:
        status, reason, conf = classify_html(
            status_code=response.status_code,
            body=body,
            title=title or "",
            final_url=response.url,
            site=site,
            username=username,
            requested_url=profile_url,
            canonical_url=canonical or "",
            og_title=public_name or "",
        )

    access_mode = AccessMode.ANONYMOUS_PUBLIC
    anonymous_status = status.value
    authenticated_status = None
    session_status = None
    auth_meta: dict[str, str] = {}
    if status == UsernameCheckStatus.LOGIN_REQUIRED and requires_auth and auth_platform and auth_service is not None:
        auth_hit = await _authenticated_public(auth_service, site, username, profile_url)
        if auth_hit is not None:
            status, reason, conf, access_mode, session_status, auth_meta = auth_hit
            authenticated_status = status.value

    finding_status = STATUS_TO_FINDING[status]
    confidence = conf if conf is not None else STATUS_TO_CONFIDENCE[status]
    if (
        status == UsernameCheckStatus.LIKELY
        and (json_name or public_name)
        and username.lower() in str(json_name or public_name).lower()
    ):
        confidence = Confidence.HIGH

    observed: dict[str, Any] = {}
    if status in {UsernameCheckStatus.CONFIRMED, UsernameCheckStatus.LIKELY}:
        json_blob = data if method == "json_api" and isinstance(data, dict) else None
        html_blob = "" if access_mode == AccessMode.AUTHENTICATED_PUBLIC else (body or "")
        observed = enrich_profile(
            platform=name,
            username=username,
            profile_url=profile_url,
            site=site,
            json_data=json_blob,
            html=html_blob,
            meta={
                "og_title": str(auth_meta.get("og_title") or public_name or ""),
                "og_url": str(auth_meta.get("og_url") or ""),
                "canonical": str(auth_meta.get("canonical_url") or canonical or ""),
                "title": str(auth_meta.get("title") or title or ""),
                "og_image": str(avatar or ""),
            },
        )
    flat = flatten_observed(observed)

    payload = {
        "platform": name,
        "site": name,
        "username": username,
        "profile_url": profile_url,
        "final_url": response.url,
        "display_name": flat.get("display_name") if observed else (json_name or public_name),
        "bio": flat.get("bio") if observed else (str(json_bio)[:300] if json_bio else description),
        "avatar_url": flat.get("avatar_url") if observed else (json_avatar or avatar),
        "website": flat.get("website") if observed else (json_website or website),
        "public_location": flat.get("public_location") if observed else json_location,
        "organization": flat.get("organization"),
        "public_email": flat.get("public_email"),
        "public_id": flat.get("public_id"),
        "public_links": flat.get("public_links") or ([json_website or website] if (json_website or website) else []),
        "observed": observed,
        "verification_status": status.value,
        "check_status": status.value,
        "checked_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "confidence": confidence.value if confidence else None,
        "http_status": response.status_code,
        "category": site.get("category"),
        "reason": reason,
        "page_title": title,
        "canonical": canonical,
        "status": status.value,
        "access_mode": access_mode.value,
        "cache_state": CacheState.REFRESHED.value if refresh else CacheState.LIVE.value,
        "anonymous_status": anonymous_status,
        "authenticated_status": authenticated_status,
        "session_status": session_status,
    }
    if result_cache is not None and status not in {
        UsernameCheckStatus.RATE_LIMITED,
        UsernameCheckStatus.PROVIDER_UNAVAILABLE,
    }:
        result_cache.set(
            "username",
            name,
            username,
            payload,
            access_mode=access_mode.value,
        )

    finding = Finding(
        module="username",
        title=name,
        status=finding_status,
        summary=f"{name}: {status.value}"
        + (f" {profile_url}" if profile_url else "")
        + (f" ({reason})" if reason and status not in {UsernameCheckStatus.CONFIRMED, UsernameCheckStatus.LIKELY} else ""),
        data=payload,
        confidence=confidence,
        entity_id=entity.id,
    )
    if status not in {UsernameCheckStatus.CONFIRMED, UsernameCheckStatus.LIKELY}:
        return {"finding": finding, "evidence": [], "entities": [], "relationships": []}

    evidence = make_evidence(
        source=name,
        provider="username",
        confidence=confidence or Confidence.MEDIUM,
        url=response.url,
        raw={
            "title": title,
            "http_status": response.status_code,
            "public_name": json_name or public_name,
            "check_status": status.value,
            "reason": reason,
        },
        entity_id=entity.id,
        notes="Presence indicator only. Same username ≠ confirmed identity.",
    )
    profile = Entity.create(
        EntityType.SOCIAL_PROFILE,
        profile_url,
        source=name,
        confidence=confidence or Confidence.MEDIUM,
        tags=[str(site.get("category") or "unknown").lower(), "username"],
        metadata={"site": name, "username": username, "public_name": json_name or public_name},
    )
    rel = Relationship(
        from_entity_id=entity.id,
        to_entity_id=profile.id,
        relation=RelationType.HAS_PROFILE,
        source=name,
        confidence=confidence or Confidence.MEDIUM,
        evidence_id=evidence.id,
    )
    linked = link_public_website(
        entity,
        json_website or website,
        source=name,
        evidence_id=evidence.id,
        confidence=confidence or Confidence.MEDIUM,
    )
    return {
        "finding": finding,
        "evidence": [evidence],
        "entities": [profile, *linked["entities"]],
        "relationships": [rel, *linked["relationships"]],
    }


def _auth_meta(outcome: Any) -> dict[str, str]:
    if outcome is None:
        return {}
    return {
        "title": str(getattr(outcome, "title", "") or ""),
        "url": str(getattr(outcome, "url", "") or ""),
        "canonical_url": str(getattr(outcome, "canonical_url", "") or ""),
        "og_url": str(getattr(outcome, "og_url", "") or ""),
        "og_title": str(getattr(outcome, "og_title", "") or ""),
    }


async def _authenticated_public(
    auth_service: Any,
    site: dict[str, Any],
    username: str,
    profile_url: str,
) -> tuple[UsernameCheckStatus, str, Confidence | None, AccessMode, str, dict[str, str]] | None:
    from spectre_osint.core.types import SessionStatus

    if not auth_service.has_active(str(site.get("auth_platform") or site.get("name") or "")):
        return None
    try:
        outcome = await auth_service.fetch_public_profile(site["name"], username, profile_url)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Authenticated public fetch failed: %s", type(exc).__name__)
        return None
    if outcome is None:
        return None

    def _done(
        classified: UsernameCheckStatus,
        reason: str,
        conf: Confidence | None,
        access: AccessMode,
        session: str,
    ) -> tuple[UsernameCheckStatus, str, Confidence | None, AccessMode, str, dict[str, str]]:
        _log_authenticated_public_evidence(
            site,
            username,
            profile_url,
            outcome,
            classified=classified,
            reason=reason,
        )
        return classified, reason, conf, access, session, _auth_meta(outcome)

    if outcome.redirected_to_login or outcome.status == UsernameCheckStatus.SESSION_EXPIRED.value:
        return _done(
            UsernameCheckStatus.SESSION_EXPIRED,
            "session expired — manual login required",
            None,
            AccessMode.AUTHENTICATED_PUBLIC,
            SessionStatus.EXPIRED.value,
        )
    if outcome.status == UsernameCheckStatus.CAPTCHA_REQUIRED.value:
        return _done(
            UsernameCheckStatus.CAPTCHA_REQUIRED,
            "CAPTCHA presented — not solved",
            None,
            AccessMode.AUTHENTICATED_PUBLIC,
            SessionStatus.CAPTCHA_REQUIRED.value,
        )
    if outcome.status == UsernameCheckStatus.CHALLENGE_REQUIRED.value:
        return _done(
            UsernameCheckStatus.CHALLENGE_REQUIRED,
            "challenge presented — not bypassed",
            None,
            AccessMode.AUTHENTICATED_PUBLIC,
            SessionStatus.CHALLENGE_REQUIRED.value,
        )
    if outcome.status == UsernameCheckStatus.TEMPORARILY_LIMITED.value:
        return _done(
            UsernameCheckStatus.TEMPORARILY_LIMITED,
            "login temporarily limited — not retried",
            None,
            AccessMode.AUTHENTICATED_PUBLIC,
            SessionStatus.TEMPORARILY_LIMITED.value,
        )
    if outcome.status == UsernameCheckStatus.OAUTH_BROWSER_REJECTED.value:
        return _done(
            UsernameCheckStatus.OAUTH_BROWSER_REJECTED,
            "OAuth refused this automated browser — not bypassed",
            None,
            AccessMode.AUTHENTICATED_PUBLIC,
            SessionStatus.OAUTH_BROWSER_REJECTED.value,
        )
    if outcome.status == UsernameCheckStatus.BLOCKED.value:
        return _done(
            UsernameCheckStatus.BLOCKED,
            "blocked — not bypassed",
            None,
            AccessMode.AUTHENTICATED_PUBLIC,
            SessionStatus.BLOCKED.value,
        )
    session_failures = {
        SessionStatus.CDP_UNAVAILABLE.value,
        SessionStatus.CHROME_NOT_FOUND.value,
        SessionStatus.CHROME_PROFILE_LOCKED.value,
        SessionStatus.WINDOWS_CDP_LAUNCH_FAILED.value,
        SessionStatus.UNAVAILABLE.value,
        UsernameCheckStatus.PROVIDER_UNAVAILABLE.value,
    }
    if outcome.status in session_failures:
        session_status = (
            SessionStatus.UNAVAILABLE.value
            if outcome.status == UsernameCheckStatus.PROVIDER_UNAVAILABLE.value
            else outcome.status
        )
        return _done(
            UsernameCheckStatus.PROVIDER_UNAVAILABLE,
            outcome.detail or outcome.status,
            None,
            AccessMode.AUTHENTICATED_PUBLIC,
            session_status,
        )
    public_site = dict(site)
    public_site["check_method"] = "generic_html"
    classified, reason, conf = classify_html(
        status_code=outcome.status_code if outcome.status_code else 0,
        body=outcome.body or "",
        title=outcome.title or "",
        final_url=outcome.url,
        site=public_site,
        username=username,
    )
    if classified == UsernameCheckStatus.LOGIN_REQUIRED:
        classified = UsernameCheckStatus.SESSION_EXPIRED
        reason = "session expired — manual login required"
        return _done(classified, reason, None, AccessMode.AUTHENTICATED_PUBLIC, SessionStatus.EXPIRED.value)
    if _is_instagram_site(site) and classified in {
        UsernameCheckStatus.INCONCLUSIVE,
        UsernameCheckStatus.LIKELY,
    }:
        instagram = classify_instagram_authenticated_public(
            username=username,
            requested_url=profile_url,
            final_url=outcome.url,
            canonical_url=str(getattr(outcome, "canonical_url", "") or ""),
            og_url=str(getattr(outcome, "og_url", "") or ""),
            og_title=str(getattr(outcome, "og_title", "") or ""),
            title=outcome.title or "",
            body=outcome.body or "",
            site=public_site,
        )
        if instagram is not None:
            classified, reason, conf = instagram
    return _done(
        classified,
        reason or outcome.detail or "public profile rendered while authenticated",
        conf,
        AccessMode.AUTHENTICATED_PUBLIC,
        SessionStatus.ACTIVE.value,
    )


def _log_authenticated_public_evidence(
    site: dict[str, Any],
    username: str,
    profile_url: str,
    outcome: Any,
    *,
    classified: UsernameCheckStatus,
    reason: str,
) -> None:
    public_site = dict(site)
    public_site["check_method"] = "generic_html"
    report = username_evidence_report(
        status_code=int(getattr(outcome, "status_code", 0) or 0),
        body=str(getattr(outcome, "body", "") or ""),
        title=str(getattr(outcome, "title", "") or ""),
        final_url=str(getattr(outcome, "url", "") or ""),
        site=public_site,
        username=username,
        canonical_url=str(getattr(outcome, "canonical_url", "") or ""),
        og_url=str(getattr(outcome, "og_url", "") or ""),
        og_title=str(getattr(outcome, "og_title", "") or ""),
        content_length=int(getattr(outcome, "content_length", 0) or 0),
    )
    logger.debug(
        "AUTHENTICATED_PUBLIC evidence platform=%s requested_url=%s final_url=%s http_status=%s "
        "title=%s canonical=%s og_url=%s og_title=%s username_in_final_url=%s username_in_canonical=%s "
        "username_in_og_url=%s username_in_title=%s username_in_og_title=%s login_wall=%s captcha=%s "
        "challenge=%s not_found=%s success_pattern=%s positive_rules=%s negative_rules=%s "
        "classification=%s reason=%s content_length=%s metadata_waited=%s metadata_ready=%s",
        redact_text(str(site.get("name") or "")),
        redact_text(profile_url),
        redact_text(str(report["final_url"])),
        report["http_status"],
        redact_text(str(report["title"])),
        redact_text(str(report["canonical_url"])),
        redact_text(str(report["og_url"])),
        redact_text(str(report["og_title"])),
        report["username_in_final_url"],
        report["username_in_canonical"],
        report["username_in_og_url"],
        report["username_in_title"],
        report["username_in_og_title"],
        report["login_wall"],
        report["captcha"],
        report["challenge"],
        report["not_found"],
        report["success_pattern"] or "-",
        ",".join(report["positive_rules"]) or "-",
        ",".join(report["negative_rules"]) or "-",
        classified.value,
        redact_text(reason),
        report["content_length"],
        bool(getattr(outcome, "metadata_waited", False)),
        bool(getattr(outcome, "metadata_ready", False)),
    )


def _bundle_from_cached(entity: Entity, payload: dict[str, Any], cached: Any) -> dict[str, Any]:
    status_name = str(payload.get("check_status") or UsernameCheckStatus.INCONCLUSIVE.value)
    try:
        status = UsernameCheckStatus(status_name)
    except ValueError:
        status = UsernameCheckStatus.INCONCLUSIVE
    data = dict(payload)
    data["cache_state"] = CacheState.CACHED.value
    data["cache_age_seconds"] = getattr(cached, "age_seconds", 0)
    conf_raw = data.get("confidence")
    try:
        confidence = Confidence(conf_raw) if conf_raw else STATUS_TO_CONFIDENCE.get(status)
    except ValueError:
        confidence = STATUS_TO_CONFIDENCE.get(status)
    finding = Finding(
        module="username",
        title=str(data.get("platform") or "username"),
        status=STATUS_TO_FINDING.get(status, FindingStatus.INCONCLUSIVE),
        summary=f"{data.get('platform')}: {status.value} (CACHED)",
        data=data,
        confidence=confidence,
        entity_id=entity.id,
    )
    if status not in {UsernameCheckStatus.CONFIRMED, UsernameCheckStatus.LIKELY}:
        return {"finding": finding, "evidence": [], "entities": [], "relationships": []}
    profile_url = str(data.get("profile_url") or "")
    evidence = make_evidence(
        source=str(data.get("platform") or "username"),
        provider="username",
        confidence=confidence or Confidence.MEDIUM,
        url=profile_url or None,
        raw={"check_status": status.value, "cache_state": CacheState.CACHED.value, "reason": data.get("reason")},
        entity_id=entity.id,
        notes="Cached public presence indicator. Same username ≠ confirmed identity.",
    )
    profile = Entity.create(
        EntityType.SOCIAL_PROFILE,
        profile_url or entity.normalized_value,
        source=str(data.get("platform") or "username"),
        confidence=confidence or Confidence.MEDIUM,
        tags=["username", "cached"],
        metadata={"site": data.get("platform"), "username": entity.normalized_value},
    )
    rel = Relationship(
        from_entity_id=entity.id,
        to_entity_id=profile.id,
        relation=RelationType.HAS_PROFILE,
        source=str(data.get("platform") or "username"),
        confidence=confidence or Confidence.MEDIUM,
        evidence_id=evidence.id,
    )
    return {
        "finding": finding,
        "evidence": [evidence],
        "entities": [profile],
        "relationships": [rel],
    }


def _extract_profile_fields(
    html: str,
) -> tuple[str | None, str | None, str | None, str | None, str | None, str | None]:
    title = description = public_name = avatar = website = canonical = None
    try:
        soup = BeautifulSoup(html, "lxml")
        if soup.title and soup.title.string:
            title = soup.title.string.strip()[:200]
        desc = soup.find("meta", attrs={"name": "description"}) or soup.find(
            "meta", attrs={"property": "og:description"}
        )
        if desc and desc.get("content"):
            description = str(desc.get("content"))[:300]
        og_title = soup.find("meta", attrs={"property": "og:title"})
        if og_title and og_title.get("content"):
            public_name = str(og_title.get("content"))[:200]
        og_img = soup.find("meta", attrs={"property": "og:image"})
        if og_img and og_img.get("content"):
            avatar = str(og_img.get("content"))[:500]
        link_can = soup.find("link", attrs={"rel": "canonical"})
        if link_can and link_can.get("href"):
            canonical = str(link_can.get("href"))[:500]
        rel_me = soup.find("a", attrs={"rel": re.compile(r"\bme\b", re.I)})
        if rel_me and rel_me.get("href"):
            website = str(rel_me.get("href"))[:500]
        og_url = soup.find("meta", attrs={"property": "og:url"})
        if not website and og_url and og_url.get("content"):
            website = str(og_url.get("content"))[:500]
    except Exception:
        pass
    return title, description, public_name, avatar, website, canonical
