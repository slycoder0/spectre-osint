"""Classify discovery novelty. Does not change identity scoring or username status."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from spectre_osint.core.entities import Finding
from spectre_osint.core.presentation import is_username_site_finding
from spectre_osint.modules.mentions.relevance import lead_host
from spectre_osint.modules.username.identity import _PLATFORM_HOSTS

OPERATOR_INPUT = "OPERATOR_INPUT"
KNOWN = "KNOWN"
OBSERVED = "OBSERVED"
DERIVED = "DERIVED"
NOVEL = "NOVEL"
REDUNDANT = "REDUNDANT"

PRIORITY_HIGH = 100
PRIORITY_MEDIUM = 50
PRIORITY_LOW = 10
PRIORITY_NONE = 0

LINK_HUB_HOSTS = frozenset(
    {
        "linktr.ee",
        "beacons.ai",
        "lnk.bio",
        "carrd.co",
        "about.me",
        "bio.link",
        "campsite.bio",
        "solo.to",
        "heylink.me",
    }
)


def catalog_platform_names() -> set[str]:
    names = {
        "github",
        "gitlab",
        "tryhackme",
        "docker",
        "docker hub",
        "instagram",
        "threads",
        "tiktok",
        "x",
        "twitter",
        "reddit",
        "pinterest",
        "steam",
        "steam community",
        "telegram",
        "last.fm",
        "replit",
        "pypi",
        "kofi",
        "ko-fi",
        "chess.com",
        "gog",
        "wordpress",
        "dev community",
        "dev.to",
    }
    try:
        from spectre_osint.modules.username.engine import load_sites

        for site in load_sites():
            name = str(site.get("name") or "").strip().lower()
            if name:
                names.add(name)
    except Exception:  # noqa: BLE001
        pass
    return names


_GENERIC_NAME_PATTERNS = (
    r"music\s+profile",
    r"user\s+profile",
    r"wordpress\s+user\s+profile",
    r"['’]s\s+profile(?:\s+on\s+.+)?$",
    r"profile\s+on\s+.+$",
    r"\bprofile\b",
    r"cyber\s*security(?:\s+training)?",
    r"(?:online\s+)?(?:security\s+)?training",
    r"(?:online\s+)?courses?",
    r"learn(?:ing)?\s+(?:online|cybersecurity|code|coding|programming)",
    r"build\s+software(?:\s+faster)?",
    r"where\s+(?:the\s+)?world\s+builds\s+software",
    r"let['’]s\s+build\s+from\s+here",
    r"container\s+image\s+library",
    r"developer\s+community",
    r"official\s+(?:site|website|page)",
    r"home(?:\s+page)?$",
)


def catalog_platform_hosts() -> set[str]:
    hosts = {item.lower().removeprefix("www.") for item in _PLATFORM_HOSTS}
    hosts.update({"docker.com", "www.github.com", "youtu.be"})
    try:
        from spectre_osint.modules.username.engine import load_sites
    except Exception:  # noqa: BLE001
        return hosts
    for site in load_sites():
        for key in ("profile_url", "check_url"):
            host = (urlparse(str(site.get(key) or "")).hostname or "").lower().removeprefix("www.")
            if host:
                hosts.add(host)
    return hosts


def is_known_platform_host(host: str, *, catalog: set[str] | None = None) -> bool:
    raw = lead_host(host) or str(host or "").lower().removeprefix("www.")
    if not raw:
        return False
    known = catalog if catalog is not None else catalog_platform_hosts()
    if raw in known:
        return True
    parts = raw.split(".")
    for idx in range(1, len(parts) - 1):
        parent = ".".join(parts[idx:])
        if parent in known:
            return True
    if raw == "docker.com" or raw.endswith(".docker.com"):
        return True
    return False


def is_link_hub(host: str) -> bool:
    return (lead_host(host) or str(host or "").lower()) in LINK_HUB_HOSTS


def _norm_value(kind: str, value: str) -> str:
    raw = str(value or "").strip()
    if kind in {"username", "handle"}:
        return raw.lstrip("@").lower()
    if kind in {"domain", "website", "url"}:
        return (lead_host(raw) or raw).lower()
    return raw.lower()


def known_profile_urls(findings: list[Finding]) -> set[str]:
    urls: set[str] = set()
    for finding in findings:
        if not is_username_site_finding(finding):
            continue
        data = finding.data or {}
        if str(data.get("check_status") or "") not in {"CONFIRMED", "LIKELY"}:
            continue
        url = str(data.get("profile_url") or data.get("final_url") or "").rstrip("/").lower()
        if url:
            urls.add(url)
    return urls


def classify_indicator(
    item: dict[str, Any],
    *,
    operator_handles: set[str],
    operator_emails: set[str],
    operator_domains: set[str],
    known_urls: set[str],
    catalog: set[str] | None = None,
) -> str:
    kind = str(item.get("indicator_type") or "")
    value = str(item.get("value") or "").strip()
    rule = str(item.get("extraction_rule") or "")
    norm = _norm_value(kind, value)
    host = lead_host(value) if kind in {"domain", "url", "website"} else ""
    if kind == "username" and norm in operator_handles:
        return OPERATOR_INPUT
    if kind == "email" and norm in {item.lower() for item in operator_emails}:
        return OPERATOR_INPUT
    if kind in {"domain", "url"} and (norm in operator_domains or (host and host in operator_domains)):
        return OPERATOR_INPUT
    url = value.rstrip("/").lower() if kind == "url" else ""
    if url and url in known_urls:
        return KNOWN
    if kind in {"domain", "url"} and host and is_known_platform_host(host, catalog=catalog) and not is_link_hub(host):
        if rule in {"profile_host", "profile_url", "discovered_profile_url"} or kind == "domain":
            return REDUNDANT
    if kind == "url" and host and is_known_platform_host(host, catalog=catalog) and not is_link_hub(host):
        return REDUNDANT
    if rule in {"bio_handle", "website", "personal_domain", "external_links", "social_links", "public_email"}:
        return DERIVED
    if rule.startswith("discovered_"):
        return DERIVED if kind == "username" else NOVEL
    return NOVEL


def annotate_indicators(
    rows: list[dict[str, Any]],
    *,
    operator_handles: set[str],
    operator_emails: set[str],
    operator_domains: set[str],
    findings: list[Finding] | None = None,
) -> list[dict[str, Any]]:
    catalog = catalog_platform_hosts()
    known_urls = known_profile_urls(findings or [])
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        kind = str(row.get("indicator_type") or "")
        key = (kind, _norm_value(kind, str(row.get("value") or "")))
        if not key[1]:
            continue
        novelty = classify_indicator(
            row,
            operator_handles=operator_handles,
            operator_emails=operator_emails,
            operator_domains=operator_domains,
            known_urls=known_urls,
            catalog=catalog,
        )
        source = str(row.get("source") or "")
        current = merged.get(key)
        if current is None:
            item = dict(row)
            item["novelty"] = novelty
            item["sources"] = [source] if source else []
            item["derived_from"] = str(row.get("original_finding") or "")
            item["priority"] = _priority(item, novelty)
            merged[key] = item
            continue
        if source and source not in current["sources"]:
            current["sources"].append(source)
        rank = {NOVEL: 5, DERIVED: 4, OBSERVED: 3, KNOWN: 2, OPERATOR_INPUT: 1, REDUNDANT: 0}
        if rank.get(novelty, 0) > rank.get(str(current.get("novelty")), 0):
            current["novelty"] = novelty
            current["priority"] = _priority(current, novelty)
    return list(merged.values())


def _priority(item: dict[str, Any], novelty: str) -> int:
    if novelty in {REDUNDANT, OPERATOR_INPUT, KNOWN}:
        return PRIORITY_NONE
    kind = str(item.get("indicator_type") or "")
    host = lead_host(str(item.get("value") or ""))
    if kind in {"email"}:
        return PRIORITY_HIGH
    if kind == "username":
        return PRIORITY_HIGH
    if kind in {"domain", "url"} and host and is_link_hub(host):
        return PRIORITY_HIGH
    if kind in {"domain", "url"} and host and not is_known_platform_host(host):
        return PRIORITY_HIGH
    if kind == "url":
        return PRIORITY_MEDIUM
    return PRIORITY_LOW


def useful_discovery(item: dict[str, Any]) -> bool:
    return str(item.get("novelty") or "") in {NOVEL, DERIVED} and int(item.get("priority") or 0) > PRIORITY_NONE


def is_generic_display_name(value: str, username: str, platform: str | None = None) -> bool:
    text = " ".join(str(value or "").split()).strip()
    handle = str(username or "").strip().lstrip("@")
    if not text:
        return True
    lowered = text.lower()
    if handle and handle.lower() == lowered:
        return True
    if handle and lowered.replace(" ", "") == handle.lower():
        return True
    import re

    if handle and re.search(rf"\b{re.escape(handle)}\b", lowered) and any(
        token in lowered for token in ("profile", "last.fm", "wordpress", "gog", "gitlab", "github", "docker", "tryhackme")
    ):
        return True

    known_platforms = catalog_platform_names()
    if platform:
        known_platforms.add(str(platform).strip().lower())

    if lowered in known_platforms:
        return True

    parts = [p.strip() for p in re.split(r"\s*[|·•—–:]\s*|\s+-\s+", text) if p.strip()]
    if len(parts) >= 2:
        def _part_is_boilerplate(part: str) -> bool:
            p_low = part.lower()
            if p_low in known_platforms:
                return True
            return any(re.search(pat, p_low, flags=re.I) for pat in _GENERIC_NAME_PATTERNS)

        if all(_part_is_boilerplate(p) for p in parts):
            return True

    for pattern in _GENERIC_NAME_PATTERNS:
        if re.search(pattern, lowered, flags=re.I):
            return True
    return False


def discovery_metrics(
    indicators: list[dict[str, Any]],
    pivots: list[dict[str, Any]],
    *,
    coverage: dict[str, Any] | None = None,
) -> dict[str, int]:
    cov = dict(coverage or {})
    novel = [item for item in indicators if str(item.get("novelty")) == NOVEL]
    derived = [item for item in indicators if str(item.get("novelty")) == DERIVED]
    redundant = [item for item in indicators if str(item.get("novelty")) == REDUNDANT]
    useful = [item for item in indicators if useful_discovery(item)]
    accepted = [row for row in pivots if row.get("accepted")]
    suppressed = [row for row in pivots if not row.get("accepted")]
    return {
        "search_providers": int(cov.get("providers") or 0),
        "queries_issued": int(cov.get("queries_issued") or 0),
        "search_results": int(cov.get("results") or 0),
        "relevant_search_hits": int(cov.get("relevant") or 0),
        "indicators_extracted": len(indicators),
        "novel_indicators": len(novel) + len(derived),
        "redundant_indicators": len(redundant),
        "new_handles": sum(1 for item in useful if item.get("indicator_type") == "username"),
        "new_domains": sum(1 for item in useful if item.get("indicator_type") == "domain"),
        "profile_candidates": int(cov.get("discovered") or 0),
        "pivots_proposed": len(pivots),
        "pivots_executed": len(accepted),
        "pivots_suppressed": len(suppressed),
        "max_depth_reached": max((int(row.get("depth") or 0) for row in pivots), default=0),
    }
