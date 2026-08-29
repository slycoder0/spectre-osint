"""Observed public-profile enrichment with explicit provenance.

Reuses the provider/fetch payload already in hand. Does not scrape extra pages
and does not treat operator leads as observed evidence.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from spectre_osint.core.logger import get_logger
from spectre_osint.modules.username.identity import (
    _PLATFORM_HOSTS,
    normalize_domain,
    normalize_name,
    normalize_url,
    normalize_username,
)

logger = get_logger("spectre.username")

FIELD_ORDER = (
    "display_name",
    "username",
    "bio",
    "location",
    "organization",
    "website",
    "personal_domain",
    "public_email",
    "avatar_url",
    "public_id",
    "external_links",
    "social_links",
)

_GENERIC_BIO = frozenset(
    {
        "",
        "no bio",
        "none",
        "n/a",
        "na",
        "hello",
        "hello world",
        "hey",
        "available",
        "this is my bio",
        "gitlab.com",
        "github.com",
        "dev community",
        "dev.to",
    }
)
_TITLE_SUFFIXES = (
    r"\s*[·|—–-]\s*gitlab(?:\.com)?$",
    r"\s*[·|—–-]\s*github(?:\.com)?$",
    r"\s*[·|—–-]\s*dev community(?: profile)?$",
    r"\s+on instagram$",
    r"\s*[•·].*instagram.*$",
    r"\s*[·|—–-]\s*chess\.com$",
    r"\s*[·|—–-]\s*docker hub$",
    r"\s*[·|—–-]\s*wordpress(?:\.org)?$",
    r"\s*[·|—–-]\s*gog(?:\.com)?$",
    r"\s*[|·—–-]\s*last\.fm$",
    r"'s music profile.*$",
    r"’s music profile.*$",
    r"'s profile on .+$",
    r"’s profile on .+$",
    r"\s+[–—-]\s*wordpress user profile$",
    r"\s+user profile$",
)
_JSON_FALLBACKS = {
    "organization": ("company", "org", "organization"),
    "public_email": ("email",),
    "public_id": ("id", "uuid", "node_id"),
    "avatar_url": ("avatar_url", "avatar", "gravatar_url", "profile_image"),
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _field(value: str, source: str, *, original: str | None = None, observed_at: str | None = None) -> dict[str, str]:
    text = str(value or "").strip()
    return {
        "value": text,
        "original": str(original if original is not None else text),
        "source": source,
        "observed_at": observed_at or _now(),
    }


def _looks_like_email(value: str) -> bool:
    text = str(value or "").strip()
    if "@" not in text or " " in text:
        return False
    local, _, domain = text.partition("@")
    return bool(local) and "." in domain


def clean_display_name(raw: str | None, username: str, platform: str | None = None) -> str:
    text = re.sub(r"\s+", " ", str(raw or "")).strip()
    if not text:
        return ""
    handle = normalize_username(username)
    text = re.sub(rf"\s*\(@{re.escape(handle)}\)\s*", " ", text, flags=re.I).strip()
    for pattern in _TITLE_SUFFIXES:
        text = re.sub(pattern, "", text, flags=re.I).strip()

    from spectre_osint.modules.search.novelty import catalog_platform_names, is_generic_display_name

    known = catalog_platform_names()
    if platform:
        known.add(str(platform).strip().lower())

    parts = [p.strip() for p in re.split(r"\s*[|·•—–:]\s*|\s+-\s+", text) if p.strip()]
    if len(parts) >= 2:
        if parts[-1].lower() in known:
            candidate = " | ".join(parts[:-1]).strip()
            if candidate and not is_generic_display_name(candidate, handle, platform=platform):
                text = candidate
        elif parts[0].lower() in known:
            candidate = " | ".join(parts[1:]).strip()
            if candidate and not is_generic_display_name(candidate, handle, platform=platform):
                text = candidate

    text = text.strip(" ·|-—–:")
    if not text:
        return ""
    if normalize_username(text) == handle:
        return ""
    if normalize_name(text) == normalize_name(handle):
        return ""

    if is_generic_display_name(text, handle, platform=platform):
        return ""
    return text[:200]


def _is_platform_url(url: str | None) -> bool:
    canon = normalize_url(url)
    if not canon:
        return True
    host = (urlparse(canon).hostname or "").lower().removeprefix("www.")
    return host in _PLATFORM_HOSTS


def _personal_website(url: str | None) -> str | None:
    canon = normalize_url(url)
    if not canon or _is_platform_url(canon):
        return None
    return canon


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


def _jsonld_people(html: str) -> list[dict[str, Any]]:
    people: list[dict[str, Any]] = []
    try:
        soup = BeautifulSoup(html or "", "lxml")
    except Exception:
        return people
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
            if "person" in type_l:
                people.append(blob)
    return people


def _rel_me_links(html: str) -> list[str]:
    out: list[str] = []
    try:
        soup = BeautifulSoup(html or "", "lxml")
    except Exception:
        return out
    for link in soup.find_all("a", attrs={"rel": True}):
        rel_raw = link.get("rel")
        if isinstance(rel_raw, list):
            rel_parts = [str(item or "").lower() for item in rel_raw]
        else:
            rel_parts = [str(rel_raw or "").lower()]
        rel = " ".join(rel_parts)
        if "me" not in rel.split():
            continue
        href = str(link.get("href") or "").strip()
        canon = normalize_url(href)
        if canon and canon not in out:
            out.append(canon)
    return out


def _meta(html: str, prop: str) -> str:
    try:
        soup = BeautifulSoup(html or "", "lxml")
    except Exception:
        return ""
    el = soup.find("meta", attrs={"property": prop}) or soup.find("meta", attrs={"name": prop})
    if el and el.get("content"):
        return str(el.get("content")).strip()
    return ""


def _classify_link(url: str) -> str:
    if _is_platform_url(url):
        return "social_links"
    if _personal_website(url):
        return "external_links"
    return ""


def enrich_profile(
    *,
    platform: str,
    username: str,
    profile_url: str,
    site: dict[str, Any] | None = None,
    json_data: dict[str, Any] | None = None,
    html: str = "",
    meta: dict[str, str] | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Return observed fields keyed by name. Empty fields are omitted."""
    spec = site or {}
    stamp = observed_at or _now()
    handle = normalize_username(username)
    provider_key = re.sub(r"[^a-z0-9]+", "_", str(platform or "profile").lower()).strip("_") or "profile"
    observed: dict[str, Any] = {}
    meta = dict(meta or {})

    def put(field: str, value: Any, source: str, *, original: str | None = None) -> None:
        if isinstance(value, list):
            cleaned = [str(item).strip() for item in value if str(item).strip()]
            if not cleaned:
                return
            existing = list(observed.get(field, {}).get("value") or []) if field in observed else []
            for item in cleaned:
                if item not in existing:
                    existing.append(item)
            observed[field] = {
                "value": existing,
                "original": existing,
                "source": source,
                "observed_at": stamp,
            }
            return
        if field in observed:
            return
        text = str(value or "").strip()
        if not text:
            return
        observed[field] = _field(text, source, original=original, observed_at=stamp)

    if handle:
        put("username", handle, f"{provider_key}.username", original=username)

    if isinstance(json_data, dict):
        api = f"{provider_key}_api"
        for path in spec.get("display_name_fields") or ["name", "displayName"]:
            raw = _dig(json_data, str(path))
            cleaned = clean_display_name(str(raw) if raw else "", handle, platform=platform)
            if cleaned:
                put("display_name", cleaned, f"{api}.{path}", original=str(raw))
                break
        for path in spec.get("website_fields") or ["blog", "website"]:
            raw = _dig(json_data, str(path))
            site_url = _personal_website(str(raw) if raw else "")
            if site_url:
                put("website", site_url, f"{api}.{path}", original=str(raw))
                domain = normalize_domain(site_url)
                if domain:
                    put("personal_domain", domain, f"{api}.{path}")
                break
        bio_path = spec.get("bio_field") or "bio"
        bio_raw = _dig(json_data, str(bio_path))
        bio_text = str(bio_raw or "").strip()
        if bio_text and normalize_name(bio_text) not in _GENERIC_BIO and len(bio_text) >= 8:
            put("bio", bio_text[:300], f"{api}.{bio_path}")
        loc_path = spec.get("location_field") or "location"
        loc_raw = _dig(json_data, str(loc_path))
        if loc_raw:
            put("location", str(loc_raw)[:120], f"{api}.{loc_path}")
        av_path = spec.get("avatar_field") or "avatar_url"
        av_raw = _dig(json_data, str(av_path))
        av_url = normalize_url(str(av_raw) if av_raw else "")
        if av_url:
            put("avatar_url", av_url, f"{api}.{av_path}", original=str(av_raw))
        numeric_id = json_data.get("id")
        if isinstance(numeric_id, int) or (isinstance(numeric_id, str) and str(numeric_id).isdigit()):
            put("public_id", str(numeric_id), f"{api}.id")
        for field, keys in _JSON_FALLBACKS.items():
            for key in keys:
                raw = json_data.get(key)
                if not raw:
                    continue
                if field == "public_email" and not _looks_like_email(str(raw)):
                    continue
                if field == "organization":
                    put(field, str(raw)[:120], f"{api}.{key}")
                elif field == "public_email":
                    put(field, str(raw).strip().lower(), f"{api}.{key}")
                elif field == "public_id":
                    put(field, str(raw).strip(), f"{api}.{key}")
                elif field == "avatar_url":
                    canon = normalize_url(str(raw))
                    if canon:
                        put(field, canon, f"{api}.{key}", original=str(raw))
        twitter = json_data.get("twitter_username") or json_data.get("twitter")
        if twitter:
            twitter_url = normalize_url(f"https://x.com/{str(twitter).lstrip('@')}")
            if twitter_url:
                put("social_links", [twitter_url], f"{api}.twitter_username")

    og_title = str(meta.get("og_title") or "")
    title = str(meta.get("title") or "")
    og_url = str(meta.get("og_url") or "")
    canonical = str(meta.get("canonical") or "")
    og_image = str(meta.get("og_image") or "")

    if html:
        people = _jsonld_people(html)
        for person in people:
            name = clean_display_name(str(person.get("name") or ""), handle, platform=platform)
            if name:
                put("display_name", name, "html_jsonld.name", original=str(person.get("name") or ""))
            email = person.get("email")
            if email and _looks_like_email(str(email)):
                put("public_email", str(email).strip().lower(), "html_jsonld.email")
            image = person.get("image")
            if isinstance(image, dict):
                image = image.get("url")
            img_url = normalize_url(str(image) if image else "")
            if img_url:
                put("avatar_url", img_url, "html_jsonld.image")
            raw_same = person.get("sameAs") or []
            if isinstance(raw_same, str):
                same_as = [raw_same]
            elif isinstance(raw_same, list):
                same_as = [str(item) for item in raw_same]
            else:
                same_as = []
            jsonld_social: list[str] = []
            jsonld_external: list[str] = []
            for item in same_as:
                canon = normalize_url(str(item))
                if not canon:
                    continue
                kind = _classify_link(canon)
                if kind == "social_links" and canon not in jsonld_social:
                    jsonld_social.append(canon)
                elif kind == "external_links" and canon not in jsonld_external:
                    jsonld_external.append(canon)
                    if "website" not in observed:
                        put("website", canon, "html_jsonld.sameAs", original=str(item))
                        domain = normalize_domain(canon)
                        if domain:
                            put("personal_domain", domain, "html_jsonld.sameAs")
            if jsonld_social:
                put("social_links", jsonld_social, "html_jsonld.sameAs")
            if jsonld_external:
                put("external_links", jsonld_external, "html_jsonld.sameAs")
            person_url = _personal_website(str(person.get("url") or ""))
            if person_url:
                put("website", person_url, "html_jsonld.url")
                domain = normalize_domain(person_url)
                if domain:
                    put("personal_domain", domain, "html_jsonld.url")
            break
        if not og_title:
            og_title = _meta(html, "og:title")
        if not og_url:
            og_url = _meta(html, "og:url")
        if not og_image:
            og_image = _meta(html, "og:image")
        if not canonical:
            try:
                soup = BeautifulSoup(html, "lxml")
                link = soup.find("link", attrs={"rel": "canonical"})
                if link and link.get("href"):
                    canonical = str(link.get("href"))
            except Exception:
                pass
        for href in _rel_me_links(html):
            kind = _classify_link(href)
            if kind == "social_links":
                put("social_links", [href], "html_rel_me")
            elif kind == "external_links":
                put("external_links", [href], "html_rel_me")
                if "website" not in observed:
                    put("website", href, "html_rel_me")
                    domain = normalize_domain(href)
                    if domain:
                        put("personal_domain", domain, "html_rel_me")

    name = clean_display_name(og_title, handle, platform=platform) or clean_display_name(title, handle, platform=platform)
    if name:
        source = "html_og.title" if clean_display_name(og_title, handle, platform=platform) else "html_title"
        if str(platform).lower() == "instagram":
            source = "instagram_og.title"
        put("display_name", name, source, original=og_title or title)
    img = normalize_url(og_image)
    if img:
        put("avatar_url", img, "html_og.image", original=og_image)
    for candidate, source in ((canonical, "html_canonical"), (og_url, "html_og.url")):
        site_url = _personal_website(candidate)
        if site_url:
            put("website", site_url, source, original=candidate)
            domain = normalize_domain(site_url)
            if domain:
                put("personal_domain", domain, source)

    fields = [key for key in FIELD_ORDER if key in observed]
    sources = sorted(
        {
            str(item.get("source"))
            for item in observed.values()
            if isinstance(item, dict) and item.get("source")
        }
    )
    if fields:
        logger.debug(
            "profile enrichment provider=%s username=%s fields=%s sources=%s",
            platform,
            handle,
            ",".join(fields),
            ",".join(sources),
        )
    return observed


def flatten_observed(observed: dict[str, Any]) -> dict[str, Any]:
    """Top-level finding fields for IdentityRecord compatibility."""
    def value(key: str) -> str:
        item = observed.get(key)
        if isinstance(item, dict):
            raw = item.get("value")
            if isinstance(raw, list):
                return ""
            return str(raw or "")
        return ""

    links: list[str] = []
    for key in ("website",):
        if value(key):
            links.append(value(key))
    for key in ("external_links", "social_links"):
        item = observed.get(key)
        if isinstance(item, dict) and isinstance(item.get("value"), list):
            for href in item["value"]:
                if href and href not in links:
                    links.append(str(href))
    return {
        "display_name": value("display_name") or None,
        "bio": value("bio") or None,
        "avatar_url": value("avatar_url") or None,
        "website": value("website") or None,
        "public_location": value("location") or None,
        "organization": value("organization") or None,
        "public_email": value("public_email") or None,
        "public_id": value("public_id") or None,
        "public_links": links,
    }
