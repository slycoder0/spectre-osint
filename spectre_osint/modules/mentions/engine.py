"""Public mention collection. Mentions are not social profiles."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.entities import Entity, Finding, MentionRecord, utcnow
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.logger import get_logger
from spectre_osint.core.redaction import redact_text
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.modules.mentions.match import match_input
from spectre_osint.modules.mentions.providers import (
    MentionProvider,
    RawMention,
    default_mention_providers,
)
from spectre_osint.modules.mentions.relevance import classify_mention

logger = get_logger("spectre.mentions")

PER_INPUT_LIMIT = 5
PER_PROVIDER_LIMIT = 5


def _canonical_url(url: str) -> str:
    raw = str(url or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        path = (parsed.path or "/").rstrip("/") or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{parsed.scheme}://{parsed.netloc.lower()}{path}{query}"
    return raw.rstrip("/").lower()


def _dedupe_key(url: str, query: str, matched: str) -> tuple[str, str, str]:
    return (_canonical_url(url), str(query or "").strip().lower(), str(matched or "").strip().lower())


def _confidence(match_type: str) -> Confidence:
    if match_type in {"url_path_segment", "exact_email", "exact_host"}:
        return Confidence.MEDIUM
    return Confidence.LOW


def _host(url: str) -> str:
    return (urlparse(url or "").hostname or "").lower()


def _valid_mention_url(url: str) -> bool:
    parsed = urlparse(str(url or "").strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _safe_associated(value: str) -> str:
    text = str(value or "")
    if "@" in text:
        local, _, domain = text.partition("@")
        return f"{(local[:1] or '*')}***@{domain}"
    return text


def _provider_available(provider: MentionProvider, settings: Settings) -> bool:
    check = getattr(provider, "available", None)
    if callable(check):
        try:
            return bool(check(settings))
        except Exception:  # noqa: BLE001
            return False
    return True


def _finding_from_raw(
    raw: RawMention,
    *,
    query: str,
    kind: str,
    match_type: str,
    matched_field: str,
    matched_value: str,
    excerpt: str,
    safe_query: str,
    relevance: str,
    relevance_reason: str,
    associated_with: list[str],
) -> tuple[MentionRecord, Entity, Any, Finding]:
    conf = _confidence(match_type)
    canonical = _canonical_url(raw.url)
    observed_at = utcnow()
    reason = f"{match_type} in {matched_field}"
    sources = [raw.provider] if raw.provider else []
    mention = MentionRecord(
        query=query,
        source=raw.provider,
        title=raw.title or "Public mention",
        url=canonical or raw.url or None,
        snippet=excerpt or raw.snippet,
        observed_term=matched_value,
        timestamp=observed_at,
        source_type="public_index",
        confidence=conf,
        evidence=[match_type, f"field:{matched_field}", f"provider:{raw.provider}"],
        matched_value=matched_value,
        matched_field=matched_field,
        match_type=match_type,
        published_at=raw.published_at or None,
        provider=raw.provider,
        query_input=query,
        input_type=kind,
        canonical_url=canonical or None,
        matched_text=matched_value,
        observed_at=observed_at,
        reason=reason,
        relevance=relevance,
        relevance_reason=relevance_reason,
        sources=list(sources),
    )
    entity = Entity.create(
        EntityType.PUBLIC_MENTION,
        canonical or raw.title,
        source=raw.provider,
        confidence=conf,
        tags=["public-mention", "not-profile"],
        metadata={
            "query": safe_query,
            "input_type": kind,
            "source": raw.provider,
            "url": canonical,
            "not_identity": True,
            "match_type": match_type,
            "relevance": relevance,
        },
    )
    ev = make_evidence(
        source=raw.provider,
        provider="mentions",
        confidence=conf,
        url=canonical or None,
        raw={
            "title": raw.title,
            "snippet": excerpt,
            "query": safe_query,
            "matched_field": matched_field,
            "match_type": match_type,
        },
        entity_id=entity.id,
        notes="Public mention. Not a social profile.",
    )
    finding = Finding(
        module="mentions",
        title="Public mention",
        status=FindingStatus.OBSERVED,
        summary=f"OBSERVED mention of {safe_query}: {raw.title}",
        data={
            "query": safe_query,
            "kind": kind,
            "input_type": kind,
            "source": raw.provider,
            "provider": raw.provider,
            "title": raw.title,
            "url": canonical,
            "canonical_url": canonical,
            "snippet": excerpt or raw.snippet,
            "observed_term": matched_value,
            "matched_value": matched_value,
            "matched_field": matched_field,
            "match_type": match_type,
            "published_at": raw.published_at,
            "observed_at": observed_at.isoformat(),
            "source_type": "public_index",
            "not_profile": True,
            "reason": reason,
            "confidence": conf.value,
            "domain": _host(canonical or raw.url),
            "query_input": safe_query,
            "relevance": relevance,
            "relevance_reason": relevance_reason,
            "sources": list(sources),
            "associated_with": list(associated_with),
        },
        confidence=conf,
        entity_id=entity.id,
        evidence=[ev],
    )
    return mention, entity, ev, finding


async def _provider_hits(
    provider: MentionProvider,
    query: str,
    *,
    http: HttpClient,
    settings: Settings,
    limit: int,
) -> tuple[list[RawMention], str]:
    try:
        hits = await provider.search(query, http=http, settings=settings, limit=limit)
        return hits, "ok"
    except Exception as exc:  # noqa: BLE001
        logger.info("Mention provider %s unavailable: %s", getattr(provider, "name", "?"), type(exc).__name__)
        return [], type(exc).__name__


def _log_coverage(
    *,
    provider: str,
    input_type: str,
    raw: int,
    parsed: int,
    matched: int,
    deduped: int,
    rejected_no_exact_match: int,
    rejected_invalid_url: int,
    rejected_duplicate: int,
    errors: int,
    status: str,
) -> None:
    logger.debug(
        "mention provider=%s input=%s raw=%s parsed=%s matched=%s deduped=%s "
        "rejected_no_exact_match=%s rejected_invalid_url=%s rejected_duplicate=%s errors=%s status=%s",
        provider,
        input_type,
        raw,
        parsed,
        matched,
        deduped,
        rejected_no_exact_match,
        rejected_invalid_url,
        rejected_duplicate,
        errors,
        status,
    )


async def collect_public_mentions(
    query: str,
    http: HttpClient,
    *,
    limit: int = PER_INPUT_LIMIT,
    kind: str = "username",
    settings: Settings | None = None,
    providers: list[MentionProvider] | None = None,
    unavailable_logged: set[str] | None = None,
    case_inputs: dict[str, Any] | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Search public indexes, then accept only verified matches."""
    value = str(query or "").strip()
    cfg = settings or get_settings()
    if not value:
        return {"findings": [], "entities": [], "evidence": [], "mentions": []}
    safe_query = redact_text(value) if kind == "email" else value
    backends = providers if providers is not None else default_mention_providers()
    findings: list[Finding] = []
    entities: list[Entity] = []
    evidence = []
    mentions: list[MentionRecord] = []
    seen: set[tuple[str, str, str]] = set()
    by_key: dict[tuple[str, str, str], tuple[MentionRecord, Finding]] = {}
    queried: list[str] = []
    unavailable: list[str] = []
    search_term = value.lstrip("@")
    relevance_counts = {"DIRECT": 0, "ASSOCIATED": 0, "AMBIGUOUS": 0}
    for provider in backends:
        name = str(getattr(provider, "name", "mentions"))
        if not _provider_available(provider, cfg):
            unavailable.append(name)
            already = unavailable_logged is not None and name in unavailable_logged
            if not already:
                logger.info("Mention provider %s unavailable (not configured)", name)
                if unavailable_logged is not None:
                    unavailable_logged.add(name)
            if progress:
                progress({
                    "phase": "mentions",
                    "state": "degraded",
                    "provider": name,
                    "message": f"{name} not configured; continuing",
                })
            continue
        queried.append(name)
        if progress:
            progress({
                "phase": "mentions",
                "state": "running",
                "provider": name,
            })
        raw_hits, status = await _provider_hits(
            provider, search_term, http=http, settings=cfg, limit=PER_PROVIDER_LIMIT
        )
        if status != "ok" and progress:
            progress({
                "phase": "mentions",
                "state": "degraded",
                "provider": name,
                "message": f"{name} unavailable ({status}); continuing",
            })
        errors = 0 if status == "ok" else 1
        raw_count = int(getattr(provider, "last_raw", len(raw_hits)) or 0)
        if raw_count < len(raw_hits):
            raw_count = len(raw_hits)
        parsed_hits = [item for item in raw_hits if _valid_mention_url(item.url)]
        parsed_count = len(parsed_hits)
        rejected_invalid_url = max(0, raw_count - parsed_count)
        matched_hits = 0
        rejected_no_exact_match = 0
        rejected_duplicate = 0
        accepted = 0
        cap = min(limit, PER_PROVIDER_LIMIT)
        for raw in parsed_hits:
            matched = match_input(
                value,
                kind,
                title=raw.title,
                snippet=raw.snippet,
                url=raw.url,
                author=raw.author,
            )
            if matched is None:
                rejected_no_exact_match += 1
                continue
            matched_hits += 1
            key = _dedupe_key(raw.url, matched.query, matched.matched_value)
            if key in seen:
                rejected_duplicate += 1
                existing = by_key.get(key)
                if existing is not None:
                    record, finding = existing
                    sources = list(finding.data.get("sources") or record.sources or [])
                    if name and name not in sources:
                        sources.append(name)
                        finding.data["sources"] = sources
                        record.sources = sources
                continue
            if accepted >= cap:
                continue
            seen.add(key)
            accepted += 1
            relevance, relevance_reason, associated_with = classify_mention(
                kind,
                matched.match_type,
                title=raw.title,
                snippet=raw.snippet,
                url=raw.url,
                author=raw.author,
                case_inputs=case_inputs,
            )
            if associated_with:
                associated_with = [_safe_associated(item) for item in associated_with]
            mention, entity, ev, finding = _finding_from_raw(
                raw,
                query=value,
                kind=kind,
                match_type=matched.match_type,
                matched_field=matched.matched_field,
                matched_value=matched.matched_value,
                excerpt=matched.excerpt,
                safe_query=safe_query,
                relevance=relevance,
                relevance_reason=relevance_reason,
                associated_with=associated_with,
            )
            mentions.append(mention)
            entities.append(entity)
            evidence.append(ev)
            findings.append(finding)
            by_key[key] = (mention, finding)
            relevance_counts[relevance] = relevance_counts.get(relevance, 0) + 1
        _log_coverage(
            provider=name,
            input_type=kind,
            raw=raw_count,
            parsed=parsed_count,
            matched=matched_hits,
            deduped=accepted,
            rejected_no_exact_match=rejected_no_exact_match,
            rejected_invalid_url=rejected_invalid_url,
            rejected_duplicate=rejected_duplicate,
            errors=errors,
            status=status,
        )
    logger.debug(
        "mention relevance input=%s direct=%s associated=%s ambiguous=%s",
        kind,
        relevance_counts["DIRECT"],
        relevance_counts["ASSOCIATED"],
        relevance_counts["AMBIGUOUS"],
    )
    if not mentions:
        findings.append(
            Finding(
                module="mentions",
                title="Public mentions",
                status=FindingStatus.NOT_FOUND,
                summary=f"No verified public mentions found for {safe_query}",
                data={
                    "query": safe_query,
                    "provider": ",".join(queried),
                    "kind": kind,
                    "providers_unavailable": unavailable,
                },
            )
        )
    return {
        "findings": findings,
        "entities": entities,
        "evidence": evidence,
        "mentions": mentions,
        "providers_queried": queried,
        "providers_unavailable": unavailable,
    }
