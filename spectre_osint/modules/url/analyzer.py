"""URL analysis with explainable heuristic risk. Heuristics never equal malicious."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup

from spectre_osint.core.entities import Entity, Finding, Relationship
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.registry import ProviderRegistry
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType, RiskLevel
from spectre_osint.core.validators import (
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    contains_punycode,
    is_ip,
    looks_like_homoglyph,
    normalize_domain,
)


async def analyze_url(
    entity: Entity,
    http: HttpClient,
    registry: ProviderRegistry,
    settings: Any,
) -> dict[str, Any]:
    parsed = urlparse(entity.normalized_value)
    host = parsed.hostname or ""
    flags: list[str] = []
    if contains_punycode(host):
        flags.append("punycode")
    if looks_like_homoglyph(host):
        flags.append("homoglyph_or_unicode")
    tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"suspicious_tld.{tld}")
    if len(host) > 50:
        flags.append("long_hostname")
    if is_ip(host):
        flags.append("ip_url")
    if host.lower() in URL_SHORTENERS:
        flags.append("url_shortener")
    if "%" in entity.normalized_value:
        flags.append("encoded_url")
    if parsed.username or parsed.password:
        flags.append("embedded_credentials")

    findings = [
        Finding(
            module="url",
            title="URL parse",
            status=FindingStatus.FOUND,
            summary=f"{parsed.scheme}://{host}{parsed.path}",
            data={
                "scheme": parsed.scheme,
                "host": host,
                "port": parsed.port,
                "path": parsed.path,
                "query": parse_qs(parsed.query),
            },
            confidence=Confidence.CONFIRMED,
            entity_id=entity.id,
        )
    ]
    entities: list[Entity] = [entity]
    relationships: list[Relationship] = []
    evidence = []
    queried: list[str] = []

    if host and not is_ip(host):
        try:
            domain = Entity.create(
                EntityType.DOMAIN, normalize_domain(host), source="URL", confidence=Confidence.CONFIRMED
            )
            entities.append(domain)
            relationships.append(
                Relationship(
                    from_entity_id=entity.id,
                    to_entity_id=domain.id,
                    relation=RelationType.BELONGS_TO_DOMAIN,
                    source="URL",
                    confidence=Confidence.CONFIRMED,
                )
            )
        except Exception:
            pass

    try:
        from spectre_osint.core.ssrf import validate_url_syntax

        if settings.ssrf_enabled and not settings.allow_private_targets:
            validate_url_syntax(entity.normalized_value)
        response = await http.get(
            entity.normalized_value,
            provider="url",
            follow_redirects=True,
            accept_statuses=set(range(200, 500)),
            ssrf=settings.ssrf_enabled and not settings.allow_private_targets,
        )
        if len(response.history) >= 3:
            flags.append("excessive_redirects")
        title = None
        try:
            soup = BeautifulSoup(response.text, "lxml")
            title = soup.title.string.strip()[:200] if soup.title and soup.title.string else None
        except Exception:
            title = None
        ev = make_evidence(
            source="Public HTTP GET",
            provider="url",
            confidence=Confidence.MEDIUM,
            url=response.url,
            raw={"status": response.status_code, "title": title, "redirects": response.history},
            entity_id=entity.id,
        )
        evidence.append(ev)
        findings.append(
            Finding(
                module="url",
                title="Live public fetch",
                status=FindingStatus.FOUND,
                summary=f"HTTP {response.status_code} redirects={len(response.history)} title={title!r}",
                data={
                    "status": response.status_code,
                    "final_url": response.url,
                    "redirects": response.history,
                    "title": title,
                    "headers": dict(list(response.headers.items())[:30]),
                },
                confidence=Confidence.MEDIUM,
                entity_id=entity.id,
            )
        )
        queried.append("http")
    except Exception as exc:  # noqa: BLE001
        from spectre_osint.core.exceptions import SSRFBlocked

        if isinstance(exc, SSRFBlocked):
            findings.append(
                Finding(
                    module="url",
                    title="Live public fetch",
                    status=FindingStatus.ERROR,
                    summary=f"SSRF blocked: {exc}",
                    data={"reason": str(exc)},
                    entity_id=entity.id,
                )
            )
        else:
            findings.append(
                Finding(
                    module="url",
                    title="Live public fetch",
                    status=FindingStatus.PROVIDER_UNAVAILABLE,
                    summary=f"PROVIDER UNAVAILABLE: {exc}",
                    entity_id=entity.id,
                )
            )

    risk_level = RiskLevel.LOW
    if any(f in flags for f in ("punycode", "homoglyph_or_unicode", "embedded_credentials")):
        risk_level = RiskLevel.HIGH_RISK
    elif flags:
        risk_level = RiskLevel.SUSPICIOUS
    findings.append(
        Finding(
            module="url",
            title="Heuristic risk",
            status=FindingStatus.INFERENCE,
            summary=f"INFERENCE risk={risk_level} flags={flags or ['none']} — heuristic is not malicious confirmation",
            data={"heuristic_flags": flags, "risk_level": risk_level.value},
            confidence=Confidence.LOW,
            entity_id=entity.id,
        )
    )

    for name in ("virustotal", "urlscan", "alienvault"):
        provider = registry.get(name)
        if not provider:
            continue
        queried.append(name)
        result = await provider.safe_search(entity, settings)
        findings.extend(result.findings)
        entities.extend(result.entities)
        relationships.extend(result.relationships)
        evidence.extend(result.evidence)

    return {
        "findings": findings,
        "entities": entities,
        "relationships": relationships,
        "evidence": evidence,
        "providers_queried": queried,
    }
