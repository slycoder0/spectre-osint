"""Domain intelligence: DNS, RDAP, CT, public HTTP fingerprint, optional APIs."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from bs4 import BeautifulSoup

from spectre_osint.core.entities import Entity, Finding, Relationship
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.logger import get_logger
from spectre_osint.core.registry import ProviderRegistry
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType
from spectre_osint.modules.dns.resolver import resolve_dns

logger = get_logger("spectre.domain")

CDN_HINTS: dict[str, tuple[str, ...]] = {
    "Cloudflare": ("cloudflare", "cf-ray", "__cf_bm"),
    "CloudFront": ("cloudfront", "x-amz-cf-id"),
    "Fastly": ("fastly", "x-served-by"),
    "Akamai": ("akamai", "x-akamai"),
    "AWS": ("awselb", "x-amz-id", "amazon"),
    "Azure": ("azure", "x-azure", "ms-azure"),
    "GCP": ("google frontend", "gws", "x-cloud-trace"),
    "Vercel": ("vercel", "x-vercel"),
    "Netlify": ("netlify", "x-nf-"),
    "GitHub Pages": ("github.com", "x-github"),
}

WAF_HINTS: tuple[str, ...] = ("cloudflare", "akamai", "sucuri", "incapsula", "mod_security", "aws waf")


async def analyze_domain(
    entity: Entity,
    http: HttpClient,
    registry: ProviderRegistry,
    settings: Any,
    *,
    include_optional: bool = True,
) -> dict[str, Any]:
    findings: list[Finding] = []
    entities: list[Entity] = [entity]
    relationships: list[Relationship] = []
    evidence = []
    queried: list[str] = []

    dns_result, dns_findings, dns_entities, dns_rels, dns_ev = await resolve_dns(entity)
    findings.extend(dns_findings)
    entities.extend(dns_entities)
    relationships.extend(dns_rels)
    evidence.extend(dns_ev)
    queried.append("dns")

    async def run_provider(name: str) -> None:
        provider = registry.get(name)
        if not provider:
            return
        queried.append(name)
        result = await provider.safe_search(entity, settings)
        findings.extend(result.findings)
        entities.extend(result.entities)
        relationships.extend(result.relationships)
        evidence.extend(result.evidence)

    provider_names = ["rdap", "crtsh"]
    if include_optional:
        provider_names.extend(["wayback", "urlscan", "virustotal", "alienvault", "github"])
    await asyncio.gather(*(run_provider(name) for name in provider_names))

    http_fp = await _http_fingerprint(entity, http)
    if http_fp:
        findings.append(http_fp["finding"])
        evidence.extend(http_fp["evidence"])
        entities.extend(http_fp["entities"])
        relationships.extend(http_fp["relationships"])
        queried.append("http-fingerprint")

    return {
        "findings": findings,
        "entities": _dedupe_entities(entities),
        "relationships": relationships,
        "evidence": evidence,
        "providers_queried": queried,
        "dns": dns_result,
    }


async def _http_fingerprint(entity: Entity, http: HttpClient) -> dict[str, Any] | None:
    url = f"https://{entity.normalized_value}/"
    try:
        response = await http.get(
            url,
            provider="http-fingerprint",
            follow_redirects=True,
            use_cache=True,
            accept_statuses=set(range(200, 500)),
        )
    except Exception as exc:  # noqa: BLE001
        logger.info("Public HTTP fingerprint skipped: %s", exc)
        return None

    headers_l = {k.lower(): v for k, v in response.headers.items()}
    server = headers_l.get("server", "")
    techs = _detect_tech(headers_l, response.text, response.url)
    title, generator, cookies_names = _parse_html(response.text, response.headers)
    evidence = make_evidence(
        source="Public HTTP GET",
        provider="http-fingerprint",
        confidence=Confidence.MEDIUM,
        url=response.url,
        raw={
            "status": response.status_code,
            "server": server,
            "title": title,
            "redirects": response.history,
            "tech": techs,
        },
        entity_id=entity.id,
        notes="Passive GET of a public URL. Not a scan and not a WAF bypass.",
    )
    finding = Finding(
        module="domain",
        title="Public HTTP fingerprint",
        status=FindingStatus.FOUND,
        summary=f"HTTP {response.status_code} title={title!r} tech={', '.join(techs) or 'none'}",
        data={
            "final_url": response.url,
            "status": response.status_code,
            "headers": {k: v for k, v in list(response.headers.items())[:40]},
            "title": title,
            "generator": generator,
            "technologies": techs,
            "cookies": cookies_names,
            "redirects": response.history,
            "server": server,
        },
        confidence=Confidence.MEDIUM,
        entity_id=entity.id,
    )
    extras: list[Entity] = []
    rels: list[Relationship] = []
    for tech in techs:
        tech_entity = Entity.create(
            EntityType.TECHNOLOGY,
            tech,
            source="HTTP fingerprint",
            confidence=Confidence.MEDIUM,
            tags=["fingerprint"],
        )
        extras.append(tech_entity)
        rels.append(
            Relationship(
                from_entity_id=entity.id,
                to_entity_id=tech_entity.id,
                relation=RelationType.USES_TECHNOLOGY,
                source="HTTP fingerprint",
                confidence=Confidence.MEDIUM,
                evidence_id=evidence.id,
            )
        )
    return {
        "finding": finding,
        "evidence": [evidence],
        "entities": extras,
        "relationships": rels,
    }


def _detect_tech(headers: dict[str, str], body: str, final_url: str) -> list[str]:
    blob = " ".join(headers.values()).lower() + " " + (body[:8000].lower()) + " " + final_url.lower()
    found: list[str] = []
    for name, needles in CDN_HINTS.items():
        if any(n in blob for n in needles):
            found.append(name)
    if any(w in blob for w in WAF_HINTS) and "WAF (probable)" not in found:
        # Heuristic only — never claim bypass or confirmed WAF vendor without a header match.
        if "cf-ray" in headers or "cloudflare" in blob:
            found.append("WAF probable: Cloudflare")
        elif "akamai" in blob:
            found.append("WAF probable: Akamai")
        else:
            found.append("WAF probable (heuristic)")
    if 'name="generator"' in body.lower() or "x-powered-by" in headers:
        powered = headers.get("x-powered-by")
        if powered:
            found.append(f"X-Powered-By: {powered}")
    return list(dict.fromkeys(found))


def _parse_html(html: str, headers: dict[str, str]) -> tuple[str | None, str | None, list[str]]:
    title = None
    generator = None
    try:
        soup = BeautifulSoup(html, "lxml")
        if soup.title and soup.title.string:
            title = soup.title.string.strip()[:200]
        gen = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
        if gen and gen.get("content"):
            generator = str(gen.get("content"))[:200]
    except Exception:
        title = None
    cookies = []
    raw = headers.get("set-cookie") or headers.get("Set-Cookie")
    if raw:
        cookies.append(raw.split("=")[0])
    return title, generator, cookies


def _dedupe_entities(entities: list[Entity]) -> list[Entity]:
    seen: dict[str, Entity] = {}
    for entity in entities:
        if entity.id in seen:
            existing = seen[entity.id]
            existing.last_seen = entity.last_seen
            existing.tags = sorted(set(existing.tags + entity.tags))
            existing.metadata.update(entity.metadata)
            existing.evidence.extend(entity.evidence)
        else:
            seen[entity.id] = entity
    return list(seen.values())
