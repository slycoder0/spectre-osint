"""Passive DNS lookups via system resolvers. CONFIRMED when answers exist."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename

from spectre_osint.core.entities import Entity, Finding, Relationship
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType
from spectre_osint.modules.dns.parsers import identify_mail_provider, parse_dmarc, parse_spf

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "CNAME")


@dataclass
class DNSResult:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    spf: dict[str, Any] = field(default_factory=dict)
    dmarc: dict[str, Any] = field(default_factory=dict)
    mail_providers: list[str] = field(default_factory=list)


def _query_sync(domain: str, rdtype: str, timeout: float = 8.0) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    answers = resolver.resolve(domain, rdtype)
    values: list[str] = []
    for rr in answers:
        text = rr.to_text()
        if rdtype == "TXT":
            text = text.strip('"').replace('" "', "")
        if rdtype == "MX":
            parts = text.split()
            text = parts[-1].rstrip(".") if parts else text
        if rdtype in {"NS", "CNAME", "SOA"}:
            text = text.rstrip(".")
        values.append(text)
    return values


async def resolve_records(domain: str, types: tuple[str, ...] = RECORD_TYPES) -> DNSResult:
    result = DNSResult(domain=domain)

    async def one(rdtype: str) -> None:
        try:
            values = await asyncio.to_thread(_query_sync, domain, rdtype)
            result.records[rdtype] = values
        except dns.resolver.NXDOMAIN:
            result.errors[rdtype] = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            result.records[rdtype] = []
        except dns.resolver.NoNameservers:
            result.errors[rdtype] = "NO_NAMESERVERS"
        except dns.exception.Timeout:
            result.errors[rdtype] = "TIMEOUT"
        except Exception as exc:  # noqa: BLE001
            result.errors[rdtype] = str(exc)

    await asyncio.gather(*(one(t) for t in types))

    try:
        dmarc_txt = await asyncio.to_thread(_query_sync, f"_dmarc.{domain}", "TXT")
        result.records["DMARC_TXT"] = dmarc_txt
    except Exception:
        result.records["DMARC_TXT"] = []

    result.spf = parse_spf(result.records.get("TXT") or [])
    result.dmarc = parse_dmarc(result.records.get("DMARC_TXT") or [])
    result.mail_providers = identify_mail_provider(
        result.records.get("MX") or [],
        result.spf.get("includes") or [],
    )
    return result


async def reverse_dns(ip: str) -> list[str]:
    try:
        name = dns.reversename.from_address(ip)
        values = await asyncio.to_thread(_query_sync, str(name), "PTR")
        return [v.rstrip(".") for v in values]
    except Exception:
        return []


async def resolve_dns(entity: Entity) -> tuple[DNSResult, list[Finding], list[Entity], list[Relationship], list]:
    result = await resolve_records(entity.normalized_value)
    evidence = make_evidence(
        source="DNS",
        provider="dns",
        confidence=Confidence.CONFIRMED if result.records else Confidence.LOW,
        raw={"records": result.records, "errors": result.errors},
        entity_id=entity.id,
    )
    findings = [
        Finding(
            module="dns",
            title="DNS records",
            status=FindingStatus.FOUND if any(result.records.values()) else FindingStatus.NOT_FOUND,
            summary=_summarize(result),
            data={
                "records": result.records,
                "errors": result.errors,
                "spf": result.spf,
                "dmarc": result.dmarc,
                "mail_providers": result.mail_providers,
            },
            confidence=Confidence.CONFIRMED if any(result.records.values()) else None,
            entity_id=entity.id,
        )
    ]
    extras: list[Entity] = []
    rels: list[Relationship] = []
    for ip in (result.records.get("A") or []) + (result.records.get("AAAA") or []):
        ip_entity = Entity.create(EntityType.IP, ip, source="DNS", confidence=Confidence.CONFIRMED)
        extras.append(ip_entity)
        rels.append(
            Relationship(
                from_entity_id=entity.id,
                to_entity_id=ip_entity.id,
                relation=RelationType.RESOLVES_TO,
                source="DNS",
                confidence=Confidence.CONFIRMED,
                evidence_id=evidence.id,
            )
        )
    for mx in result.records.get("MX") or []:
        try:
            mx_entity = Entity.create(EntityType.DOMAIN, mx, source="DNS MX", confidence=Confidence.CONFIRMED)
        except Exception:
            continue
        extras.append(mx_entity)
        rels.append(
            Relationship(
                from_entity_id=entity.id,
                to_entity_id=mx_entity.id,
                relation=RelationType.HAS_MX,
                source="DNS",
                confidence=Confidence.CONFIRMED,
                evidence_id=evidence.id,
            )
        )
    for ns in result.records.get("NS") or []:
        try:
            ns_entity = Entity.create(
                EntityType.DOMAIN, ns, source="DNS NS", confidence=Confidence.CONFIRMED, tags=["nameserver"]
            )
        except Exception:
            continue
        extras.append(ns_entity)
        rels.append(
            Relationship(
                from_entity_id=entity.id,
                to_entity_id=ns_entity.id,
                relation=RelationType.USES_NAMESERVER,
                source="DNS",
                confidence=Confidence.CONFIRMED,
                evidence_id=evidence.id,
            )
        )
    for provider in result.mail_providers:
        tech = Entity.create(
            EntityType.TECHNOLOGY,
            provider,
            source="DNS",
            confidence=Confidence.HIGH,
            tags=["mail-provider"],
        )
        extras.append(tech)
        rels.append(
            Relationship(
                from_entity_id=entity.id,
                to_entity_id=tech.id,
                relation=RelationType.USES_TECHNOLOGY,
                source="DNS",
                confidence=Confidence.HIGH,
                evidence_id=evidence.id,
            )
        )
    return result, findings, extras, rels, [evidence]


def _summarize(result: DNSResult) -> str:
    if not any(result.records.values()) and result.errors:
        return "NOT FOUND / " + ", ".join(f"{k}={v}" for k, v in result.errors.items())
    a = len(result.records.get("A") or [])
    aaaa = len(result.records.get("AAAA") or [])
    mx = len(result.records.get("MX") or [])
    parts = [f"A={a}", f"AAAA={aaaa}", f"MX={mx}"]
    if result.spf.get("present"):
        parts.append(f"SPF={result.spf.get('all_qualifier')}")
    if result.dmarc.get("present"):
        parts.append(f"DMARC={result.dmarc.get('policy')}")
    if result.mail_providers:
        parts.append("mail=" + ",".join(result.mail_providers))
    return "CONFIRMED " + " ".join(parts)
