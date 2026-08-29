"""RDAP client (domain + IP). Preferred over classic WHOIS."""

from __future__ import annotations

from typing import Any

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType
from spectre_osint.providers.base import Provider, ProviderResult


class RdapProvider(Provider):
    name = "rdap"
    supported_entities = frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP})
    requires_api_key = False
    health_url = "https://rdap.org/domain/example.com"
    rate_limit = "0.5s"

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        if entity.type == EntityType.IP:
            url = f"https://rdap.org/ip/{entity.normalized_value}"
        else:
            url = f"https://rdap.org/domain/{entity.normalized_value}"
        response = await self.http.get(
            url,
            provider=self.name,
            follow_redirects=True,
            cache_ttl=settings.cache_rdap_ttl,
            accept_statuses=set(range(200, 500)),
        )
        if response.status_code == 404:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.NOT_FOUND,
                findings=[
                    Finding_not_found(self.name, entity),
                ],
            )
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"RDAP HTTP {response.status_code}")

        data = response.json_data
        evidence = make_evidence(
            source="RDAP",
            provider=self.name,
            confidence=Confidence.CONFIRMED,
            url=url,
            raw=_summarize_rdap(data),
            entity_id=entity.id,
        )
        finding = _finding_from_rdap(self.name, entity, data, evidence.id)
        extra_entities: list[Entity] = []
        relationships = []
        if entity.type == EntityType.IP:
            asn_value = _extract_asn(data)
            if asn_value:
                asn_entity = Entity.create(
                    EntityType.ASN,
                    asn_value,
                    source="RDAP",
                    confidence=Confidence.CONFIRMED,
                    metadata={"from": entity.normalized_value},
                )
                extra_entities.append(asn_entity)
                from spectre_osint.core.entities import Relationship

                relationships.append(
                    Relationship(
                        from_entity_id=entity.id,
                        to_entity_id=asn_entity.id,
                        relation=RelationType.BELONGS_TO_ASN,
                        source="RDAP",
                        confidence=Confidence.CONFIRMED,
                        evidence_id=evidence.id,
                    )
                )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            entities=extra_entities,
            relationships=relationships,
            evidence=[evidence],
            payload=_summarize_rdap(data),
        )


def Finding_not_found(provider: str, entity: Entity):
    from spectre_osint.core.entities import Finding

    return Finding(
        module=provider,
        title="RDAP NOT FOUND",
        status=FindingStatus.NOT_FOUND,
        summary="NOT FOUND",
        entity_id=entity.id,
    )


def _finding_from_rdap(provider: str, entity: Entity, data: dict[str, Any], evidence_id: str):
    from spectre_osint.core.entities import Finding

    payload = _summarize_rdap(data)
    return Finding(
        module=provider,
        title="RDAP record",
        status=FindingStatus.FOUND,
        summary=_rdap_summary_text(payload),
        data=payload,
        confidence=Confidence.CONFIRMED,
        entity_id=entity.id,
    )


def _summarize_rdap(data: dict[str, Any]) -> dict[str, Any]:
    vcard_name = None
    registrar = None
    org = None
    country = None
    emails: list[str] = []
    nameservers = [
        (ns.get("ldhName") or ns.get("unicodeName") or "").rstrip(".").lower()
        for ns in data.get("nameservers") or []
        if isinstance(ns, dict)
    ]
    events = []
    for event in data.get("events") or []:
        events.append(
            {
                "action": event.get("eventAction"),
                "date": event.get("eventDate"),
            }
        )
    for entity in data.get("entities") or []:
        roles = entity.get("roles") or []
        vcard = entity.get("vcardArray")
        parsed = _parse_vcard(vcard)
        if "registrar" in roles:
            registrar = parsed.get("fn") or entity.get("handle")
        if "registrant" in roles:
            vcard_name = parsed.get("fn")
            org = parsed.get("org")
            country = parsed.get("country")
        emails.extend(parsed.get("emails") or [])
        for sub in entity.get("entities") or []:
            sub_parsed = _parse_vcard(sub.get("vcardArray"))
            emails.extend(sub_parsed.get("emails") or [])
    status = data.get("status") or []
    cidr = None
    if data.get("cidr0_cidrs"):
        first = data["cidr0_cidrs"][0]
        v4 = first.get("v4prefix")
        v6 = first.get("v6prefix")
        length = first.get("length")
        if v4 and length is not None:
            cidr = f"{v4}/{length}"
        elif v6 and length is not None:
            cidr = f"{v6}/{length}"
    start = data.get("startAddress")
    end = data.get("endAddress")
    return {
        "handle": data.get("handle"),
        "ldhName": data.get("ldhName"),
        "name": vcard_name or data.get("name"),
        "organization": org or data.get("name"),
        "registrar": registrar,
        "country": country or data.get("country"),
        "status": status,
        "nameservers": [ns for ns in nameservers if ns],
        "events": events,
        "emails": sorted(set(emails)),
        "port43": data.get("port43"),
        "cidr": cidr,
        "start_address": start,
        "end_address": end,
        "type": data.get("type") or data.get("objectClassName"),
        "asn": _extract_asn(data),
    }


def _rdap_summary_text(payload: dict[str, Any]) -> str:
    parts = []
    if payload.get("registrar"):
        parts.append(f"registrar={payload['registrar']}")
    if payload.get("organization"):
        parts.append(f"org={payload['organization']}")
    if payload.get("cidr"):
        parts.append(f"cidr={payload['cidr']}")
    if payload.get("asn"):
        parts.append(f"asn={payload['asn']}")
    return "RDAP CONFIRMED " + (", ".join(parts) if parts else "record retrieved")


def _extract_asn(data: dict[str, Any]) -> str | None:
    for key in ("arin_originas0_originautnums", "arin_originas0_originautnum"):
        value = data.get(key)
        if isinstance(value, list) and value:
            return f"AS{value[0]}"
        if isinstance(value, int):
            return f"AS{value}"
    remarks = data.get("remarks") or []
    for remark in remarks:
        desc = " ".join(remark.get("description") or [])
        if "AS" in desc:
            return None
    # RIPE/ARIN sometimes nest network entities
    for entity in data.get("entities") or []:
        handle = str(entity.get("handle") or "")
        if handle.upper().startswith("AS") and handle[2:].isdigit():
            return handle.upper()
    return None


def _parse_vcard(vcard_array: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"emails": []}
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return result
    for item in vcard_array[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        kind = str(item[0]).lower()
        value = item[3]
        if kind == "fn":
            result["fn"] = value
        elif kind == "org":
            result["org"] = value if isinstance(value, str) else str(value)
        elif kind == "email":
            result["emails"].append(str(value))
        elif kind == "adr" and isinstance(item[1], dict):
            country = item[1].get("cc") or (value[-1] if isinstance(value, list) else None)
            result["country"] = country
        elif kind == "adr" and isinstance(value, list) and value:
            result["country"] = value[-1]
    return result
