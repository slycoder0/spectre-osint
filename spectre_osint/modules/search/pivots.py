"""Search-discovery pivots. Candidate aliases never become confirmed identity."""

from __future__ import annotations

from typing import Any

from spectre_osint.core.entities import Entity, Finding, PivotSuggestion, Relationship, utcnow
from spectre_osint.core.logger import get_logger
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType
from spectre_osint.modules.mentions.relevance import lead_host
from spectre_osint.modules.search.novelty import (
    KNOWN,
    OPERATOR_INPUT,
    PRIORITY_NONE,
    REDUNDANT,
    useful_discovery,
)

logger = get_logger("spectre.search")

DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_PIVOTS = 25


def _norm_key(kind: str, value: str) -> tuple[str, str]:
    raw = str(value or "").strip()
    if kind in {"username", "handle"}:
        raw = raw.lstrip("@").lower()
    elif kind in {"domain", "website", "url"}:
        raw = lead_host(raw) or raw.lower()
    else:
        raw = raw.lower()
    return (kind, raw)


def propose_pivots(
    *,
    indicators: list[dict[str, Any]],
    known: set[tuple[str, str]],
    source: str,
    depth: int,
    remaining: int,
) -> list[dict[str, Any]]:
    """Return accepted/rejected pivot records. Spends budget on novel evidence first."""
    out: list[dict[str, Any]] = []
    seen = set(known)
    accepted = 0
    ordered = sorted(
        indicators,
        key=lambda item: (-int(item.get("priority") or 0), str(item.get("indicator_type") or "")),
    )
    for item in ordered:
        kind = str(item.get("indicator_type") or "")
        value = str(item.get("value") or "").strip()
        if kind not in {"username", "domain", "email", "url"} or not value:
            continue
        key = _norm_key(kind, value)
        action = {
            "username": "search username",
            "domain": "inspect domain",
            "email": "search exact email",
            "url": "inspect public URL",
        }[kind]
        novelty = str(item.get("novelty") or "")
        record = {
            "action": action,
            "target": value,
            "type": kind,
            "source": source,
            "depth": depth,
            "reason": str(item.get("extraction_rule") or "extracted_indicator"),
            "original_finding": str(item.get("original_finding") or ""),
            "novelty": novelty,
            "derived_from": str(item.get("derived_from") or ""),
            "priority": int(item.get("priority") or 0),
        }
        if novelty and (novelty in {REDUNDANT, OPERATOR_INPUT, KNOWN} or not useful_discovery(item)):
            record["accepted"] = False
            record["reject_reason"] = "redundant" if novelty == REDUNDANT else "not_novel"
            logger.debug(
                "pivot source=%s type=%s depth=%s accepted=false reason=%s",
                source,
                kind,
                depth,
                record["reject_reason"],
            )
            out.append(record)
            continue
        if key in seen:
            record["accepted"] = False
            record["reject_reason"] = "duplicate"
            logger.debug(
                "pivot source=%s type=%s depth=%s accepted=false reason=duplicate",
                source,
                kind,
                depth,
            )
            out.append(record)
            continue
        if accepted >= max(0, remaining):
            record["accepted"] = False
            record["reject_reason"] = "budget"
            out.append(record)
            continue
        if novelty and int(item.get("priority") or 0) <= PRIORITY_NONE:
            record["accepted"] = False
            record["reject_reason"] = "low_priority"
            out.append(record)
            continue
        seen.add(key)
        record["accepted"] = True
        accepted += 1
        logger.debug(
            "pivot source=%s type=%s depth=%s accepted=true novelty=%s",
            source,
            kind,
            depth,
            novelty,
        )
        out.append(record)
    return out


def pivot_entities(records: list[dict[str, Any]], *, origin_id: str) -> dict[str, list[Any]]:
    entities: list[Entity] = []
    relationships: list[Relationship] = []
    findings: list[Finding] = []
    pivots: list[PivotSuggestion] = []
    for row in records:
        if not row.get("accepted"):
            continue
        kind = str(row.get("type") or "")
        value = str(row.get("target") or "")
        etype = {
            "username": EntityType.USERNAME,
            "domain": EntityType.DOMAIN,
            "email": EntityType.EMAIL,
            "url": EntityType.URL,
        }.get(kind)
        if etype is None or not value:
            continue
        entity = Entity.create(
            etype,
            value,
            source="search.pivot",
            confidence=Confidence.LOW,
            tags=["candidate", "not_identity_evidence"],
            metadata={
                "candidate": True,
                "not_identity_evidence": True,
                "depth": int(row.get("depth") or 0),
                "extraction_rule": row.get("reason"),
            },
        )
        entities.append(entity)
        relationships.append(
            Relationship(
                from_entity_id=origin_id,
                to_entity_id=entity.id,
                relation=RelationType.REFERENCES,
                source="search.pivot",
                confidence=Confidence.LOW,
                metadata={"candidate": True, "not_identity_evidence": True},
            )
        )
        findings.append(
            Finding(
                module="search",
                title="Automatic pivot",
                status=FindingStatus.OBSERVED,
                summary=f"{row.get('action')}: {value}",
                data={"kind": "pivot", **row, "observed_at": utcnow().isoformat()},
            )
        )
        pivots.append(
            PivotSuggestion(
                action=str(row.get("action") or "search"),
                target=value,
                entity_type=etype,
                reason=f"{row.get('reason')} (candidate; depth={row.get('depth')})",
                confidence=Confidence.LOW,
                source=str(row.get("source") or "search.pivot"),
            )
        )
    return {
        "entities": entities,
        "relationships": relationships,
        "findings": findings,
        "pivots": pivots,
    }
