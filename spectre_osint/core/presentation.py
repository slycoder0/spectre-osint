"""Shared view of an InvestigationResult for CLI, GUI and reports."""

from __future__ import annotations

import html
import re
from collections import Counter
from datetime import datetime
from typing import Any

from markupsafe import Markup

from spectre_osint.core.entities import Finding, InvestigationResult
from spectre_osint.core.types import EntityType, FindingStatus, UsernameCheckStatus

_USERNAME_SWEEP_TITLE = "Username sweep"
_IDENTITY_TITLE = "Identity correlation"

STATUS_FILTERS = (
    "ALL",
    "FOUND",
    "CONFIRMED",
    "LIKELY",
    "NOT_FOUND",
    "BLOCKED",
    "LOGIN_REQUIRED",
    "PROVIDER_UNAVAILABLE",
    "INCONCLUSIVE",
    "RATE_LIMITED",
    "SESSION_EXPIRED",
    "CHALLENGE_REQUIRED",
    "CAPTCHA_REQUIRED",
    "TEMPORARILY_LIMITED",
    "OAUTH_BROWSER_REJECTED",
)

RELATION_LABELS = {
    "FOUND_ON": "found on",
    "RESOLVES_TO": "resolves to",
    "HOSTED_ON": "hosted on",
    "BELONGS_TO_ASN": "belongs to ASN",
    "USES_EMAIL": "uses email",
    "USES_USERNAME": "uses username",
    "REFERENCES": "references",
    "HAS_CERTIFICATE": "has certificate",
    "HAS_SUBDOMAIN": "has subdomain",
    "OBSERVED_BY": "observed by",
    "LINKS_TO": "publicly links to",
    "REGISTERED_BY": "registered by",
    "USES_NAMESERVER": "uses nameserver",
    "USES_TECHNOLOGY": "uses technology",
    "HAS_MX": "has MX",
    "BELONGS_TO_DOMAIN": "belongs to domain",
    "POSSIBLE_MATCH": "possible match (not identity)",
    "HAS_PROFILE": "has public profile on",
    "IDENTITY_LINK": "public identity evidence links",
    "OPERATOR_PROVIDED_ALIAS": "operator-provided alias (not identity evidence)",
    "OPERATOR_PROVIDED_INPUT": "operator-provided input (not identity evidence)",
}


def relation_label(relation: str) -> str:
    key = getattr(relation, "value", relation)
    return RELATION_LABELS.get(str(key), str(key).replace("_", " ").lower())


def is_username_site_finding(finding: Finding) -> bool:
    return finding.module == "username" and finding.title not in {_USERNAME_SWEEP_TITLE, _IDENTITY_TITLE}


def platform_of(finding: Finding) -> str:
    data = finding.data or {}
    return str(
        data.get("platform")
        or data.get("site")
        or (finding.title if finding.title != _USERNAME_SWEEP_TITLE else "")
        or finding.module
    )


def check_status_of(finding: Finding) -> str:
    data = finding.data or {}
    return str(
        data.get("check_status")
        or data.get("verification_status")
        or data.get("status")
        or finding.status.value
    )


def username_rows(result: InvestigationResult) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in result.findings:
        if not is_username_site_finding(finding):
            continue
        data = finding.data or {}
        url = str(data.get("profile_url") or data.get("final_url") or "")
        rows.append(
            {
                "platform": platform_of(finding),
                "username": str(data.get("username") or result.target),
                "status": check_status_of(finding),
                "finding_status": finding.status.value,
                "confidence": finding.confidence.value if finding.confidence else "",
                "profile_url": url,
                "detail": str(data.get("reason") or data.get("error") or finding.summary),
                "http_status": data.get("http_status"),
                "evidence": "yes" if finding.status == FindingStatus.FOUND else "",
                "checked_at": str(data.get("checked_at") or finding.timestamp.isoformat()),
                "summary": finding.summary,
                "access_mode": str(data.get("access_mode") or "ANONYMOUS_PUBLIC"),
                "cache_state": str(data.get("cache_state") or "LIVE"),
                "anonymous_status": str(data.get("anonymous_status") or ""),
                "authenticated_status": str(data.get("authenticated_status") or ""),
                "session_status": str(data.get("session_status") or ""),
                "cache_age_seconds": data.get("cache_age_seconds"),
                "observed": observed_profile_fields(data),
            }
        )
    return rows


def observed_profile_fields(data: dict[str, Any] | None) -> list[dict[str, Any]]:
    payload = data or {}
    raw_observed = payload.get("observed")
    observed: dict[str, Any] = raw_observed if isinstance(raw_observed, dict) else {}
    order = (
        "display_name",
        "bio",
        "location",
        "organization",
        "website",
        "personal_domain",
        "public_email",
        "public_id",
        "avatar_url",
        "external_links",
        "social_links",
    )
    rows: list[dict[str, Any]] = []
    for key in order:
        item = observed.get(key)
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if not value:
            continue
        if isinstance(value, list):
            value = [str(entry) for entry in value if entry]
            if not value:
                continue
        rows.append(
            {
                "field": key,
                "value": value,
                "source": str(item.get("source") or ""),
                "observed_at": str(item.get("observed_at") or ""),
                "kind": "observed",
            }
        )
    return rows


def username_counts(result: InvestigationResult) -> dict[str, int]:
    rows = username_rows(result)
    counter: Counter[str] = Counter()
    for row in rows:
        status = row["status"]
        counter[status] += 1
        if status in {UsernameCheckStatus.CONFIRMED.value, UsernameCheckStatus.LIKELY.value}:
            counter["FOUND"] += 1
    out = {
        "checked": len(rows),
        "found": counter.get("FOUND", 0),
        "confirmed": counter.get(UsernameCheckStatus.CONFIRMED.value, 0),
        "likely": counter.get(UsernameCheckStatus.LIKELY.value, 0),
        "not_found": counter.get(UsernameCheckStatus.NOT_FOUND.value, 0),
        "blocked": counter.get(UsernameCheckStatus.BLOCKED.value, 0),
        "login_required": counter.get(UsernameCheckStatus.LOGIN_REQUIRED.value, 0),
        "rate_limited": counter.get(UsernameCheckStatus.RATE_LIMITED.value, 0),
        "provider_unavailable": counter.get(UsernameCheckStatus.PROVIDER_UNAVAILABLE.value, 0),
        "inconclusive": counter.get(UsernameCheckStatus.INCONCLUSIVE.value, 0),
        "session_expired": counter.get(UsernameCheckStatus.SESSION_EXPIRED.value, 0),
        "challenge_required": counter.get(UsernameCheckStatus.CHALLENGE_REQUIRED.value, 0),
        "captcha_required": counter.get(UsernameCheckStatus.CAPTCHA_REQUIRED.value, 0),
        "temporarily_limited": counter.get(UsernameCheckStatus.TEMPORARILY_LIMITED.value, 0),
        "oauth_browser_rejected": counter.get(UsernameCheckStatus.OAUTH_BROWSER_REJECTED.value, 0),
    }
    return out


def filter_username_rows(rows: list[dict[str, Any]], status: str | None) -> list[dict[str, Any]]:
    if not status or status.upper() in {"", "ALL"}:
        return rows
    wanted = status.upper()
    if wanted == "FOUND":
        return [r for r in rows if r["status"] in {"CONFIRMED", "LIKELY"}]
    return [r for r in rows if r["status"] == wanted]


def modules_executed(result: InvestigationResult) -> list[str]:
    return sorted({f.module for f in result.findings if f.module})


def duration_seconds(result: InvestigationResult) -> float | None:
    if not result.finished_at:
        return None
    start = result.started_at
    end = result.finished_at
    if start.tzinfo is None and end.tzinfo is not None:
        start = start.replace(tzinfo=end.tzinfo)
    if end.tzinfo is None and start.tzinfo is not None:
        end = end.replace(tzinfo=start.tzinfo)
    return max(0.0, (end - start).total_seconds())


def investigation_meta(result: InvestigationResult) -> dict[str, Any]:
    elapsed = duration_seconds(result)
    return {
        "target": result.target,
        "target_type": result.target_type.value
        if isinstance(result.target_type, EntityType)
        else str(result.target_type),
        "mode": result.mode,
        "case_id": result.case_id,
        "case_name": result.case_name,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "duration_seconds": elapsed,
        "modules": modules_executed(result),
        "providers": list(result.providers_queried),
        "entities": len(result.entities),
        "relationships": len(result.relationships),
        "findings": len(result.findings),
        "evidence": len(result.evidence),
        "report_path": result.report_path,
        "run_id": result.run_id,
    }


def sibling_reports(report_path: str | None) -> dict[str, str]:
    if not report_path:
        return {}
    from pathlib import Path

    path = Path(report_path)
    stem = path.stem
    parent = path.parent
    mapping = {
        "html": parent / f"{stem}.html",
        "json": parent / f"{stem}.json",
        "markdown": parent / f"{stem}.md",
        "graphml": parent / f"{stem}.graphml",
        "csv": parent / f"{stem}-entities.csv",
    }
    out = {key: str(item) for key, item in mapping.items() if item.exists()}
    if path.exists():
        out.setdefault(path.suffix.lstrip(".") or "html", str(path))
    return out


def iso(value: datetime | None) -> str:
    return value.isoformat() if value else ""


STATUS_MARKS = {
    "CONFIRMED": "✓",
    "LIKELY": "~",
    "INCONCLUSIVE": "?",
    "NOT_FOUND": "×",
    "BLOCKED": "!",
    "LOGIN_REQUIRED": "🔒",
    "RATE_LIMITED": "⏳",
    "PROVIDER_UNAVAILABLE": "○",
    "SESSION_EXPIRED": "🔒",
    "CHALLENGE_REQUIRED": "!",
    "CAPTCHA_REQUIRED": "!",
    "TEMPORARILY_LIMITED": "⏳",
    "OAUTH_BROWSER_REJECTED": "!",
    "FOUND": "✓",
    "ERROR": "!",
    "ACTIVE": "●",
    "NOT_CONFIGURED": "○",
    "AUTHENTICATED_PUBLIC": "◉",
    "ANONYMOUS_PUBLIC": "○",
    "OBSERVED": "◌",
}

COLLECTION_ISSUE_KEYS = (
    "blocked",
    "login_required",
    "rate_limited",
    "provider_unavailable",
    "session_expired",
    "challenge_required",
    "captcha_required",
    "temporarily_limited",
    "oauth_browser_rejected",
)

ERROR_STATUSES = {
    "PROVIDER_UNAVAILABLE",
    "BLOCKED",
    "LOGIN_REQUIRED",
    "ERROR",
    "RATE_LIMITED",
    "SESSION_EXPIRED",
    "CHALLENGE_REQUIRED",
    "CAPTCHA_REQUIRED",
    "TEMPORARILY_LIMITED",
    "OAUTH_BROWSER_REJECTED",
}

GRAPH_FOCUS_RELATIONS = {"HAS_PROFILE", "LINKS_TO", "IDENTITY_LINK"}


def status_mark(code: str | None) -> str:
    return STATUS_MARKS.get(str(code or ""), "·")


def highlight_match(text: str | None, value: str | None) -> Markup:
    raw = str(text or "")
    needle = str(value or "").strip()
    escaped = html.escape(raw)
    if not needle:
        return Markup(escaped)
    pattern = re.compile(re.escape(html.escape(needle)), re.I)
    return Markup(pattern.sub(lambda match: f"<mark>{match.group(0)}</mark>", escaped))


def collection_health(counts: dict[str, int]) -> dict[str, int]:
    issues = sum(int(counts.get(key, 0) or 0) for key in COLLECTION_ISSUE_KEYS)
    checked = int(counts.get("checked", 0) or 0)
    return {
        "ok": max(0, checked - issues),
        "blocked": int(counts.get("blocked", 0) or 0),
        "login_required": int(counts.get("login_required", 0) or 0),
        "rate_limited": int(counts.get("rate_limited", 0) or 0),
        "provider_unavailable": int(counts.get("provider_unavailable", 0) or 0),
        "issues": issues,
        "checked": checked,
    }


def top_evidence_rows(rows: list[dict[str, Any]], *, limit: int = 8) -> list[dict[str, Any]]:
    ranked: list[tuple[int, dict[str, Any]]] = []
    for row in rows:
        status = str(row.get("status") or "")
        if status == "CONFIRMED":
            ranked.append((0, row))
        elif status == "LIKELY":
            ranked.append((1, row))
    ranked.sort(key=lambda item: (item[0], str(item[1].get("platform") or "")))
    return [row for _, row in ranked[:limit]]


def identity_payload(result: InvestigationResult) -> dict[str, Any]:
    raw = result.identity_correlation
    if isinstance(raw, dict) and raw:
        return raw
    for finding in result.findings:
        if finding.title == _IDENTITY_TITLE and isinstance(finding.data, dict):
            if "clusters" in finding.data or "pairs" in finding.data:
                return finding.data
    return {}


_STRONG_PAIR_EVIDENCE = frozenset(
    {
        "cross_profile_link",
        "same_display_name",
        "same_personal_domain",
        "same_personal_url",
        "same_public_email",
        "same_public_id",
        "same_domain",
        "same_url",
        "same_organization",
        "similar_bio",
        "same_avatar_url",
        "same_location",
    }
)


def _pair_is_notable(pair: dict[str, Any]) -> bool:
    """GUI default: hide same_username-only pairs. Backend weights stay unchanged."""
    if pair.get("conflicts"):
        return True
    score = int(pair.get("score") or 0)
    if score >= 10:
        return True
    evidence = {str(item) for item in (pair.get("evidence") or [])}
    return bool(evidence & _STRONG_PAIR_EVIDENCE)


def _pair_side_label(pair: dict[str, Any], side: str) -> str:
    platform = str(pair.get(side) or "")
    username = str(pair.get(f"{side}_username") or "")
    if username:
        return f"{platform} ({username})"
    return platform


def identity_view(result: InvestigationResult) -> dict[str, Any]:
    payload = identity_payload(result)
    clusters = list(payload.get("clusters") or [])
    bands = {str(cluster.get("band") or "") for cluster in clusters}
    pairs = []
    for pair in list(payload.get("pairs") or []):
        row = dict(pair)
        row["left_label"] = _pair_side_label(row, "left")
        row["right_label"] = _pair_side_label(row, "right")
        pairs.append(row)
    pairs.sort(key=lambda item: (-int(item.get("score") or 0), item.get("left_label") or ""))
    notable = [pair for pair in pairs if _pair_is_notable(pair)]
    return {
        "payload": payload,
        "records": int(payload.get("records") or 0),
        "has_records": int(payload.get("records") or 0) > 1,
        "has_cluster": bool(clusters),
        "has_strong": bool(bands & {"STRONG", "LIKELY"}),
        "clusters": clusters,
        "pairs": pairs,
        "notable_pairs": notable,
        "unclustered": list(payload.get("unclustered") or []),
        "max_score": int(payload.get("max_score") or 0),
        "notes": list(payload.get("notes") or []),
    }


def _entity_type_value(entity: Any) -> str:
    kind = getattr(entity, "type", "")
    return str(getattr(kind, "value", kind) or "")


def graph_payload(result: InvestigationResult, *, limit: int = 36) -> dict[str, Any]:
    by_id = {entity.id: entity for entity in result.entities}
    nodes: list[dict[str, Any]] = []
    used: set[str] = set()

    def add_entity(entity: Any) -> None:
        if entity is None or entity.id in used:
            return
        used.add(entity.id)
        value = str(getattr(entity, "normalized_value", None) or getattr(entity, "value", "") or entity.id)
        etype = _entity_type_value(entity)
        nodes.append(
            {
                "id": entity.id,
                "label": value[:42],
                "type": etype,
                "kind": "target" if value == result.target else "entity",
            }
        )

    for entity in result.entities:
        if str(entity.normalized_value) == result.target:
            add_entity(entity)
            break
    else:
        if result.entities:
            add_entity(result.entities[0])

    focused = [
        rel
        for rel in result.relationships
        if str(getattr(rel.relation, "value", rel.relation)) in GRAPH_FOCUS_RELATIONS
    ]
    rest = [rel for rel in result.relationships if rel not in focused]
    ordered = focused + rest
    edges: list[dict[str, str]] = []
    truncated = False
    for rel in ordered:
        if len(used) >= limit and (
            rel.from_entity_id not in used or rel.to_entity_id not in used
        ):
            truncated = True
            continue
        add_entity(by_id.get(rel.from_entity_id))
        add_entity(by_id.get(rel.to_entity_id))
        if rel.from_entity_id in used and rel.to_entity_id in used:
            edges.append(
                {
                    "from": rel.from_entity_id,
                    "to": rel.to_entity_id,
                    "relation": str(getattr(rel.relation, "value", rel.relation)),
                }
            )
        if len(used) >= limit:
            truncated = truncated or len(result.entities) > limit
    return {
        "nodes": nodes,
        "edges": edges,
        "truncated": truncated or len(result.entities) > len(nodes),
        "node_count": len(result.entities),
        "edge_count": len(result.relationships),
    }


def classify_entity_observation(
    *,
    last_seen: datetime | None,
    latest_run_started: datetime | None,
    latest_run_finished: datetime | None,
) -> dict[str, Any]:
    """Latest vs historical using case-run timestamps only. No identity inference."""
    if last_seen is None or latest_run_started is None:
        return {"kind": "LATEST", "superseded": False}
    last = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=latest_run_started.tzinfo)
    start = latest_run_started
    if last.tzinfo is None and start.tzinfo is not None:
        last = last.replace(tzinfo=start.tzinfo)
    if start.tzinfo is None and last.tzinfo is not None:
        start = start.replace(tzinfo=last.tzinfo)
    if last < start:
        return {"kind": "HISTORICAL", "superseded": True}
    return {"kind": "LATEST", "superseded": False}


def group_username_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        handle = str(row.get("username") or "")
        grouped.setdefault(handle, []).append(row)
    out = []
    for handle, items in grouped.items():
        hits = [r for r in items if r.get("status") in {"CONFIRMED", "LIKELY"}]
        out.append({"username": handle, "rows": items, "hits": len(hits), "checked": len(items)})
    out.sort(key=lambda item: (0 if item["username"] else 1, item["username"]))
    return out


def search_kind_findings(result: InvestigationResult, kind: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in result.findings:
        data = finding.data or {}
        if finding.module == "search" and str(data.get("kind") or "") == kind:
            rows.append(data)
    return rows


def mention_findings(result: InvestigationResult) -> list[Finding]:
    return [
        finding
        for finding in result.findings
        if finding.module == "mentions" and finding.status == FindingStatus.OBSERVED
    ]


_MENTION_RELEVANCE_RANK = {"DIRECT": 0, "ASSOCIATED": 1, "AMBIGUOUS": 2}


def mention_relevance_counts(result: InvestigationResult) -> dict[str, int]:
    counts = {"DIRECT": 0, "ASSOCIATED": 0, "AMBIGUOUS": 0}
    for finding in mention_findings(result):
        relevance = str((finding.data or {}).get("relevance") or "AMBIGUOUS")
        if relevance not in counts:
            relevance = "AMBIGUOUS"
        counts[relevance] += 1
    return counts


def _mention_card(finding: Finding) -> dict[str, Any]:
    from spectre_osint.modules.mentions.relevance import provider_label

    data = dict(finding.data or {})
    sources = [str(item) for item in (data.get("sources") or []) if item]
    if not sources and data.get("provider"):
        sources = [str(data.get("provider"))]
    unique: list[str] = []
    for source in sources:
        if source not in unique:
            unique.append(source)
    return {
        "finding": finding,
        "data": data,
        "title": str(data.get("title") or finding.title),
        "snippet": str(data.get("snippet") or ""),
        "url": str(data.get("canonical_url") or data.get("url") or ""),
        "domain": str(data.get("domain") or ""),
        "published_at": data.get("published_at"),
        "timestamp": finding.timestamp,
        "matched_value": str(data.get("matched_value") or data.get("query") or ""),
        "query": str(data.get("query") or ""),
        "confidence": str(data.get("confidence") or (finding.confidence.value if finding.confidence else "")),
        "relevance": str(data.get("relevance") or "AMBIGUOUS"),
        "relevance_reason": str(data.get("relevance_reason") or ""),
        "sources": unique,
        "observed_by": ", ".join(provider_label(item) for item in unique),
        "provider": str(data.get("provider") or ""),
    }


def mention_groups(result: InvestigationResult) -> list[dict[str, Any]]:
    grouped: dict[str, list[Finding]] = {}
    kinds: dict[str, str] = {}
    for finding in mention_findings(result):
        data = finding.data or {}
        query = str(data.get("query") or "")
        grouped.setdefault(query, []).append(finding)
        kinds[query] = str(data.get("kind") or data.get("input_type") or "username")
    out: list[dict[str, Any]] = []
    for query, items in grouped.items():
        cards: list[dict[str, Any]] = []
        by_url: dict[str, dict[str, Any]] = {}
        for finding in items:
            card = _mention_card(finding)
            url = card["url"]
            if url and url in by_url:
                prev = by_url[url]
                merged = list(prev["sources"])
                for source in card["sources"]:
                    if source not in merged:
                        merged.append(source)
                prev["sources"] = merged
                from spectre_osint.modules.mentions.relevance import provider_label

                prev["observed_by"] = ", ".join(provider_label(item) for item in merged)
                continue
            cards.append(card)
            if url:
                by_url[url] = card
        cards.sort(
            key=lambda card: (
                _MENTION_RELEVANCE_RANK.get(str(card.get("relevance") or ""), 9),
                str(card.get("title") or ""),
            )
        )
        out.append(
            {
                "query": query,
                "kind": kinds.get(query, "username"),
                "count": len(cards),
                "mentions": cards,
            }
        )
    return out


def overview_context(result: InvestigationResult, counts: dict[str, int], meta: dict[str, Any]) -> dict[str, Any]:
    health = collection_health(counts)
    identity = identity_view(result)
    return {
        "meta": meta,
        "counts": counts,
        "health": health,
        "identity": identity,
        "providers_n": len(meta.get("providers") or []),
        "checked": counts.get("checked", 0),
    }
