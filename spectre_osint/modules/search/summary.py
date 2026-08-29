"""Deterministic public-identity summary. No LLM. No invented absence."""

from __future__ import annotations

from collections import Counter
from typing import Any

from spectre_osint.core.entities import InvestigationResult
from spectre_osint.core.presentation import (
    identity_view,
    mention_relevance_counts,
    username_counts,
    username_rows,
)
from spectre_osint.core.types import EntityType
from spectre_osint.modules.mentions.relevance import lead_host
from spectre_osint.modules.search.novelty import is_generic_display_name, useful_discovery


def _uniq(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        raw = str(item or "").strip()
        key = raw.lower()
        if not raw or key in seen:
            continue
        seen.add(key)
        out.append(raw)
    return out


def _operator_supplied(result: InvestigationResult) -> dict[str, list[str]]:
    inputs = dict(result.inputs or {})
    names = [str(inputs.get("display_name") or "").strip()]
    handles = [result.target]
    handles.extend(str(item) for item in (inputs.get("aliases") or []) if item)
    emails = [str(inputs.get("email") or "").strip()]
    domains = [lead_host(str(inputs.get("website") or ""))]
    ttype = result.target_type
    value = str(getattr(ttype, "value", ttype) or "")
    if value == EntityType.PERSON.value:
        names = [result.target, *names]
    return {
        "names": _uniq(names),
        "handles": _uniq(handles),
        "emails": _uniq(emails),
        "domains": _uniq([item for item in domains if item]),
    }


def build_intelligence_summary(result: InvestigationResult) -> dict[str, Any]:
    """Facts already on the result. Insufficient evidence ≠ confirmed absence."""
    operator = _operator_supplied(result)
    counts = username_counts(result)
    mentions = mention_relevance_counts(result)
    identity = identity_view(result)
    observed_names: list[str] = []
    observed_locations: list[str] = []
    observed_domains: list[str] = []
    observed_profiles: list[str] = []
    for row in username_rows(result):
        status = str(row.get("status") or "")
        if status not in {"CONFIRMED", "LIKELY"}:
            continue
        platform = str(row.get("platform") or "")
        if platform:
            observed_profiles.append(platform)
        for item in row.get("observed") or []:
            field = str(item.get("field") or "")
            value = item.get("value")
            if field == "display_name" and isinstance(value, str):
                handle = str(row.get("username") or result.target)
                if not is_generic_display_name(value, handle, platform=platform):
                    observed_names.append(value)
            elif field == "location" and isinstance(value, str):
                observed_locations.append(value)
            elif field in {"website", "personal_domain"} and isinstance(value, str):
                host = lead_host(value)
                if host:
                    observed_domains.append(host)
    discovered = [
        f
        for f in result.findings
        if f.module == "search" and str((f.data or {}).get("kind") or "") == "discovered_profile"
    ]
    indicators = [
        f
        for f in result.findings
        if f.module == "search" and str((f.data or {}).get("kind") or "") == "indicator"
    ]
    auto_pivots = [
        f
        for f in result.findings
        if f.module == "search" and str((f.data or {}).get("kind") or "") == "pivot"
    ]
    coverage = next(
        (
            f.data
            for f in result.findings
            if f.module == "search" and str((f.data or {}).get("kind") or "") == "coverage"
        ),
        {},
    )
    for finding in indicators:
        data = finding.data or {}
        if data.get("indicator_type") == "domain":
            observed_domains.append(str(data.get("value") or ""))
    loc_counts = Counter(item.lower() for item in observed_locations if item)
    confident_geo = ""
    if loc_counts:
        top, n = loc_counts.most_common(1)[0]
        if n >= 2:
            confident_geo = next(item for item in observed_locations if item.lower() == top)
    correlation = "Insufficient evidence"
    if identity.get("has_strong"):
        correlation = "Strong public overlap among observed profiles"
    elif identity.get("max_score", 0) >= 30 and identity.get("notable_pairs"):
        pair = identity["notable_pairs"][0]
        correlation = f"Possible public overlap: {pair.get('left_label')} ↔ {pair.get('right_label')}"
    next_pivots: list[str] = []
    if operator["names"] and counts.get("found", 0) < 3:
        next_pivots.append("exact full-name search")
    if operator["names"] and operator["handles"]:
        next_pivots.append("name + username search")
    if not discovered:
        next_pivots.append("search outside known platforms")
    if any(observed_domains):
        next_pivots.append("inspect public profile links")
    if not next_pivots:
        next_pivots.append("insufficient evidence for a further public pivot")
    summary = {
        "observed_names": _uniq(observed_names),
        "observed_handles": _uniq(
            [str(row.get("username") or "") for row in username_rows(result) if row.get("status") in {"CONFIRMED", "LIKELY"}]
        ),
        "observed_profiles": _uniq(observed_profiles),
        "observed_domains": _uniq(observed_domains),
        "geographic_indicators": [confident_geo] if confident_geo else [],
        "mentions": dict(mentions),
        "mentions_total": sum(mentions.values()),
        "correlation": correlation,
        "correlation_score": int(identity.get("max_score") or 0),
        "operator": operator,
        "coverage": {
            "profile_checks": int(counts.get("checked") or 0),
            "confirmed": int(counts.get("confirmed") or 0),
            "likely": int(counts.get("likely") or 0),
            "blocked": int(counts.get("blocked") or 0),
            "login_required": int(counts.get("login_required") or 0),
            "search_providers": int(coverage.get("providers") or 0),
            "queries_issued": int(coverage.get("queries_issued") or 0),
            "search_results": int(coverage.get("results") or 0),
            "relevant": int(coverage.get("relevant") or 0),
            "discovered_profiles": len(discovered),
            "new_indicators": len(indicators),
            "automatic_pivots": len(auto_pivots),
        },
        "next_pivots": next_pivots[:6],
        "insufficient_evidence": not bool(observed_profiles or discovered or sum(mentions.values())),
        "profile_titles": [
            str(item.get("value") or "")
            for row in username_rows(result)
            for item in (row.get("observed") or [])
            if item.get("field") == "display_name"
            and is_generic_display_name(str(item.get("value") or ""), str(row.get("username") or result.target))
        ],
        "new_discoveries": _new_discoveries(indicators),
        "discovery_gain": {
            "operator_inputs": sum(len(v) for v in operator.values()),
            "novel_indicators": int(coverage.get("novel_indicators") or len(_new_discoveries(indicators))),
            "new_handles": int(coverage.get("new_handles") or 0),
            "new_external_domains": int(coverage.get("new_domains") or 0),
            "new_profile_candidates": int(coverage.get("profile_candidates") or len(discovered)),
            "redundant_pivots_suppressed": int(coverage.get("pivots_suppressed") or 0),
        },
    }
    return summary


def _new_discoveries(indicator_findings: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for finding in indicator_findings:
        data = finding.data if hasattr(finding, "data") else finding
        if not useful_discovery(data):
            continue
        out.append(
            {
                "value": data.get("value"),
                "type": data.get("indicator_type"),
                "novelty": data.get("novelty"),
                "source": data.get("source"),
                "sources": data.get("sources") or [],
                "reason": data.get("extraction_rule"),
                "derived_from": data.get("derived_from") or "",
            }
        )
    return out[:12]
