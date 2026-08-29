"""Extract public indicators from already-collected findings. No extra fetches."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from spectre_osint.core.entities import Finding, utcnow
from spectre_osint.core.presentation import is_username_site_finding, observed_profile_fields
from spectre_osint.core.types import FindingStatus
from spectre_osint.modules.mentions.relevance import lead_host

_HANDLE_RE = re.compile(r"(?<![A-Za-z0-9_])@([A-Za-z0-9_]{3,32})\b")


def _now() -> str:
    return utcnow().isoformat()


def _add(
    out: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    *,
    indicator_type: str,
    value: str,
    source: str,
    original_finding: str,
    extraction_rule: str,
    match_type: str = "EXACT_MATCH",
    originating_lead: str = "",
) -> None:
    raw = str(value or "").strip()
    if not raw:
        return
    if indicator_type == "username":
        raw = raw.lstrip("@")
    if indicator_type == "domain":
        raw = lead_host(raw) or raw
    key = (indicator_type, raw.lower())
    if key in seen:
        for item in out:
            if (item.get("indicator_type"), str(item.get("value") or "").lower()) == key:
                sources = list(item.get("sources") or [])
                if source and source not in sources:
                    sources.append(source)
                    item["sources"] = sources
                break
        return
    seen.add(key)
    out.append(
        {
            "indicator_type": indicator_type,
            "value": raw,
            "source": source,
            "sources": [source] if source else [],
            "original_finding": original_finding,
            "extraction_rule": extraction_rule,
            "match_type": match_type,
            "originating_lead": originating_lead,
            "observed_at": _now(),
        }
    )


def extract_indicators(
    findings: list[Finding],
    *,
    operator_usernames: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Public-only extraction. Operator aliases are not treated as observed."""
    operator = {item.lower().lstrip("@") for item in (operator_usernames or set())}
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for finding in findings:
        data = finding.data or {}
        fid = finding.id
        if is_username_site_finding(finding):
            status = str(data.get("check_status") or "")
            if status not in {"CONFIRMED", "LIKELY"}:
                continue
            url = str(data.get("profile_url") or "")
            if url:
                _add(
                    out,
                    seen,
                    indicator_type="url",
                    value=url,
                    source=finding.title,
                    original_finding=fid,
                    extraction_rule="profile_url",
                )
                host = lead_host(url)
                if host:
                    _add(
                        out,
                        seen,
                        indicator_type="domain",
                        value=host,
                        source=finding.title,
                        original_finding=fid,
                        extraction_rule="profile_host",
                    )
            for item in observed_profile_fields(data):
                field = str(item.get("field") or "")
                value = item.get("value")
                src = str(item.get("source") or field)
                if field in {"website", "personal_domain"} and isinstance(value, str):
                    _add(
                        out,
                        seen,
                        indicator_type="domain",
                        value=value,
                        source=src,
                        original_finding=fid,
                        extraction_rule=field,
                    )
                    _add(
                        out,
                        seen,
                        indicator_type="url",
                        value=value if "://" in value else f"https://{value}",
                        source=src,
                        original_finding=fid,
                        extraction_rule=field,
                    )
                elif field == "public_email" and isinstance(value, str):
                    _add(
                        out,
                        seen,
                        indicator_type="email",
                        value=value,
                        source=src,
                        original_finding=fid,
                        extraction_rule="public_email",
                    )
                elif field in {"external_links", "social_links"}:
                    links = value if isinstance(value, list) else [value]
                    for href in links:
                        if not href:
                            continue
                        _add(
                            out,
                            seen,
                            indicator_type="url",
                            value=str(href),
                            source=src,
                            original_finding=fid,
                            extraction_rule=field,
                        )
                        host = urlparse(str(href)).hostname or ""
                        if host:
                            _add(
                                out,
                                seen,
                                indicator_type="domain",
                                value=host,
                                source=src,
                                original_finding=fid,
                                extraction_rule=field,
                            )
            bio = ""
            for item in observed_profile_fields(data):
                if item.get("field") == "bio":
                    bio = str(item.get("value") or "")
            for handle in _HANDLE_RE.findall(bio):
                if handle.lower() in operator:
                    continue
                _add(
                    out,
                    seen,
                    indicator_type="username",
                    value=handle,
                    source=str(data.get("platform") or finding.title),
                    original_finding=fid,
                    extraction_rule="bio_handle",
                )
        if finding.module == "search" and str(data.get("kind") or "") == "discovered_profile":
            handle = str(data.get("username") or "")
            match_type = str(data.get("match_type") or "EXACT_MATCH")
            originating_lead = str(data.get("originating_lead") or "")
            if handle and handle.lower() not in operator:
                _add(
                    out,
                    seen,
                    indicator_type="username",
                    value=handle,
                    source=str(data.get("source") or "search"),
                    original_finding=fid,
                    extraction_rule="discovered_profile_username",
                    match_type=match_type,
                    originating_lead=originating_lead,
                )
            url = str(data.get("profile_url") or "")
            if url:
                _add(
                    out,
                    seen,
                    indicator_type="url",
                    value=url,
                    source=str(data.get("source") or "search"),
                    original_finding=fid,
                    extraction_rule="discovered_profile_url",
                )
    return out


def indicator_findings(rows: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for row in rows:
        findings.append(
            Finding(
                module="search",
                title="Observed indicator",
                status=FindingStatus.OBSERVED,
                summary=f"{row['indicator_type']}: {row['value']}",
                data={"kind": "indicator", **row},
            )
        )
    return findings
