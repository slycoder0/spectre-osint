"""Search intelligence: plan queries, search, discover, extract, pivot.

Mentions stay mentions. Discovered URLs are never CONFIRMED profiles.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.entities import Entity, Finding, utcnow
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.logger import get_logger
from spectre_osint.core.redaction import redact_text
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.modules.mentions.engine import (
    PER_PROVIDER_LIMIT,
    _canonical_url,
    _finding_from_raw,
    _provider_available,
    _safe_associated,
    _valid_mention_url,
)
from spectre_osint.modules.mentions.match import match_input
from spectre_osint.modules.mentions.providers import RawMention
from spectre_osint.modules.mentions.relevance import classify_mention, normalize_case_inputs
from spectre_osint.modules.search.discover import classify_discovered_profile
from spectre_osint.modules.search.extract import extract_indicators, indicator_findings
from spectre_osint.modules.search.novelty import annotate_indicators, discovery_metrics
from spectre_osint.modules.search.pivots import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_PIVOTS,
    _norm_key,
    pivot_entities,
    propose_pivots,
)
from spectre_osint.modules.search.planner import DEFAULT_BUDGET, PlannedQuery, plan_queries
from spectre_osint.modules.search.providers import (
    SearxngProvider,
    default_search_providers,
)
from spectre_osint.modules.username.matching import (
    SIMILAR_CANDIDATE,
    UNRELATED,
)

logger = get_logger("spectre.search")


class SearchEngine:
    """Backward-compatible Google CSE helper. Discovery uses collect_search_intelligence."""

    name = "search"

    def __init__(self, http: HttpClient, settings: Settings) -> None:
        self.http = http
        self.settings = settings

    async def search(self, query: str) -> Finding:
        if not self.settings.secret_present("google_api_key") or not self.settings.google_cse_id:
            return Finding(
                module=self.name,
                title="Search",
                status=FindingStatus.NOT_CONFIGURED,
                summary="Provider not configured",
                data={"query": query, "provider": "google_cse"},
            )
        response = await self.http.get(
            "https://www.googleapis.com/customsearch/v1",
            provider="google-cse",
            params={
                "key": self.settings.google_api_key.get_secret_value() if self.settings.google_api_key else "",
                "cx": self.settings.google_cse_id,
                "q": query,
            },
            follow_redirects=True,
        )
        items = (response.json_data or {}).get("items") or []
        return Finding(
            module=self.name,
            title="Google CSE",
            status=FindingStatus.FOUND if items else FindingStatus.NOT_FOUND,
            summary=f"{len(items)} public results" if items else "NOT FOUND",
            data={
                "query": query,
                "results": [{"title": i.get("title"), "link": i.get("link")} for i in items[:10]],
            },
        )


def _known_hosts() -> set[str]:
    try:
        from spectre_osint.modules.username.engine import load_sites
    except Exception:  # noqa: BLE001
        return set()
    hosts: set[str] = set()
    for site in load_sites():
        for key in ("profile_url", "check_url"):
            host = (urlparse(str(site.get(key) or "")).hostname or "").lower().removeprefix("www.")
            if host:
                hosts.add(host)
    return hosts


def _existing_urls(findings: list[Finding]) -> set[str]:
    seen: set[str] = set()
    for finding in findings:
        data = finding.data or {}
        for key in ("canonical_url", "profile_url", "url", "final_url"):
            raw = str(data.get(key) or "")
            if raw:
                seen.add(_canonical_url(raw))
    return seen


def _query_kind(planned: PlannedQuery) -> str:
    if planned.input_kind in {"username", "name", "email", "domain"}:
        return planned.input_kind
    if planned.query_type in {"name", "pair", "name_domain"}:
        return "name"
    if planned.query_type == "email":
        return "email"
    if "domain" in planned.query_type:
        return "domain"
    return "username"


def _match_value(planned: PlannedQuery, leads: dict[str, list[str]]) -> str:
    if planned.target_value:
        return planned.target_value
    if planned.originating_lead:
        return planned.originating_lead
    kind = _query_kind(planned)
    if kind == "username":
        return (leads.get("usernames") or [""])[0]
    if kind == "name":
        return (leads.get("names") or [""])[0]
    if kind == "email":
        return (leads.get("emails") or [""])[0]
    if kind == "domain":
        return (leads.get("domains") or [""])[0]
    return planned.text


def _safe_query(kind: str, value: str) -> str:
    if kind == "email":
        return redact_text(value)
    return value


async def _run_queries(
    queries: list[PlannedQuery],
    *,
    http: HttpClient,
    settings: Settings,
    leads: dict[str, list[str]],
    known_hosts: set[str],
    existing_urls: set[str],
    include_coverage: bool = True,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    providers = default_search_providers()
    findings: list[Finding] = []
    entities: list[Entity] = []
    evidence: list[Any] = []
    queried: list[str] = []
    unavailable: list[str] = []
    seen_urls = set(existing_urls)
    stats = {
        "results": 0,
        "relevant": 0,
        "unrelated": 0,
        "discovered": 0,
        "queries_issued": 0,
    }
    for planned in queries:
        stats["queries_issued"] += 1
        kind = _query_kind(planned)
        seed = _match_value(planned, leads) or planned.text
        originating_lead = planned.originating_lead or seed
        safe = _safe_query(kind, seed)
        for provider in providers:
            name = str(getattr(provider, "name", "search"))
            if not _provider_available(provider, settings):
                if name not in unavailable:
                    unavailable.append(name)
                    if progress:
                        progress({
                            "phase": "search",
                            "state": "degraded",
                            "provider": name,
                            "message": f"{name} not configured; continuing",
                        })
                continue
            if name not in queried:
                queried.append(name)
            if progress:
                progress({
                    "phase": "search",
                    "state": "running",
                    "provider": name,
                })
            try:
                hits: list[RawMention] = await provider.search(
                    planned.text, http=http, settings=settings, limit=PER_PROVIDER_LIMIT
                )
            except Exception as exc:  # noqa: BLE001
                logger.info("search provider=%s unavailable: %s", name, type(exc).__name__)
                if progress:
                    progress({
                        "phase": "search",
                        "state": "degraded",
                        "provider": name,
                        "message": f"{name} unavailable; continuing",
                    })
                continue
            raw_count = int(getattr(provider, "last_raw", len(hits)) or 0)
            parsed = [hit for hit in hits if _valid_mention_url(hit.url)]
            matched = 0
            for hit in parsed:
                stats["results"] += 1
                canonical = _canonical_url(hit.url)
                matched_row = match_input(
                    seed,
                    kind,
                    title=hit.title,
                    snippet=hit.snippet,
                    url=hit.url,
                    author=hit.author,
                )
                discovered = False
                relevance = UNRELATED
                disc_res = None
                if kind == "username":
                    disc_res = classify_discovered_profile(
                        url=hit.url,
                        title=hit.title,
                        snippet=hit.snippet,
                        username=seed,
                        known_hosts=known_hosts,
                    )
                    if disc_res.is_candidate:
                        discovered = True
                        relevance = disc_res.relevance
                if matched_row is None and not discovered:
                    stats["unrelated"] += 1
                    continue
                if matched_row is not None:
                    matched += 1
                    relevance, relevance_reason, associated_with = classify_mention(
                        kind,
                        matched_row.match_type,
                        title=hit.title,
                        snippet=hit.snippet,
                        url=hit.url,
                        author=hit.author,
                        case_inputs=leads,
                    )
                    if associated_with:
                        associated_with = [_safe_associated(item) for item in associated_with]
                else:
                    relevance_reason = "username_path"
                    associated_with = []
                stats["relevant"] += 1
                if canonical in seen_urls:
                    continue
                seen_urls.add(canonical)
                if discovered and disc_res is not None:
                    stats["discovered"] += 1
                    host = (urlparse(hit.url).hostname or "").lower().removeprefix("www.")
                    handle = disc_res.observed_username or seed.lstrip("@")
                    match_type = disc_res.match_type
                    if match_type == SIMILAR_CANDIDATE:
                        summary = f"Similar profile candidate on {host}: @{handle} (lead: @{originating_lead.lstrip('@')})"
                        confidence = Confidence.LOW
                        tags = ["candidate", "discovered", "similar"]
                    else:
                        summary = f"Candidate profile on {host}: @{handle}"
                        confidence = Confidence.LOW
                        tags = ["candidate", "discovered"]
                    findings.append(
                        Finding(
                            module="search",
                            title="Discovered profile",
                            status=FindingStatus.OBSERVED,
                            summary=summary,
                            confidence=confidence,
                            data={
                                "kind": "discovered_profile",
                                "platform": "discovered",
                                "host": host,
                                "username": handle,
                                "requested_username": seed.lstrip("@"),
                                "observed_username": handle,
                                "originating_lead": originating_lead.lstrip("@"),
                                "match_type": match_type,
                                "profile_url": canonical,
                                "source": name,
                                "relevance": relevance,
                                "candidate": True,
                                "check_status": "INCONCLUSIVE",
                                "query": safe,
                                "query_type": planned.query_type,
                                "title": hit.title,
                                "snippet": hit.snippet,
                                "observed_at": utcnow().isoformat(),
                            },
                        )
                    )
                    entities.append(
                        Entity.create(
                            EntityType.SOCIAL_PROFILE,
                            canonical,
                            source=name,
                            confidence=confidence,
                            tags=tags,
                            metadata={
                                "candidate": True,
                                "host": host,
                                "username": handle,
                                "requested_username": seed.lstrip("@"),
                                "observed_username": handle,
                                "originating_lead": originating_lead.lstrip("@"),
                                "match_type": match_type,
                                "not_confirmed": True,
                            },
                        )
                    )
                    logger.debug(
                        "discovered profile host=%s input=username relevance=%s match_type=%s",
                        host,
                        relevance,
                        match_type,
                    )
                    continue
                if matched_row is None:
                    continue
                _mention, entity, ev, finding = _finding_from_raw(
                    hit,
                    query=seed,
                    kind=kind,
                    match_type=matched_row.match_type,
                    matched_field=matched_row.matched_field,
                    matched_value=matched_row.matched_value,
                    excerpt=matched_row.excerpt,
                    safe_query=safe,
                    relevance=relevance,
                    relevance_reason=relevance_reason,
                    associated_with=associated_with,
                    originating_lead=originating_lead.lstrip("@"),
                )
                findings.append(finding)
                entities.append(entity)
                evidence.append(ev)
            logger.debug(
                "search provider=%s query_type=%s raw=%s parsed=%s matched=%s deduped=%s",
                name,
                planned.query_type,
                raw_count,
                len(parsed),
                matched,
                len(parsed),
            )
    coverage_data = {
        "kind": "coverage",
        "providers": len(queried),
        "providers_queried": queried,
        "providers_unavailable": unavailable,
        "queries_issued": stats["queries_issued"],
        "results": stats["results"],
        "relevant": stats["relevant"],
        "unrelated": stats["unrelated"],
        "discovered": stats["discovered"],
    }
    if include_coverage:
        findings.append(
            Finding(
                module="search",
                title="Search coverage",
                status=FindingStatus.FOUND if stats["results"] else FindingStatus.NOT_FOUND,
                summary=(
                    f"{stats['queries_issued']} queries, {stats['results']} results, "
                    f"{stats['discovered']} profile candidates"
                ),
                data=coverage_data,
            )
        )
    return {
        "findings": findings,
        "entities": entities,
        "evidence": evidence,
        "providers_queried": queried,
        "stats": stats,
        "coverage": coverage_data,
    }


async def collect_search_intelligence(
    entity: Entity,
    http: HttpClient,
    *,
    settings: Settings | None = None,
    case_inputs: dict[str, Any] | None = None,
    existing_findings: list[Finding] | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    cfg = settings or get_settings()
    budget = int(getattr(cfg, "search_query_budget", DEFAULT_BUDGET) or DEFAULT_BUDGET)
    max_pivots = int(getattr(cfg, "search_max_pivots", DEFAULT_MAX_PIVOTS) or DEFAULT_MAX_PIVOTS)
    max_depth = int(getattr(cfg, "search_max_depth", DEFAULT_MAX_DEPTH) or DEFAULT_MAX_DEPTH)
    leads = normalize_case_inputs(case_inputs)
    if entity.type == EntityType.USERNAME and entity.normalized_value not in leads["usernames"]:
        leads["usernames"] = [entity.normalized_value, *leads["usernames"]]
    queries = plan_queries(leads, budget=budget)
    known_hosts = _known_hosts()
    existing = list(existing_findings or [])
    bundle = await _run_queries(
        queries,
        http=http,
        settings=cfg,
        leads=leads,
        known_hosts=known_hosts,
        existing_urls=_existing_urls(existing),
        include_coverage=True,
        progress=progress,
    )
    merged_findings = existing + list(bundle["findings"])
    operator_handles = {item.lower().lstrip("@") for item in leads["usernames"]}
    operator_emails = {item.lower() for item in leads["emails"]}
    operator_domains = {item.lower() for item in leads["domains"]}
    indicators = annotate_indicators(
        extract_indicators(merged_findings, operator_usernames=operator_handles),
        operator_handles=operator_handles,
        operator_emails=operator_emails,
        operator_domains=operator_domains,
        findings=merged_findings,
    )
    bundle["findings"].extend(indicator_findings(indicators))
    known_keys = {_norm_key("username", item) for item in leads["usernames"]}
    known_keys |= {_norm_key("email", item) for item in leads["emails"]}
    known_keys |= {_norm_key("domain", item) for item in leads["domains"]}
    remaining = max_pivots
    all_pivot_rows: list[dict[str, Any]] = []
    for depth in range(1, max(1, max_depth) + 1):
        if remaining <= 0:
            break
        proposed = propose_pivots(
            indicators=indicators,
            known=known_keys,
            source="search",
            depth=depth,
            remaining=remaining,
        )
        accepted_rows = [row for row in proposed if row.get("accepted")]
        for row in proposed:
            if row.get("accepted"):
                known_keys.add(_norm_key(str(row.get("type")), str(row.get("target"))))
        remaining -= len(accepted_rows)
        all_pivot_rows.extend(proposed)
        if depth >= max_depth:
            break
        follow = [
            PlannedQuery(text=f'"{row["target"]}"', query_type="pivot", input_kind=str(row.get("type") or "username"))
            for row in accepted_rows
            if str(row.get("type")) in {"username", "domain", "email"}
        ][: min(4, remaining + len(accepted_rows))]
        if not follow:
            break
        extra_leads = dict(leads)
        for row in accepted_rows:
            kind = str(row.get("type") or "")
            target = str(row.get("target") or "")
            if kind == "username":
                extra_leads["usernames"] = list(dict.fromkeys([*extra_leads["usernames"], target]))
            elif kind == "email":
                extra_leads["emails"] = list(dict.fromkeys([*extra_leads["emails"], target]))
            elif kind == "domain":
                extra_leads["domains"] = list(dict.fromkeys([*extra_leads["domains"], target]))
        extra = await _run_queries(
            follow,
            http=http,
            settings=cfg,
            leads=extra_leads,
            known_hosts=known_hosts,
            existing_urls=_existing_urls(merged_findings + bundle["findings"]),
            include_coverage=False,
        )
        bundle["findings"].extend(extra["findings"])
        bundle["entities"].extend(extra["entities"])
        bundle["evidence"].extend(extra["evidence"])
        for name in extra.get("providers_queried") or []:
            if name not in bundle["providers_queried"]:
                bundle["providers_queried"].append(name)
        merged_findings = existing + list(bundle["findings"])
        indicators = annotate_indicators(
            extract_indicators(merged_findings, operator_usernames=operator_handles),
            operator_handles=operator_handles,
            operator_emails=operator_emails,
            operator_domains=operator_domains,
            findings=merged_findings,
        )
    pivot_bundle = pivot_entities(all_pivot_rows, origin_id=entity.id)
    bundle["findings"].extend(pivot_bundle["findings"])
    bundle["entities"].extend(pivot_bundle["entities"])
    bundle["relationships"] = list(pivot_bundle["relationships"])
    bundle["pivots"] = list(pivot_bundle["pivots"])
    metrics = discovery_metrics(
        indicators,
        all_pivot_rows,
        coverage=bundle.get("coverage") or {},
    )
    for finding in bundle["findings"]:
        if finding.module == "search" and str((finding.data or {}).get("kind") or "") == "coverage":
            finding.data.update(metrics)
            bundle["coverage"] = dict(finding.data)
            break
    logger.debug(
        "intelligence summary observed_names=%s handles=%s profiles=%s mentions=n/a domains=%s",
        0,
        len(operator_handles),
        sum(1 for f in bundle["findings"] if str((f.data or {}).get("kind")) == "discovered_profile"),
        sum(1 for f in bundle["findings"] if str((f.data or {}).get("indicator_type")) == "domain"),
    )
    searx = SearxngProvider()
    if not searx.available(cfg) and not any(
        f.title == "SearXNG" for f in bundle["findings"]
    ):
        bundle["findings"].insert(
            0,
            Finding(
                module="search",
                title="SearXNG",
                status=FindingStatus.NOT_CONFIGURED,
                summary="SearXNG not configured",
                data={"provider": "searxng", "kind": "provider_status"},
            ),
        )
    return bundle
