"""Investigation workflow:

INPUT → VALIDATION → ENTITY DETECTION → PROVIDER SELECTION → COLLECTION
→ NORMALIZATION → CORRELATION → SCORING → PIVOT SUGGESTIONS → REPORT → GRAPH
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from spectre_osint.core.case_manager import CaseManager
from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.entities import (
    Entity,
    InvestigationResult,
    Relationship,
    TimelineEvent,
    utcnow,
)
from spectre_osint.core.exceptions import SpectreError, SSRFBlocked
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.logger import get_logger
from spectre_osint.core.paths import report_path, slugify
from spectre_osint.core.progress import ProgressEvent, ProgressPhase, ProgressState
from spectre_osint.core.registry import ProviderRegistry, default_registry
from spectre_osint.core.scoring import score_investigation
from spectre_osint.core.ssrf import is_blocked_ip, validate_url_syntax
from spectre_osint.core.types import Confidence, EntityType, InvestigationMode, RelationType
from spectre_osint.core.validators import detect_entity_type, is_ip, is_private_ip
from spectre_osint.correlation.graph import build_graph, export_graphml
from spectre_osint.correlation.pivots import suggest_pivots
from spectre_osint.modules.company import analyze_company
from spectre_osint.modules.domain import analyze_domain
from spectre_osint.modules.email import analyze_email
from spectre_osint.modules.hash import analyze_hash
from spectre_osint.modules.ip import analyze_ip
from spectre_osint.modules.person import analyze_person
from spectre_osint.modules.threatintel import analyze_threat
from spectre_osint.modules.url import analyze_url
from spectre_osint.modules.username import analyze_username
from spectre_osint.reporting.csv import write_csv_report
from spectre_osint.reporting.html import write_html_report
from spectre_osint.reporting.json import write_json_report
from spectre_osint.reporting.markdown import write_markdown_report

logger = get_logger("spectre.pipeline")

PIVOTABLE = {EntityType.IP, EntityType.DOMAIN, EntityType.SUBDOMAIN}


def _extend_bundle(merged: dict[str, Any], bundle: dict[str, Any]) -> None:
    for key in ("findings", "entities", "relationships", "evidence", "pivots"):
        merged.setdefault(key, []).extend(bundle.get(key) or [])
    queried = list(merged.get("providers_queried") or [])
    for name in bundle.get("providers_queried") or []:
        if name not in queried:
            queried.append(name)
    merged["providers_queried"] = queried
    if bundle.get("identity_correlation") is not None:
        merged["identity_correlation"] = bundle["identity_correlation"]


class InvestigationRunner:
    def __init__(
        self,
        settings: Settings | None = None,
        http: HttpClient | None = None,
        registry: ProviderRegistry | None = None,
        cases: CaseManager | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.http = http or HttpClient(self.settings)
        self.registry = registry or default_registry(self.http)
        self.cases = cases or CaseManager()
        self._owns_http = http is None
        self._progress: Callable[[dict[str, Any]], None] | None = None

    def _emit_progress(
        self,
        phase: str | ProgressPhase,
        state: str | ProgressState = ProgressState.RUNNING,
        *,
        current: int | None = None,
        total: int | None = None,
        provider: str | None = None,
        message: str | None = None,
        **info: Any,
    ) -> None:
        if self._progress is None:
            return
        event = ProgressEvent(
            phase=str(phase),
            state=str(state),
            current=current if current is not None else info.get("done"),
            total=total,
            provider=provider if provider is not None else info.get("source"),
            message=message if message is not None else info.get("error") or info.get("source_status"),
        )
        payload = event.as_dict()
        for k, v in info.items():
            if k not in payload:
                payload[k] = v
        try:
            self._progress(payload)
        except Exception:  # noqa: BLE001
            logger.debug("progress callback failed", exc_info=True)

    async def close(self) -> None:
        if self._owns_http:
            await self.http.close()

    async def run(
        self,
        target: str,
        *,
        force_type: EntityType | None = None,
        case_name: str | None = None,
        auto_pivot: bool = False,
        depth: int = 1,
        write_report: bool = True,
        extra: dict[str, Any] | None = None,
        refresh: bool = False,
        progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> InvestigationResult:
        started = utcnow()
        self._progress = progress
        entity_type = force_type or detect_entity_type(target)
        self._emit_progress(ProgressPhase.INITIALIZING, ProgressState.RUNNING, target=target)
        _preflight_target(target, entity_type, self.settings)
        entity = Entity.create(entity_type, target, source="user", confidence=Confidence.CONFIRMED)
        if case_name:
            selected = self.cases.select(case_name)
            case = selected or self.cases.create(case_name)
        else:
            prefix = f"case-{entity.type.value.lower()}-{slugify(entity.normalized_value, max_length=24)}"
            case = self.cases.create_unique(prefix)
        run = self.cases.start_run(
            case.id,
            entity.normalized_value,
            entity_type.value,
            depth=depth if auto_pivot else 0,
        )
        result = InvestigationResult(
            case_id=case.id,
            case_name=case.name,
            target=entity.normalized_value,
            target_type=entity_type,
            mode=InvestigationMode.PASSIVE.value,
            started_at=started,
            entities=[entity],
            run_id=run.id,
            inputs=(extra or {}).get("inputs"),
        )

        try:
            payload = dict(extra or {})
            if refresh:
                payload["refresh"] = True
            if entity.type != EntityType.USERNAME:
                self._emit_progress(ProgressPhase.COLLECTING, ProgressState.RUNNING)
            bundle = await self._collect(entity, payload)
            if entity.type != EntityType.USERNAME:
                self._emit_progress(ProgressPhase.COLLECTING, ProgressState.COMPLETED)
            self._emit_progress(ProgressPhase.NORMALIZING, ProgressState.RUNNING)
            self._merge(result, bundle)
            result.timeline = _timeline_from_result(result)
            discovery_pivots = list(bundle.get("pivots") or [])
            self._emit_progress(ProgressPhase.DISCOVERY, ProgressState.RUNNING)
            result.pivots = suggest_pivots(result) + discovery_pivots
            self._emit_progress(ProgressPhase.DISCOVERY, ProgressState.COMPLETED)
            self._emit_progress(ProgressPhase.NORMALIZING, ProgressState.COMPLETED)
            self._emit_progress(ProgressPhase.SCORING, ProgressState.RUNNING)
            result.scores = score_investigation(result)
            self._emit_progress(ProgressPhase.SCORING, ProgressState.COMPLETED)
            result.finished_at = utcnow()

            if auto_pivot and depth > 0:
                self._emit_progress(ProgressPhase.DISCOVERY, ProgressState.RUNNING, message="auto_pivot")
                await self._auto_pivot(
                    result,
                    depth=min(depth, 3),
                    visited={entity.normalized_value},
                    budget=self.settings.pivot_budget,
                )
                result.pivots = suggest_pivots(result) + discovery_pivots
                result.scores = score_investigation(result)
                result.finished_at = utcnow()
                self._emit_progress(ProgressPhase.DISCOVERY, ProgressState.COMPLETED)

            report_path_str = None
            if write_report:
                self._emit_progress(ProgressPhase.REPORT, ProgressState.RUNNING)
                report_path_str = self._write_reports(result)
                result.report_path = report_path_str
                self._emit_progress(ProgressPhase.REPORT, ProgressState.COMPLETED, message=report_path_str)
            self.cases.persist_result(result, report_path=report_path_str)
            extra = {}
            if result.scores:
                extra["scores"] = result.scores.model_dump()
            extra["providers_queried"] = result.providers_queried
            extra["modules"] = sorted({f.module for f in result.findings})
            extra["pivots"] = [p.model_dump(mode="json") for p in result.pivots]
            if result.inputs:
                extra["inputs"] = result.inputs
            self.cases.finish_run(
                run.id, status="completed", report_path=report_path_str, extra=extra
            )
            return result
        except Exception as exc:
            self.cases.finish_run(run.id, status="failed", error=str(exc))
            raise

    def _write_reports(self, result: InvestigationResult) -> str:
        graph = build_graph(result)
        graph_path = report_path(
            self.settings.reports_dir, result.case_name, result.target, ".graphml"
        )
        try:
            export_graphml(graph, graph_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Graph export failed: %s", exc)
            result.notes.append(f"GraphML export failed: {exc}")
        try:
            html_path = write_html_report(result, self.settings.reports_dir)
            write_json_report(result, self.settings.reports_dir)
            write_markdown_report(result, self.settings.reports_dir)
            write_csv_report(result, self.settings.reports_dir)
        except OSError as exc:
            raise SpectreError(
                "Reports directory is not writable. "
                "Set SPECTRE_REPORTS_DIR to a writable path and run `spectre doctor`."
            ) from exc
        return str(html_path)

    async def _collect_username_bundle(self, entity: Entity, extra: dict[str, Any]) -> dict[str, Any]:
        from spectre_osint.modules.mentions import collect_public_mentions
        from spectre_osint.modules.username.engine import load_sites
        from spectre_osint.modules.username.identity import identity_artifacts

        inputs = dict(extra.get("inputs") or {})
        aliases = [str(a) for a in (inputs.get("aliases") or []) if str(a).strip()]
        handles = [entity.normalized_value]
        for alias in aliases:
            if alias not in handles:
                handles.append(alias)
        simple = len(handles) == 1 and not inputs.get("email") and not inputs.get("website") and not inputs.get("display_name")
        mention_unavailable: set[str] = set()
        mention_leads = {
            "usernames": list(handles),
            "names": [str(inputs.get("display_name") or "").strip()] if str(inputs.get("display_name") or "").strip() else [],
            "emails": [str(inputs.get("email") or "").strip()] if str(inputs.get("email") or "").strip() else [],
            "domains": [str(inputs.get("website") or "").strip()] if str(inputs.get("website") or "").strip() else [],
        }
        if simple:
            bundle = await analyze_username(
                entity,
                self.http,
                concurrency=self.settings.max_concurrency,
                refresh=bool(extra.get("refresh")),
                progress=self._progress,
            )
            self._emit_progress(ProgressPhase.MENTIONS, ProgressState.RUNNING)
            try:
                mentions = await collect_public_mentions(
                    entity.normalized_value,
                    self.http,
                    limit=5,
                    kind="username",
                    settings=self.settings,
                    unavailable_logged=mention_unavailable,
                    case_inputs=mention_leads,
                    originating_lead=entity.normalized_value,
                    progress=self._progress,
                )
                _extend_bundle(bundle, mentions)
            except Exception as exc:  # noqa: BLE001
                logger.info("Public mention collection skipped: %s", type(exc).__name__)
                self._emit_progress(
                    ProgressPhase.MENTIONS,
                    ProgressState.DEGRADED,
                    message=f"Public mention collection skipped: {type(exc).__name__}",
                )
            self._emit_progress(ProgressPhase.MENTIONS, ProgressState.COMPLETED)
            self._emit_progress(ProgressPhase.SEARCH, ProgressState.RUNNING)
            try:
                from spectre_osint.modules.search import collect_search_intelligence

                search_bundle = await collect_search_intelligence(
                    entity,
                    self.http,
                    settings=self.settings,
                    case_inputs=mention_leads,
                    existing_findings=list(bundle.get("findings") or []),
                    progress=self._progress,
                )
                _extend_bundle(bundle, search_bundle)
            except Exception as exc:  # noqa: BLE001
                logger.info("Search intelligence skipped: %s", type(exc).__name__)
                self._emit_progress(
                    ProgressPhase.SEARCH,
                    ProgressState.DEGRADED,
                    message=f"Search intelligence skipped: {type(exc).__name__}",
                )
            self._emit_progress(ProgressPhase.SEARCH, ProgressState.COMPLETED)
            return bundle

        n_sites = len(load_sites())
        total = n_sites * len(handles)
        offset = 0

        def _progress_for(shift: int) -> Any:
            def inner(payload: dict[str, Any]) -> None:
                data = dict(payload)
                if data.get("done") is not None:
                    try:
                        data["done"] = shift + int(data["done"])
                        data["current"] = data["done"]
                    except (TypeError, ValueError):
                        pass
                data["total"] = total
                self._emit_progress(str(data.get("phase") or ProgressPhase.CATALOG.value), **{k: v for k, v in data.items() if k != "phase"})
            return inner

        merged: dict[str, Any] = {
            "findings": [],
            "entities": [entity],
            "relationships": [],
            "evidence": [],
            "providers_queried": [],
        }
        for handle in handles:
            user = (
                entity
                if handle == entity.normalized_value
                else Entity.create(EntityType.USERNAME, handle, source="operator", confidence=Confidence.CONFIRMED)
            )
            if user.id != entity.id:
                merged["entities"].append(user)
                merged["relationships"].append(
                    Relationship(
                        from_entity_id=entity.id,
                        to_entity_id=user.id,
                        relation=RelationType.OPERATOR_PROVIDED_ALIAS,
                        source="operator",
                        confidence=Confidence.LOW,
                        metadata={"not_identity_evidence": True},
                    )
                )
            bundle = await analyze_username(
                user,
                self.http,
                concurrency=self.settings.max_concurrency,
                refresh=bool(extra.get("refresh")),
                progress=_progress_for(offset),
                include_identity=False,
            )
            offset += n_sites
            _extend_bundle(merged, bundle)

        self._emit_progress(ProgressPhase.CORRELATION, ProgressState.RUNNING)
        artifacts = identity_artifacts(merged["findings"], entity)
        _extend_bundle(merged, artifacts)
        merged["identity_correlation"] = artifacts.get("identity_correlation")
        self._emit_progress(ProgressPhase.CORRELATION, ProgressState.COMPLETED)

        display_name = str(inputs.get("display_name") or "").strip()
        if display_name:
            person = Entity.create(
                EntityType.PERSON,
                display_name,
                source="operator",
                confidence=Confidence.LOW,
                tags=["operator-provided"],
                metadata={"not_identity_evidence": True},
            )
            merged["entities"].append(person)
            merged["relationships"].append(
                Relationship(
                    from_entity_id=entity.id,
                    to_entity_id=person.id,
                    relation=RelationType.OPERATOR_PROVIDED_INPUT,
                    source="operator",
                    confidence=Confidence.LOW,
                    metadata={"field": "display_name", "not_identity_evidence": True},
                )
            )

        email = str(inputs.get("email") or "").strip()
        if email:
            mail = Entity.create(EntityType.EMAIL, email, source="operator", confidence=Confidence.CONFIRMED)
            try:
                mail_bundle = await analyze_email(mail, self.http, self.registry, self.settings)
                _extend_bundle(merged, mail_bundle)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Optional email collection failed: %s", exc)
            merged["entities"].append(mail)
            merged["relationships"].append(
                Relationship(
                    from_entity_id=entity.id,
                    to_entity_id=mail.id,
                    relation=RelationType.OPERATOR_PROVIDED_INPUT,
                    source="operator",
                    confidence=Confidence.LOW,
                    metadata={"field": "email", "not_identity_evidence": True},
                )
            )

        website = str(inputs.get("website") or "").strip()
        website_type = str(inputs.get("website_type") or "")
        if website:
            site_type = EntityType.URL if website_type == EntityType.URL.value else EntityType.DOMAIN
            site_entity = Entity.create(site_type, website, source="operator", confidence=Confidence.CONFIRMED)
            try:
                handler = analyze_url if site_type == EntityType.URL else analyze_domain
                site_bundle = await handler(site_entity, self.http, self.registry, self.settings)
                _extend_bundle(merged, site_bundle)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Optional website collection failed: %s", exc)
            merged["entities"].append(site_entity)
            merged["relationships"].append(
                Relationship(
                    from_entity_id=entity.id,
                    to_entity_id=site_entity.id,
                    relation=RelationType.OPERATOR_PROVIDED_INPUT,
                    source="operator",
                    confidence=Confidence.LOW,
                    metadata={"field": "website", "not_identity_evidence": True},
                )
            )

        mention_jobs: list[tuple[str, str]] = [("username", handle) for handle in handles]
        if display_name:
            mention_jobs.append(("name", display_name))
        if email:
            mention_jobs.append(("email", email))
        if website:
            mention_jobs.append(("domain", website))
        self._emit_progress(ProgressPhase.MENTIONS, ProgressState.RUNNING)
        for kind, value in mention_jobs:
            try:
                mention_bundle = await collect_public_mentions(
                    value,
                    self.http,
                    limit=5,
                    kind=kind,
                    settings=self.settings,
                    unavailable_logged=mention_unavailable,
                    case_inputs=mention_leads,
                    originating_lead=value,
                    progress=self._progress,
                )
                _extend_bundle(merged, mention_bundle)
            except Exception as exc:  # noqa: BLE001
                logger.info("Public mention collection skipped: %s", type(exc).__name__)
        self._emit_progress(ProgressPhase.MENTIONS, ProgressState.COMPLETED)
        self._emit_progress(ProgressPhase.SEARCH, ProgressState.RUNNING)
        try:
            from spectre_osint.modules.search import collect_search_intelligence

            search_bundle = await collect_search_intelligence(
                entity,
                self.http,
                settings=self.settings,
                case_inputs=mention_leads,
                existing_findings=list(merged.get("findings") or []),
                progress=self._progress,
            )
            _extend_bundle(merged, search_bundle)
        except Exception as exc:  # noqa: BLE001
            logger.info("Search intelligence skipped: %s", type(exc).__name__)
        self._emit_progress(ProgressPhase.SEARCH, ProgressState.COMPLETED)
        return merged

    async def _collect(self, entity: Entity, extra: dict[str, Any]) -> dict[str, Any]:
        mapping = {
            EntityType.DOMAIN: analyze_domain,
            EntityType.SUBDOMAIN: analyze_domain,
            EntityType.IP: analyze_ip,
            EntityType.USERNAME: analyze_username,
            EntityType.EMAIL: analyze_email,
            EntityType.URL: analyze_url,
            EntityType.HASH: analyze_hash,
            EntityType.COMPANY: analyze_company,
            EntityType.ORGANIZATION: analyze_company,
            EntityType.PERSON: analyze_person,
            EntityType.THREAT: analyze_threat,
        }
        if entity.type == EntityType.USERNAME:
            return await self._collect_username_bundle(entity, extra)
        if entity.type == EntityType.PERSON:
            return await analyze_person(
                entity,
                self.http,
                self.registry,
                self.settings,
                username=extra.get("username"),
                email=extra.get("email"),
            )
        handler = mapping.get(entity.type)
        if handler is None:
            return await analyze_threat(entity, self.http, self.registry, self.settings)
        return await handler(entity, self.http, self.registry, self.settings)  # type: ignore[operator]

    def _merge(self, result: InvestigationResult, bundle: dict[str, Any]) -> None:
        result.findings.extend(bundle.get("findings") or [])
        result.relationships.extend(bundle.get("relationships") or [])
        result.evidence.extend(bundle.get("evidence") or [])
        result.providers_queried = sorted(
            set(result.providers_queried + list(bundle.get("providers_queried") or []))
        )
        if bundle.get("identity_correlation") is not None:
            result.identity_correlation = bundle["identity_correlation"]
        existing = {e.id: e for e in result.entities}
        for entity in bundle.get("entities") or []:
            if entity.id in existing:
                existing[entity.id].last_seen = entity.last_seen
                existing[entity.id].tags = sorted(set(existing[entity.id].tags + entity.tags))
            else:
                existing[entity.id] = entity
                result.entities.append(entity)

    async def _auto_pivot(
        self,
        result: InvestigationResult,
        *,
        depth: int,
        visited: set[str],
        budget: int,
    ) -> int:
        """Recursive pivots with visited set, remaining depth and a hard budget."""
        if depth <= 0 or budget <= 0:
            return budget
        max_follow = min(5 if depth == 1 else 3 if depth == 2 else 2, budget)
        seeds = [
            e
            for e in result.entities
            if e.type in PIVOTABLE
            and e.normalized_value not in visited
            and e.confidence in {Confidence.CONFIRMED, Confidence.HIGH}
        ]
        followed = 0
        for entity in seeds:
            if followed >= max_follow or budget <= 0:
                break
            if entity.type == EntityType.IP and is_private_ip(entity.normalized_value):
                continue
            visited.add(entity.normalized_value)
            logger.info(
                "Auto-pivot depth=%s remaining_budget=%s target=%s",
                depth,
                budget,
                entity.normalized_value,
            )
            try:
                bundle = await asyncio.wait_for(self._collect(entity, {}), timeout=60)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Pivot failed for %s: %s", entity.normalized_value, exc)
                continue
            self._merge(result, bundle)
            followed += 1
            budget -= 1
            budget = await self._auto_pivot(
                result, depth=depth - 1, visited=visited, budget=budget
            )
        return budget


def _preflight_target(target: str, entity_type: EntityType, settings: Settings) -> None:
    if settings.allow_private_targets or not settings.ssrf_enabled:
        return
    if entity_type == EntityType.URL:
        validate_url_syntax(target)
    if entity_type == EntityType.IP and (is_private_ip(target) or is_blocked_ip(target)):
        raise SSRFBlocked(f"private/reserved IP blocked: {target}")
    if is_ip(target) and is_blocked_ip(target):
        raise SSRFBlocked(f"private/reserved IP blocked: {target}")


def _timeline_from_result(result: InvestigationResult) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for finding in result.findings:
        data = finding.data or {}
        for cert in data.get("timeline") or []:
            events.append(
                TimelineEvent(
                    timestamp=_parse_dt(cert.get("date")),
                    label=cert.get("label") or "certificate event",
                    source=cert.get("source") or finding.module,
                    entity_id=finding.entity_id,
                    confidence=finding.confidence,
                )
            )
        events_rdap = data.get("events") or []
        if isinstance(events_rdap, list):
            for item in events_rdap:
                if not isinstance(item, dict):
                    continue
                events.append(
                    TimelineEvent(
                        timestamp=_parse_dt(item.get("date")),
                        label=f"RDAP {item.get('action')}",
                        source="RDAP",
                        entity_id=finding.entity_id,
                        confidence=finding.confidence,
                    )
                )
        if data.get("first_seen"):
            events.append(
                TimelineEvent(
                    timestamp=_parse_dt(str(data.get("first_seen"))),
                    label=f"{finding.module} first_seen",
                    source=finding.module,
                    entity_id=finding.entity_id,
                    confidence=finding.confidence,
                )
            )
    events.sort(key=lambda e: e.timestamp or utcnow())
    return events


def _parse_dt(value: Any):
    if not value:
        return None
    from datetime import datetime

    text = str(value).strip()
    if text.isdigit() and len(text) >= 8:
        try:
            return datetime.strptime(text[:14], "%Y%m%d%H%M%S"[: len(text) - 2 if len(text) > 8 else 8])
        except Exception:
            try:
                return datetime.strptime(text[:8], "%Y%m%d")
            except Exception:
                return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(text[:19], fmt)
            except Exception:
                continue
        return None
