"""Investigation case management with per-run persistence and rollback."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import delete, select, update

from spectre_osint.core.database import init_db, session_scope
from spectre_osint.core.entities import (
    Entity,
    Evidence,
    Finding,
    InvestigationResult,
    Relationship,
    utcnow,
)
from spectre_osint.core.models import (
    CaseRow,
    EntityRow,
    EvidenceRow,
    FindingRow,
    InvestigationRunRow,
    RelationshipRow,
    ReportRow,
)
from spectre_osint.core.paths import validate_case_name
from spectre_osint.core.redaction import redact_mapping, redact_text


class CaseManager:
    def __init__(self) -> None:
        init_db()

    def create(self, name: str, description: str = "") -> CaseRow:
        safe = validate_case_name(name)
        with session_scope() as session:
            existing = session.scalar(select(CaseRow).where(CaseRow.name == safe))
            if existing:
                return existing
            session.execute(update(CaseRow).values(active=False))
            row = CaseRow(
                id=uuid4().hex,
                name=safe,
                description=description,
                targets=[],
                notes="",
                active=True,
            )
            session.add(row)
            session.flush()
            session.expunge(row)
            return row

    def create_unique(self, prefix: str) -> CaseRow:
        """Always insert a new case. Never reuse the active case."""
        base = validate_case_name(prefix)
        return self.create(f"{base}-{uuid4().hex[:8]}")

    def select(self, name: str) -> CaseRow | None:
        safe = validate_case_name(name)
        with session_scope() as session:
            row = session.scalar(select(CaseRow).where(CaseRow.name == safe))
            if not row:
                return None
            session.execute(update(CaseRow).values(active=False))
            row.active = True
            row.updated_at = utcnow()
            session.flush()
            session.expunge(row)
            return row

    def list_cases(self) -> list[CaseRow]:
        with session_scope() as session:
            rows = list(session.scalars(select(CaseRow).order_by(CaseRow.updated_at.desc())))
            for row in rows:
                session.expunge(row)
            return rows

    def get_or_create_active(self, fallback_name: str) -> CaseRow:
        with session_scope() as session:
            row = session.scalar(select(CaseRow).where(CaseRow.active.is_(True)))
            if row:
                session.expunge(row)
                return row
        return self.create(fallback_name)

    def start_run(
        self,
        case_id: str,
        target: str,
        target_type: str,
        *,
        depth: int = 0,
        parent_run_id: str | None = None,
    ) -> InvestigationRunRow:
        with session_scope() as session:
            row = InvestigationRunRow(
                id=uuid4().hex,
                case_id=case_id,
                target=target,
                target_type=target_type,
                status="running",
                depth=depth,
                parent_run_id=parent_run_id,
                extra={},
            )
            session.add(row)
            session.flush()
            session.expunge(row)
            return row

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        report_path: str | None = None,
        error: str | None = None,
        extra: dict | None = None,
    ) -> None:
        with session_scope() as session:
            row = session.get(InvestigationRunRow, run_id)
            if row is None:
                return
            row.status = status
            row.finished_at = utcnow()
            row.report_path = report_path
            row.error = redact_text(error) if error else None
            if extra:
                merged = dict(row.extra or {})
                merged.update(extra)
                row.extra = merged

    def persist_result(self, result: InvestigationResult, report_path: str | None = None) -> None:
        run_id = result.run_id
        with session_scope() as session:
            case = session.get(CaseRow, result.case_id)
            if case is None:
                return
            targets = list(case.targets or [])
            extras: list[str] = []
            if isinstance(result.inputs, dict):
                extras.extend(str(x) for x in (result.inputs.get("aliases") or []) if x)
                primary = result.inputs.get("primary")
                if primary:
                    extras.append(str(primary))
            for value in [result.target, *extras]:
                if value and value not in targets:
                    targets.append(value)
            case.targets = targets
            case.updated_at = utcnow()

            for entity in result.entities:
                existing = session.get(EntityRow, f"{result.case_id}:{entity.id}")
                if existing:
                    existing.last_seen = utcnow()
                    existing.confidence = entity.confidence.value
                    continue
                session.add(
                    EntityRow(
                        id=f"{result.case_id}:{entity.id}",
                        case_id=result.case_id,
                        type=entity.type.value,
                        value=entity.value,
                        normalized_value=entity.normalized_value,
                        source=entity.source,
                        confidence=entity.confidence.value,
                        tags=entity.tags,
                        extra=redact_mapping(entity.metadata),
                    )
                )

            for finding in result.findings:
                session.add(
                    FindingRow(
                        id=finding.id,
                        case_id=result.case_id,
                        run_id=run_id,
                        entity_id=finding.entity_id,
                        module=finding.module,
                        title=finding.title,
                        status=finding.status.value,
                        summary=finding.summary,
                        data=redact_mapping(finding.data),
                        confidence=finding.confidence.value if finding.confidence else None,
                    )
                )

            for evidence in result.evidence:
                session.add(
                    EvidenceRow(
                        id=evidence.id,
                        case_id=result.case_id,
                        run_id=run_id,
                        entity_id=evidence.entity_id,
                        finding_id=evidence.finding_id,
                        source=evidence.source,
                        url=redact_text(evidence.url) if evidence.url else None,
                        timestamp=evidence.timestamp,
                        raw_reference=evidence.raw_reference,
                        provider=evidence.provider,
                        confidence=evidence.confidence.value,
                        notes=evidence.notes,
                    )
                )

            for rel in result.relationships:
                session.add(
                    RelationshipRow(
                        id=rel.id,
                        case_id=result.case_id,
                        run_id=run_id,
                        from_entity_id=rel.from_entity_id,
                        to_entity_id=rel.to_entity_id,
                        relation=rel.relation.value,
                        source=rel.source,
                        confidence=rel.confidence.value,
                        timestamp=rel.timestamp,
                        evidence_id=rel.evidence_id,
                        extra=redact_mapping(rel.metadata),
                    )
                )

            if report_path:
                session.add(
                    ReportRow(
                        id=uuid4().hex,
                        case_id=result.case_id,
                        run_id=run_id,
                        path=report_path,
                        format="html",
                    )
                )

    def rollback_run(self, run_id: str) -> bool:
        with session_scope() as session:
            run = session.get(InvestigationRunRow, run_id)
            if run is None:
                return False
            session.execute(delete(FindingRow).where(FindingRow.run_id == run_id))
            session.execute(delete(EvidenceRow).where(EvidenceRow.run_id == run_id))
            session.execute(delete(RelationshipRow).where(RelationshipRow.run_id == run_id))
            session.execute(delete(ReportRow).where(ReportRow.run_id == run_id))
            run.status = "rolled_back"
            run.finished_at = utcnow()
            return True

    def get_run(self, run_id: str) -> InvestigationRunRow | None:
        with session_scope() as session:
            row = session.get(InvestigationRunRow, run_id)
            if row:
                session.expunge(row)
            return row

    def list_runs(self, case_id: str) -> list[InvestigationRunRow]:
        with session_scope() as session:
            rows = list(
                session.scalars(
                    select(InvestigationRunRow)
                    .where(InvestigationRunRow.case_id == case_id)
                    .order_by(InvestigationRunRow.started_at.desc())
                )
            )
            for row in rows:
                session.expunge(row)
            return rows

    def load_result_by_id(self, case_id: str) -> InvestigationResult | None:
        with session_scope() as session:
            case = session.get(CaseRow, case_id)
            if case is None:
                return None
            name = case.name
        return self.load_result(name)

    def load_result(self, case_name: str) -> InvestigationResult | None:
        """Rebuild a result snapshot from the latest completed run's rows."""
        from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType

        with session_scope() as session:
            try:
                safe = validate_case_name(case_name)
            except Exception:
                safe = case_name
            case = session.scalar(select(CaseRow).where(CaseRow.name == safe))
            if case is None:
                case = session.get(CaseRow, case_name)
            if case is None:
                case = session.scalar(select(CaseRow).where(CaseRow.active.is_(True)))
            if case is None:
                return None
            run = session.scalar(
                select(InvestigationRunRow)
                .where(
                    InvestigationRunRow.case_id == case.id,
                    InvestigationRunRow.status == "completed",
                )
                .order_by(InvestigationRunRow.finished_at.desc())
            )
            if run is None:
                return None
            entities = list(session.scalars(select(EntityRow).where(EntityRow.case_id == case.id)))
            findings = list(
                session.scalars(select(FindingRow).where(FindingRow.run_id == run.id))
            )
            evidence = list(
                session.scalars(select(EvidenceRow).where(EvidenceRow.run_id == run.id))
            )
            rels = list(
                session.scalars(select(RelationshipRow).where(RelationshipRow.run_id == run.id))
            )
            referenced: set[str] = set()
            for finding_row in findings:
                if finding_row.entity_id:
                    referenced.add(finding_row.entity_id)
            for evidence_row in evidence:
                if evidence_row.entity_id:
                    referenced.add(evidence_row.entity_id)
            for rel_row in rels:
                referenced.add(rel_row.from_entity_id)
                referenced.add(rel_row.to_entity_id)
            entities = [
                e
                for e in entities
                if e.id.split(":", 1)[-1] in referenced or e.normalized_value == run.target
            ]
            result = InvestigationResult(
                case_id=case.id,
                case_name=case.name,
                target=run.target,
                target_type=EntityType(run.target_type)
                if run.target_type in EntityType._value2member_map_
                else EntityType.DOMAIN,
                mode="PASSIVE_OSINT",
                started_at=run.started_at,
                finished_at=run.finished_at,
                run_id=run.id,
                report_path=run.report_path,
                entities=[
                    Entity(
                        id=e.id.split(":", 1)[-1],
                        type=EntityType(e.type) if e.type in EntityType._value2member_map_ else EntityType.DOMAIN,
                        value=e.value,
                        normalized_value=e.normalized_value,
                        source=e.source,
                        confidence=Confidence(e.confidence)
                        if e.confidence in Confidence._value2member_map_
                        else Confidence.LOW,
                        tags=list(e.tags or []),
                        metadata=dict(e.extra or {}),
                        first_seen=e.first_seen,
                        last_seen=e.last_seen,
                    )
                    for e in entities
                ],
                findings=[
                    Finding(
                        id=f.id,
                        module=f.module,
                        title=f.title,
                        status=FindingStatus(f.status)
                        if f.status in FindingStatus._value2member_map_
                        else FindingStatus.ERROR,
                        summary=f.summary,
                        data=dict(f.data or {}),
                        confidence=Confidence(f.confidence)
                        if f.confidence and f.confidence in Confidence._value2member_map_
                        else None,
                        entity_id=f.entity_id,
                    )
                    for f in findings
                ],
                evidence=[
                    Evidence(
                        id=ev.id,
                        source=ev.source,
                        url=ev.url,
                        timestamp=ev.timestamp,
                        raw_reference=ev.raw_reference,
                        provider=ev.provider,
                        confidence=Confidence(ev.confidence)
                        if ev.confidence in Confidence._value2member_map_
                        else Confidence.LOW,
                        entity_id=ev.entity_id,
                        finding_id=ev.finding_id,
                        notes=ev.notes,
                    )
                    for ev in evidence
                ],
                relationships=[
                    Relationship(
                        id=r.id,
                        from_entity_id=r.from_entity_id,
                        to_entity_id=r.to_entity_id,
                        relation=RelationType(r.relation)
                        if r.relation in RelationType._value2member_map_
                        else RelationType.REFERENCES,
                        source=r.source,
                        confidence=Confidence(r.confidence)
                        if r.confidence in Confidence._value2member_map_
                        else Confidence.LOW,
                        timestamp=r.timestamp,
                        evidence_id=r.evidence_id,
                        metadata=dict(r.extra or {}),
                    )
                    for r in rels
                ],
            )
            from spectre_osint.core.scoring import score_investigation

            extra = run.extra or {}
            result.providers_queried = list(extra.get("providers_queried") or [])
            if isinstance(extra.get("inputs"), dict):
                result.inputs = extra.get("inputs")
            from spectre_osint.core.entities import PivotSuggestion

            pivots_raw = extra.get("pivots") or []
            if isinstance(pivots_raw, list):
                loaded = []
                for item in pivots_raw:
                    if isinstance(item, dict):
                        try:
                            loaded.append(PivotSuggestion(**item))
                        except Exception:
                            continue
                result.pivots = loaded
            result.scores = score_investigation(result)
            return result
