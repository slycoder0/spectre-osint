"""Universal entity model used by every module and provider."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType
from spectre_osint.core.validators import entity_id, normalize_for_type


def utcnow() -> datetime:
    return datetime.now(UTC)


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    source: str
    url: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    raw_reference: str | None = None
    provider: str
    confidence: Confidence
    entity_id: str | None = None
    finding_id: str | None = None
    notes: str | None = None


class Entity(BaseModel):
    id: str
    type: EntityType
    value: str
    normalized_value: str
    source: str
    confidence: Confidence
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)

    @classmethod
    def create(
        cls,
        entity_type: EntityType,
        value: str,
        source: str,
        confidence: Confidence,
        *,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        evidence: list[Evidence] | None = None,
    ) -> Entity:
        normalized = normalize_for_type(entity_type, value)
        return cls(
            id=entity_id(entity_type, normalized),
            type=entity_type,
            value=value.strip(),
            normalized_value=normalized,
            source=source,
            confidence=confidence,
            tags=tags or [],
            metadata=metadata or {},
            evidence=evidence or [],
        )


class Relationship(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    from_entity_id: str
    to_entity_id: str
    relation: RelationType
    source: str
    confidence: Confidence
    timestamp: datetime = Field(default_factory=utcnow)
    evidence_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    module: str
    title: str
    status: FindingStatus
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    confidence: Confidence | None = None
    entity_id: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    evidence: list[Evidence] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime | None = None
    label: str
    source: str
    entity_id: str | None = None
    confidence: Confidence | None = None
    evidence_id: str | None = None


class PivotSuggestion(BaseModel):
    action: str
    target: str
    entity_type: EntityType
    reason: str
    confidence: Confidence
    source: str


class ScoreBreakdown(BaseModel):
    confidence_score: int
    risk_score: int
    reputation_score: int
    confidence_explain: list[str] = Field(default_factory=list)
    risk_explain: list[str] = Field(default_factory=list)
    reputation_explain: list[str] = Field(default_factory=list)
    risk_level: str = "LOW"
    confidence_breakdown: dict[str, int] = Field(default_factory=dict)
    risk_breakdown: dict[str, int] = Field(default_factory=dict)
    reputation_breakdown: dict[str, int] = Field(default_factory=dict)


class InvestigationResult(BaseModel):
    case_id: str
    case_name: str
    target: str
    target_type: EntityType
    mode: str
    started_at: datetime
    finished_at: datetime | None = None
    entities: list[Entity] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    pivots: list[PivotSuggestion] = Field(default_factory=list)
    scores: ScoreBreakdown | None = None
    providers_queried: list[str] = Field(default_factory=list)
    report_path: str | None = None
    run_id: str | None = None
    notes: list[str] = Field(default_factory=list)
    identity_correlation: dict[str, Any] | None = None
    inputs: dict[str, Any] | None = None


class MentionRecord(BaseModel):
    """Public mention. Not a social profile and not civil identification."""

    query: str
    source: str
    title: str = ""
    url: str | None = None
    snippet: str = ""
    observed_term: str = ""
    timestamp: datetime | None = None
    source_type: str = "public_index"
    confidence: Confidence = Confidence.LOW
    evidence: list[str] = Field(default_factory=list)
    matched_value: str = ""
    matched_field: str = ""
    match_type: str = ""
    published_at: str | None = None
    provider: str = ""
    query_input: str = ""
    input_type: str = ""
    canonical_url: str | None = None
    matched_text: str = ""
    observed_at: datetime | None = None
    reason: str = ""
    relevance: str = ""
    relevance_reason: str = ""
    sources: list[str] = Field(default_factory=list)
