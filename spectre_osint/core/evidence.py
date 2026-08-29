"""Helpers to attach traceable evidence to every discovery."""

from __future__ import annotations

from typing import Any

from spectre_osint.core.entities import Evidence, utcnow
from spectre_osint.core.redaction import redact_text, safe_json
from spectre_osint.core.types import Confidence


def make_evidence(
    *,
    source: str,
    provider: str,
    confidence: Confidence,
    url: str | None = None,
    raw: Any = None,
    notes: str | None = None,
    entity_id: str | None = None,
    finding_id: str | None = None,
    max_raw: int = 4000,
) -> Evidence:
    raw_reference = None
    if raw is not None:
        if isinstance(raw, str):
            raw_reference = redact_text(raw)[:max_raw]
        else:
            raw_reference = safe_json(raw)[:max_raw]
    return Evidence(
        source=source,
        url=url,
        timestamp=utcnow(),
        raw_reference=raw_reference,
        provider=provider,
        confidence=confidence,
        entity_id=entity_id,
        finding_id=finding_id,
        notes=notes,
    )
