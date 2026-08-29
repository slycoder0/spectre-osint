"""Factual progress contract.

Progress is strictly factual:
- Known phases (catalog, mentions, search, discovery, correlation, scoring, report)
- Known states (running, completed, degraded)
- Real counts when known (current, total)
- Optional provider and factual message

No artificial percentages are ever calculated for phases with unknown totals.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ProgressPhase(StrEnum):
    CATALOG = "catalog"
    MENTIONS = "mentions"
    SEARCH = "search"
    DISCOVERY = "discovery"
    CORRELATION = "correlation"
    SCORING = "scoring"
    REPORT = "report"
    INITIALIZING = "initializing"
    COLLECTING = "collecting"
    NORMALIZING = "normalizing"


class ProgressState(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    DEGRADED = "degraded"


@dataclass(frozen=True)
class ProgressEvent:
    phase: str
    state: str = ProgressState.RUNNING.value
    current: int | None = None
    total: int | None = None
    provider: str | None = None
    message: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Convert to dictionary with backwards-compatible aliases."""
        data: dict[str, Any] = {
            "phase": str(self.phase),
            "state": str(self.state),
        }
        if self.current is not None:
            data["current"] = self.current
            data["done"] = self.current
        if self.total is not None:
            data["total"] = self.total
        if self.provider is not None:
            data["provider"] = self.provider
            data["source"] = self.provider
        if self.message is not None:
            data["message"] = self.message
        return data

    @classmethod
    def from_payload(cls, payload: dict[str, Any] | ProgressEvent) -> ProgressEvent:
        if isinstance(payload, ProgressEvent):
            return payload
        phase = str(payload.get("phase") or ProgressPhase.COLLECTING.value)
        state = str(payload.get("state") or ProgressState.RUNNING.value)
        current = payload.get("current")
        if current is None:
            current = payload.get("done")
        total = payload.get("total")
        provider = payload.get("provider")
        if provider is None:
            provider = payload.get("source")
        message = payload.get("message")
        return cls(
            phase=phase,
            state=state,
            current=int(current) if current is not None else None,
            total=int(total) if total is not None else None,
            provider=str(provider) if provider is not None else None,
            message=str(message) if message is not None else None,
        )


ProgressCallback = Callable[[dict[str, Any]], None]
