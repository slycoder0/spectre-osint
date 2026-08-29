"""Confidence combination rules. LLM/inference can never become CONFIRMED."""

from __future__ import annotations

from spectre_osint.core.types import Confidence, FindingStatus

_ORDER = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
    Confidence.CONFIRMED: 3,
}


def merge_confidence(*values: Confidence, allow_confirmed: bool = True) -> Confidence:
    if not values:
        return Confidence.LOW
    best = max(values, key=lambda c: _ORDER[c])
    if not allow_confirmed and best == Confidence.CONFIRMED:
        return Confidence.HIGH
    return best


def from_status(status: FindingStatus) -> Confidence | None:
    if status == FindingStatus.INFERENCE:
        return Confidence.LOW
    if status == FindingStatus.FOUND:
        return Confidence.MEDIUM
    return None
