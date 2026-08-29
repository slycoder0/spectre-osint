"""Compatibility re-export. Correlation lives in spectre_osint.correlation."""

from spectre_osint.correlation.graph import build_graph
from spectre_osint.correlation.pivots import suggest_pivots

__all__ = ["build_graph", "suggest_pivots"]
