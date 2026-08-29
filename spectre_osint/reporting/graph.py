from __future__ import annotations

from pathlib import Path

from spectre_osint.core.entities import InvestigationResult
from spectre_osint.core.paths import report_path
from spectre_osint.correlation.graph import build_graph, export_graphml, to_cytoscape


def write_graph_exports(result: InvestigationResult, reports_dir: Path) -> Path:
    graph = build_graph(result)
    path = report_path(reports_dir, result.case_name, result.target, ".graphml")
    return export_graphml(graph, path)


def cytoscape_payload(result: InvestigationResult) -> dict:
    return to_cytoscape(build_graph(result))
