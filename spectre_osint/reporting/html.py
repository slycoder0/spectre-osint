from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from spectre_osint.core.entities import InvestigationResult
from spectre_osint.core.paths import report_path
from spectre_osint.core.presentation import username_counts, username_rows
from spectre_osint.correlation.graph import build_graph, to_cytoscape

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def write_html_report(result: InvestigationResult, reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    graph = to_cytoscape(build_graph(result))
    html = template.render(
        result=result,
        graph=graph,
        username_rows=username_rows(result),
        username_counts=username_counts(result),
    )
    path = report_path(reports_dir, result.case_name, result.target, ".html")
    path.write_text(html, encoding="utf-8")
    return path
