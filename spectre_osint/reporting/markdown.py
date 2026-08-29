from __future__ import annotations

from pathlib import Path

from spectre_osint.core.entities import InvestigationResult
from spectre_osint.core.paths import report_path


def write_markdown_report(result: InvestigationResult, reports_dir: Path) -> Path:
    path = report_path(reports_dir, result.case_name, result.target, ".md")
    scores = result.scores
    lines = [
        f"# SPECTRE OSINT — {result.target}",
        "",
        f"- Case: `{result.case_name}`",
        f"- Type: `{result.target_type}`",
        f"- Mode: `{result.mode}`",
        f"- Started: {result.started_at}",
        f"- Finished: {result.finished_at}",
        "",
        "## Scores",
        "",
    ]
    if scores:
        lines += [
            f"- Confidence: **{scores.confidence_score}**",
            f"- Risk: **{scores.risk_score}** ({scores.risk_level})",
            f"- Reputation: **{scores.reputation_score}**",
            "",
            "### Confidence rationale",
            *[f"- {x}" for x in scores.confidence_explain],
            "",
            "### Risk rationale",
            *[f"- {x}" for x in scores.risk_explain],
            "",
        ]
    lines += ["## Entities", ""]
    for entity in result.entities:
        lines.append(
            f"- `{entity.type}` `{entity.normalized_value}` confidence={entity.confidence} source={entity.source}"
        )
    lines += ["", "## Findings", ""]
    for finding in result.findings:
        lines.append(f"### {finding.title}")
        lines.append(f"- Status: `{finding.status}` module=`{finding.module}`")
        lines.append(f"- {finding.summary}")
        lines.append("")
    lines += ["## Evidence", ""]
    for ev in result.evidence:
        lines.append(f"- {ev.provider} | {ev.source} | {ev.url or ''} | {ev.confidence}")
    lines += ["", "## Pivots", ""]
    for pivot in result.pivots:
        lines.append(f"- {pivot.action}: `{pivot.target}` — {pivot.reason} ({pivot.confidence})")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
