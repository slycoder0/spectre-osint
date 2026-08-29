from __future__ import annotations

import csv
from pathlib import Path

from spectre_osint.core.entities import InvestigationResult
from spectre_osint.core.paths import report_path


def write_csv_report(result: InvestigationResult, reports_dir: Path) -> Path:
    path = report_path(reports_dir, result.case_name, result.target, "-entities.csv")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["type", "value", "confidence", "source", "tags"]
        )
        writer.writeheader()
        for entity in result.entities:
            writer.writerow(
                {
                    "type": entity.type.value,
                    "value": entity.normalized_value,
                    "confidence": entity.confidence.value,
                    "source": entity.source,
                    "tags": ",".join(entity.tags),
                }
            )
    return path
