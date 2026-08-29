from __future__ import annotations

from pathlib import Path

import orjson

from spectre_osint.core.entities import InvestigationResult
from spectre_osint.core.paths import report_path
from spectre_osint.core.redaction import redact_mapping, strip_auth_material


def write_json_report(result: InvestigationResult, reports_dir: Path) -> Path:
    path = report_path(reports_dir, result.case_name, result.target, ".json")
    payload = strip_auth_material(redact_mapping(result.model_dump(mode="json")))
    path.write_bytes(orjson.dumps(payload, option=orjson.OPT_INDENT_2))
    return path
