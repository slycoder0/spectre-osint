"""`spectre search <query>` runs inside `target_scope()` (Phase 3A, STATUS follow-up).

Before, only the call-site rule protected the query: it was never registered in the log
safety net, so a log line that slipped would keep it in clear.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from spectre_osint.cli.commands import app
from spectre_osint.core import redaction
from spectre_osint.core.entities import Finding
from spectre_osint.core.logger import LOG_FILENAME
from spectre_osint.core.types import FindingStatus
from spectre_osint.modules.search import engine as search_engine

runner = CliRunner()
QUERY = "alice_osint"


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("SPECTRE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SPECTRE_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("SPECTRE_LOGS_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("SPECTRE_DATABASE_URL", f"sqlite:///{tmp_path / 't.db'}")
    from spectre_osint.core.config import reload_settings
    from spectre_osint.core.database import reset_engine

    reload_settings()
    reset_engine()
    yield tmp_path
    reset_engine()
    reload_settings()


def test_search_registers_the_query_for_the_duration_of_the_command(isolated, monkeypatch) -> None:
    seen: dict[str, Any] = {}

    async def fake_search(self, query: str) -> Finding:
        seen["scrubbed"] = redaction.scrub_target_values(f"q={query}")
        seen["forms"] = redaction.registered_form_count()
        # A call site that slips: the safety net must still catch it.
        logging.getLogger("spectre.search").warning("slipped query=%s", query)
        return Finding(module="search", title="Search", status=FindingStatus.NOT_FOUND, summary="no results")

    monkeypatch.setattr(search_engine.SearchEngine, "search", fake_search)
    result = runner.invoke(app, ["search", QUERY])
    assert result.exit_code == 0, result.output
    assert seen["forms"] > 0, "query registered inside the scope"
    assert QUERY not in seen["scrubbed"]
    assert redaction.registered_form_count() == 0, "forgotten when the command ends"
    log = (isolated / "logs" / LOG_FILENAME).read_text(encoding="utf-8")
    assert "slipped query=" in log
    assert QUERY not in log
