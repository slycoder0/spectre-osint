"""`spectre username` end to end through the CLI (B2-06), with the investigation faked.

Compact output on stdout by default; nothing on stderr unless asked (no logs, and no
progress bar because the runner's stderr is not a TTY); --lang / SPECTRE_LANG select the
language; --verbose adds detail and scores; reports stay complete.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from spectre_osint.cli import commands
from spectre_osint.cli.commands import app
from spectre_osint.core.entities import InvestigationResult, ScoreBreakdown
from spectre_osint.core.logger import LOG_FILENAME, get_logger
from spectre_osint.reporting.html import write_html_report
from spectre_osint.reporting.json import write_json_report
from spectre_osint.reporting.markdown import write_markdown_report
from spectre_osint.services.investigations import InvestigationRequest
from tests.conftest import strip_ansi
from tests.test_username_presentation import EN_SNAPSHOT, PT_BR_SNAPSHOT, alice_result

runner = CliRunner()


def _scored(result: InvestigationResult) -> InvestigationResult:
    result.scores = ScoreBreakdown(
        confidence_score=61,
        risk_score=12,
        risk_level="LOW",
        reputation_score=0,
        confidence_explain=["synthetic confidence explanation"],
        risk_explain=["synthetic risk explanation"],
    )
    return result


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[InvestigationRequest]:
    monkeypatch.setenv("SPECTRE_LOGS_DIR", str(tmp_path / "logs"))
    from spectre_osint.core.config import reload_settings

    reload_settings()
    seen: list[InvestigationRequest] = []

    async def fake(request: InvestigationRequest, *, progress: Any = None, **_kwargs: Any) -> InvestigationResult:
        seen.append(request)
        if progress is not None:
            progress({"phase": "catalog", "state": "running", "current": 4, "total": 8})
            progress({"phase": "catalog", "state": "degraded", "provider": "x", "message": "x unavailable; continuing"})
        get_logger("spectre.http").warning("provider=demo host=example.test status=429 synthetic-log-line")
        return _scored(alice_result())

    monkeypatch.setattr(commands, "run_investigation", fake)
    return seen


def test_default_output_is_the_compact_english_view(fake_run: list[InvestigationRequest]) -> None:
    result = runner.invoke(app, ["username", "alice_osint"])
    assert result.exit_code == 0, result.output
    assert strip_ansi(result.stdout) == EN_SNAPSHOT
    assert fake_run[0].target == "alice_osint"


def test_lang_flag_selects_brazilian_portuguese(fake_run: list[InvestigationRequest]) -> None:
    result = runner.invoke(app, ["--lang", "pt-BR", "username", "alice_osint"])
    assert result.exit_code == 0, result.output
    assert strip_ansi(result.stdout) == PT_BR_SNAPSHOT


def test_spectre_lang_env_selects_the_language(
    fake_run: list[InvestigationRequest], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SPECTRE_LANG", "pt_BR")
    result = runner.invoke(app, ["username", "alice_osint"])
    assert strip_ansi(result.stdout) == PT_BR_SNAPSHOT


def test_flag_beats_environment(fake_run: list[InvestigationRequest], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPECTRE_LANG", "pt-BR")
    result = runner.invoke(app, ["--lang", "en", "username", "alice_osint"])
    assert strip_ansi(result.stdout) == EN_SNAPSHOT


def test_unsupported_lang_flag_is_a_usage_error(fake_run: list[InvestigationRequest]) -> None:
    result = runner.invoke(app, ["--lang", "klingon", "username", "alice_osint"])
    assert result.exit_code == 2
    assert "klingon" in strip_ansi(result.output)
    assert fake_run == []


def test_stderr_is_silent_by_default_and_logs_reach_the_file(
    fake_run: list[InvestigationRequest], tmp_path: Path
) -> None:
    result = runner.invoke(app, ["username", "alice_osint"])
    assert result.exit_code == 0
    assert result.stderr == ""
    assert "synthetic-log-line" not in result.stdout
    assert "unavailable; continuing" not in result.stdout
    log = (tmp_path / "logs" / LOG_FILENAME).read_text(encoding="utf-8")
    assert "synthetic-log-line" in log


def test_debug_flag_prints_logs_on_stderr_only(fake_run: list[InvestigationRequest]) -> None:
    result = runner.invoke(app, ["--debug", "username", "alice_osint"])
    assert result.exit_code == 0
    assert "synthetic-log-line" in result.stderr
    assert "synthetic-log-line" not in result.stdout


def test_default_output_hides_scores_metrics_and_banner(fake_run: list[InvestigationRequest]) -> None:
    out = strip_ansi(runner.invoke(app, ["username", "alice_osint"]).stdout)
    for hidden in ("Scoring", "confidence_score", "risk_score", "Entities discovered", "Providers queried", "█"):
        assert hidden not in out
    for unverified_platform in ("Instagram", "Docker Hub", "Reddit", "Bluesky"):
        assert unverified_platform not in out


def test_verbose_adds_every_platform_and_scores_but_keeps_the_line(fake_run: list[InvestigationRequest]) -> None:
    result = runner.invoke(app, ["--verbose", "username", "alice_osint"])
    assert result.exit_code == 0, result.output
    out = strip_ansi(result.stdout)
    for platform in ("Instagram", "Docker Hub", "Reddit", "Bluesky", "LOGIN_REQUIRED"):
        assert platform in out
    assert "confidence_score = 61" in out
    assert "risk_score       = 12 (LOW)" in out
    assert "4 not verified: 1 blocked, 1 needs login, 1 rate-limited, 1 inconclusive" in out
    assert "(--verbose lists them)" not in out
    assert "Observed name  " not in out
    assert "Alice Example, A. Example" not in out
    assert "GitHub: Alice Example" in out
    assert "Hugging Face: A. Example" in out


def test_verbose_progress_and_logs_go_to_stderr(fake_run: list[InvestigationRequest]) -> None:
    result = runner.invoke(app, ["--verbose", "username", "alice_osint"])
    assert "x unavailable; continuing" in result.stderr
    assert "synthetic-log-line" in result.stderr
    assert "x unavailable; continuing" not in result.stdout


def test_compact_flag_is_still_accepted(fake_run: list[InvestigationRequest]) -> None:
    result = runner.invoke(app, ["--compact", "username", "alice_osint"])
    assert result.exit_code == 0
    assert strip_ansi(result.stdout) == EN_SNAPSHOT


def test_help_documents_the_new_global_options() -> None:
    clean = strip_ansi(runner.invoke(app, ["--help"]).stdout)
    for option in ("--lang", "--verbose", "--debug", "--no-banner"):
        assert option in clean


# --- reports stay complete; compaction is terminal-only -------------------------------------


def test_reports_keep_everything_the_compact_terminal_hides(tmp_path: Path, capsys) -> None:
    from spectre_osint.cli.display import print_result

    result = _scored(alice_result())
    before = result.model_dump(mode="json")
    print_result(result)
    terminal = strip_ansi(capsys.readouterr().out)
    assert result.model_dump(mode="json") == before, "rendering must not mutate the result"

    payload = json.loads(write_json_report(result, tmp_path).read_text(encoding="utf-8"))
    html = write_html_report(result, tmp_path).read_text(encoding="utf-8")
    markdown = write_markdown_report(result, tmp_path).read_text(encoding="utf-8")

    hidden_in_terminal = ("Docker Hub", "Instagram", "Reddit", "Bluesky")
    for platform in hidden_in_terminal:
        assert platform not in terminal
        assert platform in html
        assert platform in markdown
    blob = json.dumps(payload)
    for platform in hidden_in_terminal:
        assert platform in blob
    for status in ("NOT_FOUND", "LOGIN_REQUIRED", "BLOCKED", "RATE_LIMITED", "PROVIDER_UNAVAILABLE"):
        assert status in blob
    assert payload["scores"]["confidence_score"] == 61
    assert "61" in html
    assert "Alice Example" in blob and "A. Example" in blob
