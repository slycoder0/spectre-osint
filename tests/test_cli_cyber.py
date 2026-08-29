from __future__ import annotations

from typer.testing import CliRunner

from spectre_osint.cli.commands import app
from spectre_osint.cli.display import BANNER_WIDE, configure_display, print_banner, print_result
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.types import Confidence, EntityType, FindingStatus

runner = CliRunner()


def test_help_lists_auth_and_no_banner() -> None:
    from tests.conftest import strip_ansi

    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    clean_help = strip_ansi(help_result.stdout)
    assert "--no-banner" in clean_help
    assert "auth" in clean_help
    assert "cache" in clean_help
    none = runner.invoke(app, ["--no-banner", "version"])
    assert none.exit_code == 0
    assert "0.1.0b1" in none.stdout
    assert "██████" not in none.stdout


def test_banner_respects_no_color(capsys, monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    configure_display(no_banner=False)
    print_banner()
    out = capsys.readouterr().out
    assert "I N T E L L I G E N C E" in out
    assert "passive-first" in out
    configure_display(no_banner=True)
    print_banner()
    skipped = capsys.readouterr().out
    assert skipped.strip() == ""
    assert "I N T E L L I G E N C E" in BANNER_WIDE
    assert BANNER_WIDE.count("█") > 20


def test_compact_username_summary(capsys) -> None:
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id="c",
        case_name="n",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user],
        findings=[
            Finding(
                module="username",
                title="GitHub",
                status=FindingStatus.FOUND,
                summary="GitHub: CONFIRMED",
                data={
                    "platform": "GitHub",
                    "check_status": "CONFIRMED",
                    "profile_url": "https://github.com/alice_osint",
                    "cache_state": "CACHED",
                    "access_mode": "ANONYMOUS_PUBLIC",
                    "checked_at": utcnow().isoformat(),
                },
                confidence=Confidence.CONFIRMED,
            )
        ],
    )
    configure_display(compact=True, no_banner=True)
    print_result(result)
    out = capsys.readouterr().out
    assert "USERNAME SUMMARY" in out
    assert "CACHED" not in out or "GitHub" not in out  # compact skips table
    configure_display(compact=False, verbose=True, no_banner=True)
    print_result(result)
    verbose = capsys.readouterr().out
    assert "GitHub" in verbose
    assert "CACHED" in verbose
    configure_display()


def test_cache_cli(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTRE_DATA_DIR", str(tmp_path / "data"))
    from spectre_osint.core.config import Settings, reload_settings
    from spectre_osint.core.result_cache import ResultCache

    reload_settings()
    settings = Settings(data_dir=tmp_path / "data", reports_dir=tmp_path / "r", logs_dir=tmp_path / "l")
    settings.ensure_dirs()
    cache = ResultCache(settings)
    cache.set("username", "GitHub", "octocat", {"check_status": "CONFIRMED"})
    cache.close()
    monkeypatch.setenv("SPECTRE_DATA_DIR", str(tmp_path / "data"))
    reload_settings()
    status = runner.invoke(app, ["--no-banner", "cache", "status"])
    assert status.exit_code == 0
    assert "GitHub" in status.stdout
    cleared = runner.invoke(app, ["--no-banner", "cache", "clear", "--provider", "GitHub"])
    assert cleared.exit_code == 0
