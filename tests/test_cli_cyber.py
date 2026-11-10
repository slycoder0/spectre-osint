from __future__ import annotations

from typer.testing import CliRunner

from spectre_osint.cli import theme as theme_mod
from spectre_osint.cli.commands import app
from spectre_osint.cli.display import configure_display, print_banner, print_result
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
    """Phase 3A: the small banner never shows with NO_COLOR or on a non-terminal stdout."""
    monkeypatch.setattr(theme_mod, "is_tty", lambda _stream: True)
    monkeypatch.delenv("SPECTRE_NO_BANNER", raising=False)
    monkeypatch.delenv("NO_BANNER", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    configure_display()
    print_banner()
    assert capsys.readouterr().out.strip() == "", "no banner by default outside username (B2-06)"
    configure_display(no_banner=False, verbose=True)
    print_banner()
    out = capsys.readouterr().out
    assert "passive-first" in out
    assert "█" not in out, "no big ASCII art"
    configure_display(no_banner=True, verbose=True)
    print_banner()
    assert capsys.readouterr().out.strip() == ""
    monkeypatch.setenv("NO_COLOR", "1")
    configure_display(verbose=True)
    print_banner()
    assert capsys.readouterr().out.strip() == ""


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
    assert "GitHub  https://github.com/alice_osint" in out
    assert "0 not verified" in out
    assert "USERNAME SUMMARY" not in out  # compact skips the legacy panels
    assert "CACHED" not in out
    configure_display(compact=False, verbose=True, no_banner=True)
    print_result(result)
    verbose = capsys.readouterr().out
    assert "USERNAME SUMMARY" in verbose
    assert "GitHub" in verbose
    assert "CACHED" in verbose
    assert "0 not verified" in verbose
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
