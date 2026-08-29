from __future__ import annotations

from typer.testing import CliRunner

from spectre_osint.cli.commands import app

runner = CliRunner()


def test_help_and_version() -> None:
    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    assert "investigate" in help_result.stdout
    ver = runner.invoke(app, ["version"])
    assert ver.exit_code == 0
    assert "0.1.0b1" in ver.stdout


def test_username_cli_lists_platform(capsys) -> None:
    from spectre_osint.cli.display import print_result
    from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
    from spectre_osint.core.types import Confidence, EntityType, FindingStatus

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
                title="Instagram",
                status=FindingStatus.LOGIN_REQUIRED,
                summary="Instagram: LOGIN_REQUIRED https://instagram.com/alice_osint",
                data={
                    "platform": "Instagram",
                    "username": "alice_osint",
                    "check_status": "LOGIN_REQUIRED",
                    "profile_url": "https://instagram.com/alice_osint",
                    "access_mode": "ANONYMOUS_PUBLIC",
                    "cache_state": "LIVE",
                },
            )
        ],
    )
    print_result(result)
    out = capsys.readouterr().out
    assert "Platform" in out
    assert "Instagram" in out
    assert "LOGIN_REQUIRED" in out


def test_providers_not_probed() -> None:
    result = runner.invoke(app, ["providers"])
    assert result.exit_code == 0
    assert "NOT PROBED" in result.stdout
    assert "crtsh" in result.stdout
