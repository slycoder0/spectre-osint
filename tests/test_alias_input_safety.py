"""Tests for safe alias input and explicit alias removal (B2-01B).

The dashboard-side alias chip contract was removed with the legacy web layer in
0.1.0b2. What survives is the operator-facing invariant: multiple aliases reach
the pipeline as *inputs*, never as observed evidence.
"""

from __future__ import annotations

from typer.testing import CliRunner

from spectre_osint.core.entities import InvestigationResult, utcnow
from spectre_osint.core.types import EntityType

runner = CliRunner()


def test_cli_username_forwards_multiple_aliases(settings, monkeypatch) -> None:
    """Verify the CLI accepts repeated --alias and forwards them as case inputs."""
    from spectre_osint.cli import commands as cli_commands

    captured: dict[str, object] = {}

    async def fake_investigate(target, **kwargs):
        captured["target"] = target
        captured["extra"] = kwargs.get("extra")
        return InvestigationResult(
            case_id="c",
            case_name="n",
            target=target,
            target_type=EntityType.USERNAME,
            mode="PASSIVE_OSINT",
            started_at=utcnow(),
            finished_at=utcnow(),
        )

    monkeypatch.setattr(cli_commands, "_investigate", fake_investigate)
    result = runner.invoke(
        cli_commands.app,
        [
            "--no-banner",
            "username",
            "alice_main",
            "--alias",
            "alice_shop",
            "--alias",
            "alice_store",
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured["target"] == "alice_main"
    extra = captured.get("extra") or {}
    inputs = extra.get("inputs") or {}
    assert inputs.get("primary") == "alice_main"
    assert inputs.get("aliases") == ["alice_shop", "alice_store"]
