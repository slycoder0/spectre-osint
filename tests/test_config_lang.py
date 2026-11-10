"""`spectre config lang <pt_br|en>` persists the language with `save_language()` (Phase 3A)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from spectre_osint.cli import commands
from spectre_osint.cli.commands import app
from tests.conftest import strip_ansi
from tests.test_username_presentation import PT_BR_SNAPSHOT, alice_result

runner = CliRunner()


@pytest.fixture
def config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "cfg" / "config.json"
    monkeypatch.setenv("SPECTRE_CONFIG_FILE", str(path))
    monkeypatch.delenv("SPECTRE_LANG", raising=False)
    return path


@pytest.mark.parametrize("value", ["pt_br", "pt-BR", "PT_BR"])
def test_config_lang_saves_brazilian_portuguese(config_file: Path, value: str) -> None:
    result = runner.invoke(app, ["config", "lang", value])
    assert result.exit_code == 0, result.output
    assert json.loads(config_file.read_text(encoding="utf-8")) == {"language": "pt-BR"}
    out = strip_ansi(result.stdout)
    assert "Idioma salvo: pt-BR" in out, "confirmation is in the new language"
    assert str(config_file) in out


def test_config_lang_en_keeps_other_keys(config_file: Path) -> None:
    config_file.parent.mkdir(parents=True)
    config_file.write_text(json.dumps({"language": "pt-BR", "other": 1}), encoding="utf-8")
    result = runner.invoke(app, ["config", "lang", "en"])
    assert result.exit_code == 0, result.output
    assert json.loads(config_file.read_text(encoding="utf-8")) == {"language": "en", "other": 1}
    assert "Language saved: en" in strip_ansi(result.stdout)


def test_config_lang_rejects_unsupported_values_without_writing(config_file: Path) -> None:
    result = runner.invoke(app, ["config", "lang", "klingon"])
    assert result.exit_code == 2
    assert "klingon" in strip_ansi(result.output)
    assert "pt-BR" in strip_ansi(result.output)
    assert not config_file.exists()


def test_saved_language_is_used_by_the_next_command(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SPECTRE_LOGS_DIR", str(tmp_path / "logs"))
    from spectre_osint.core.config import reload_settings

    reload_settings()

    async def fake(_request, **_kwargs):
        return alice_result()

    monkeypatch.setattr(commands, "run_investigation", fake)
    assert runner.invoke(app, ["config", "lang", "pt_br"]).exit_code == 0
    result = runner.invoke(app, ["username", "alice_osint"])
    assert result.exit_code == 0, result.output
    assert strip_ansi(result.stdout) == PT_BR_SNAPSHOT


def test_config_lang_warns_when_spectre_lang_overrides_it(
    config_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SPECTRE_LANG", "en")
    result = runner.invoke(app, ["config", "lang", "pt_br"])
    assert result.exit_code == 0, result.output
    assert "SPECTRE_LANG" in strip_ansi(result.stdout)


def test_config_lang_unwritable_file_is_a_friendly_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("SPECTRE_CONFIG_FILE", str(blocker / "config.json"))
    result = runner.invoke(app, ["config", "lang", "en"])
    assert result.exit_code == 1
    assert result.stderr.startswith("Error: ")
    assert "SPECTRE_CONFIG_FILE" in result.stderr
    assert "Traceback" not in result.stderr


def test_help_lists_the_config_command() -> None:
    assert "config" in strip_ansi(runner.invoke(app, ["--help"]).stdout)
    assert "lang" in strip_ansi(runner.invoke(app, ["config", "--help"]).stdout)
