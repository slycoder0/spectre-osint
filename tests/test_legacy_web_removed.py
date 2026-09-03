"""Guards for the 0.1.0b2 removal of the deprecated local web dashboard.

Structural assertions only: the command tree, the import graph, the declared
dependencies and the doctor check set. Nothing here depends on Typer/Click
help prose, so the guards survive CLI framework upgrades.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import tomllib
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

import spectre_osint
from spectre_osint.cli.commands import app
from spectre_osint.cli.doctor import render_doctor, run_doctor
from spectre_osint.core.config import Settings

runner = CliRunner()

REMOVED_COMMANDS = ("web", "dashboard")
WEB_ONLY_IMPORTS = frozenset({"fastapi", "starlette", "uvicorn", "multipart", "python_multipart"})
WEB_ONLY_REQUIREMENTS = ("fastapi", "starlette", "uvicorn", "python-multipart")
PACKAGE_DIR = Path(spectre_osint.__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent


def _command_names() -> set[str]:
    """Resolved Click command names, including Typer's implicit callback names."""
    return set(get_command(app).commands)


def _pyproject() -> dict:
    return tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def test_web_and_dashboard_are_not_registered_commands() -> None:
    names = _command_names()
    assert "doctor" in names, "sanity: the command tree must still be readable"
    for removed in REMOVED_COMMANDS:
        assert removed not in names


@pytest.mark.parametrize("command", REMOVED_COMMANDS)
def test_removed_commands_exit_non_zero(command: str) -> None:
    # Checked first on purpose: invoking a still-registered `web` would start a
    # blocking server instead of failing the guard.
    assert command not in _command_names()
    result = runner.invoke(app, ["--no-banner", command])
    assert result.exit_code != 0


def test_web_package_no_longer_exists() -> None:
    assert not (PACKAGE_DIR / "web").exists()
    assert importlib.util.find_spec("spectre_osint.web") is None
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("spectre_osint.web.app")


def test_no_runtime_module_imports_a_web_framework() -> None:
    offenders: list[str] = []
    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        hits = _imported_roots(path) & WEB_ONLY_IMPORTS
        if hits:
            offenders.append(f"{path.relative_to(PROJECT_ROOT)}: {sorted(hits)}")
    assert offenders == []


def test_no_test_module_imports_a_web_framework() -> None:
    offenders: list[str] = []
    for path in sorted((PROJECT_ROOT / "tests").rglob("*.py")):
        hits = _imported_roots(path) & WEB_ONLY_IMPORTS
        if hits:
            offenders.append(f"{path.relative_to(PROJECT_ROOT)}: {sorted(hits)}")
    assert offenders == []


def test_project_does_not_declare_web_dependencies() -> None:
    names = set()
    for requirement in _pyproject()["project"]["dependencies"]:
        head = requirement.split("[")[0].split(">")[0].split("<")[0].split("=")[0]
        names.add(head.strip().lower())
    for requirement in WEB_ONLY_REQUIREMENTS:
        assert requirement not in names
    assert "jinja2" in names, "sanity: reporting still renders templates with Jinja2"


def test_package_data_has_no_web_entries() -> None:
    package_data = _pyproject()["tool"]["setuptools"]["package-data"]["spectre_osint"]
    assert [entry for entry in package_data if entry.startswith("web/")] == []
    assert "reporting/templates/*" in package_data


def test_settings_have_no_dashboard_bind_fields() -> None:
    assert "web_host" not in Settings.model_fields
    assert "allow_public_bind" not in Settings.model_fields
    assert "allow_private_targets" in Settings.model_fields, "sanity: SSRF settings stay"
    assert "ssrf_enabled" in Settings.model_fields


def test_retired_bind_env_vars_are_inert(monkeypatch) -> None:
    monkeypatch.setenv("SPECTRE_WEB_HOST", "0.0.0.0")
    monkeypatch.setenv("SPECTRE_ALLOW_PUBLIC_BIND", "true")
    settings = Settings()
    assert not hasattr(settings, "web_host")
    assert not hasattr(settings, "allow_public_bind")


def test_doctor_has_no_dashboard_or_bind_diagnostic(settings, monkeypatch) -> None:
    monkeypatch.setattr("spectre_osint.browser.chrome.chrome_available", lambda _s=None: False)
    report = run_doctor(settings)
    assert isinstance(report["checks"], list) and report["checks"]
    labels = {check["label"] for check in report["checks"]}
    assert {"Secrets redaction", "SSRF policy"} <= labels
    assert not any("bind" in label.lower() for label in labels)
    blob = (render_doctor(report) + repr(report)).lower()
    assert "dashboard" not in blob
    assert "bind address" not in blob

    monkeypatch.setattr("spectre_osint.cli.doctor.run_doctor", lambda: run_doctor(settings))
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "SPECTRE DOCTOR" in result.stdout
    assert "dashboard" not in result.stdout.lower()
