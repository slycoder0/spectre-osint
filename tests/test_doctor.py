from __future__ import annotations

import json
from pathlib import Path

from pydantic import SecretStr
from typer.testing import CliRunner

from spectre_osint import __version__
from spectre_osint.cli import doctor as doctor_mod
from spectre_osint.cli.commands import app
from spectre_osint.cli.doctor import (
    ACTION_REQUIRED,
    READY,
    READY_OPTIONAL,
    dumps_doctor,
    render_doctor,
    run_doctor,
)
from spectre_osint.core.pipeline import InvestigationRunner

runner = CliRunner()


def test_version_is_alpha() -> None:
    assert __version__ == "0.1.0b1"
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "0.1.0b1"
    named = runner.invoke(app, ["version"])
    assert named.exit_code == 0
    assert named.stdout.strip() == "0.1.0b1"


def test_doctor_ready_without_optionals(settings, monkeypatch) -> None:
    monkeypatch.setattr("spectre_osint.browser.chrome.chrome_available", lambda _s=None: False)
    monkeypatch.setattr("spectre_osint.cli.doctor.run_doctor", lambda: run_doctor(settings))
    report = run_doctor(settings)
    assert report["ready"] is True
    assert report["version"] == "0.1.0b1"
    assert report["status"] in {READY, READY_OPTIONAL}
    searx = next(item for item in report["checks"] if item["label"] == "SearXNG")
    assert searx["state"] == "optional"
    chrome = next(item for item in report["checks"] if item["label"] == "Chrome/Chromium")
    assert chrome["state"] == "optional"
    text = render_doctor(report)
    assert report["status"] != ACTION_REQUIRED
    assert "Overall: ACTION REQUIRED" not in text
    cli = runner.invoke(app, ["doctor"])
    assert cli.exit_code == 0
    assert "SPECTRE DOCTOR" in cli.stdout


def test_doctor_never_prints_secret_values(settings, monkeypatch) -> None:
    secret = "supersecret-test-token-xyz"
    settings.virustotal_api_key = SecretStr(secret)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", secret)
    report = run_doctor(settings)
    blob = dumps_doctor(report) + render_doctor(report) + json.dumps(report)
    assert secret not in blob
    vt = next(item for item in report["checks"] if item["label"] == "VirusTotal")
    assert vt["value"] == "CONFIGURED"
    assert "supersecret" not in blob


def test_doctor_json_is_valid(settings, monkeypatch) -> None:
    monkeypatch.setattr("spectre_osint.cli.doctor.run_doctor", lambda: run_doctor(settings))
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "checks" in payload
    assert payload["version"] == "0.1.0b1"
    assert isinstance(payload["ready"], bool)
    assert isinstance(payload["checks"], list)


def test_doctor_reports_dir_not_writable(settings, tmp_path, monkeypatch) -> None:
    locked = tmp_path / "locked-reports"
    settings.reports_dir = locked
    orig_writable = doctor_mod._writable_dir
    monkeypatch.setattr(
        doctor_mod,
        "_writable_dir",
        lambda p: (False, "PermissionError") if p == locked else orig_writable(p),
    )
    report = run_doctor(settings)
    row = next(item for item in report["checks"] if item["label"] == "Reports directory")
    assert row["state"] == "action"
    assert report["status"] == ACTION_REQUIRED
    assert report["ready"] is False


def test_doctor_database_dir_not_writable(settings, tmp_path, monkeypatch) -> None:
    locked = tmp_path / "locked-data"
    settings.data_dir = locked
    settings.database_url = f"sqlite:///{locked / 't.db'}"
    orig_writable = doctor_mod._writable_dir
    monkeypatch.setattr(
        doctor_mod,
        "_writable_dir",
        lambda p: (False, "PermissionError") if p == locked else orig_writable(p),
    )
    report = run_doctor(settings)
    row = next(item for item in report["checks"] if item["label"] == "Database writable")
    assert row["state"] == "action"
    assert report["status"] == ACTION_REQUIRED


def test_doctor_action_required_exit_code(settings, tmp_path, monkeypatch) -> None:
    locked = tmp_path / "locked-reports"
    settings.reports_dir = locked
    orig_writable = doctor_mod._writable_dir
    monkeypatch.setattr(
        doctor_mod,
        "_writable_dir",
        lambda p: (False, "PermissionError") if p == locked else orig_writable(p),
    )
    monkeypatch.setattr("spectre_osint.cli.doctor.run_doctor", lambda: run_doctor(settings))
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "ACTION REQUIRED" in result.stdout


def test_doctor_does_not_start_investigation_or_login(settings, monkeypatch) -> None:
    def boom(*_args, **_kwargs):
        raise AssertionError("doctor must not start this")

    monkeypatch.setattr(InvestigationRunner, "run", boom)
    monkeypatch.setattr("spectre_osint.browser.auth.AuthService.login", boom)
    monkeypatch.setattr("spectre_osint.browser.chrome.ensure_chrome_profile", boom)
    monkeypatch.setattr("spectre_osint.browser.chrome.spawn_via_windows_helper", boom)
    monkeypatch.setattr("spectre_osint.browser.chrome.wait_cdp_http", boom)
    report = run_doctor(settings)
    assert report["version"] == "0.1.0b1"
    assert report["ready"] in {True, False}


def test_doctor_session_status_has_no_cookies(settings) -> None:
    auth = Path(settings.resolved_auth_dir)
    insta = auth / "instagram"
    insta.mkdir(parents=True, exist_ok=True)
    (insta / "profile.json").write_text(
        json.dumps(
            {
                "platform": "instagram",
                "profile_name": "osint-research",
                "status": "ACTIVE",
                "cookie": "SHOULD_NEVER_APPEAR",
                "sessionid": "SHOULD_NEVER_APPEAR",
            }
        ),
        encoding="utf-8",
    )
    (insta / "storage_state.json").write_text(
        '{"cookies":[{"name":"sessionid","value":"live-cookie-value"}]}',
        encoding="utf-8",
    )
    report = run_doctor(settings)
    blob = json.dumps(report).lower() + render_doctor(report).lower()
    assert "should_never_appear" not in blob
    assert "live-cookie-value" not in blob
    assert "cookie" not in blob
    assert "sessionid" not in blob
    assert "storage_state" not in blob
    assert "authorization" not in blob
    instagram = next(item for item in report["checks"] if item["label"] == "Instagram")
    assert instagram["value"] == "ACTIVE"


def test_doctor_output_has_no_home_slycoder(settings) -> None:
    text = render_doctor(run_doctor(settings))
    assert "/home/testuser" not in text
    assert "C:\\Users\\" not in text


def test_source_tree_has_no_hardcoded_project_home() -> None:
    root = Path("spectre_osint")
    hits: list[str] = []
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "/home/testuser" in text or "/home/testuser/projects/spectre-osint" in text:
            hits.append(str(path))
    assert hits == []


def test_doctor_does_not_crash_without_database_file(settings, tmp_path) -> None:
    missing = tmp_path / "no-such-data"
    settings.data_dir = missing
    settings.database_url = f"sqlite:///{missing / 'spectre.db'}"
    report = run_doctor(settings)
    assert "checks" in report
    row = next(item for item in report["checks"] if item["label"] == "Database writable")
    assert row["state"] in {"ok", "action"}
