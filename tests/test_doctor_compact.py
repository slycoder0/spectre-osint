"""Compact `spectre doctor` (B2-06): ~8 lines by default, `--all` for the full list.

Configured / OK items are summarized, unconfigured optionals collapse into one line,
anything needing attention or action is always listed with its hint. The JSON contract
(`--json`) is unchanged and language-neutral.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from spectre_osint import __version__
from spectre_osint.cli import doctor as doctor_mod
from spectre_osint.cli.commands import app
from spectre_osint.cli.doctor import (
    ACTION,
    ACTION_REQUIRED,
    OK,
    OPTIONAL,
    READY_OPTIONAL,
    dumps_doctor,
    render_doctor,
    run_doctor,
)
from spectre_osint.core.i18n import has_message, set_language

runner = CliRunner()


def _c(group: str, label: str, value: str, state: str, hint: str = "") -> dict[str, str]:
    return {"group": group, "label": label, "value": value, "state": state, "hint": hint}


def _report(extra: list[dict[str, str]] | None = None, status: str = READY_OPTIONAL) -> dict[str, Any]:
    checks = [
        _c("core", "Python", "3.13.1", OK),
        _c("core", "SPECTRE", __version__, OK),
        _c("core", "Package import", "OK", OK),
        _c("core", "Database", "SQLite", OK),
        _c("core", "Database writable", "OK", OK),
        _c("core", "Reports directory", "OK", OK),
        _c("browser", "Chrome/Chromium", "detected", OK),
        _c("browser", "Chrome CDP", "inactive", OPTIONAL, "Doctor does not launch Chrome."),
        _c("search", "SearXNG", "missing", OPTIONAL, "Set SEARXNG_URL=http://127.0.0.1:<port> for local search."),
        _c("search", "Google CSE", "missing", OPTIONAL),
        _c("auth", "Instagram", "ACTIVE", OK),
        _c("auth", "TikTok", "NOT_CONFIGURED", OPTIONAL),
        _c("auth", "X", "NOT_CONFIGURED", OPTIONAL),
        _c("providers", "VirusTotal", "CONFIGURED", OPTIONAL),
        _c("providers", "Shodan", "NOT CONFIGURED", OPTIONAL),
        _c("providers", "GitHub token", "NOT CONFIGURED", OPTIONAL),
        _c("security", "Secrets redaction", "OK", OK),
        _c("security", "SSRF policy", "enabled", OK),
    ]
    checks.extend(extra or [])
    return {"ready": status != ACTION_REQUIRED, "status": status, "version": __version__, "checks": checks}


EN_COMPACT = f"""\
SPECTRE DOCTOR {__version__}
Core: OK (Python 3.13.1, SQLite database)
Security: OK (SSRF policy enabled, secrets redacted)
Configured: Chrome/Chromium, Instagram session, VirusTotal
7 optional items not configured (browser, search, sessions, API keys) — `spectre doctor --all` lists them
Overall: READY WITH OPTIONAL FEATURES MISSING"""

PT_COMPACT = f"""\
SPECTRE DOCTOR {__version__}
Núcleo: OK (Python 3.13.1, banco SQLite)
Segurança: OK (política SSRF ativa, segredos ocultados)
Configurado: Chrome/Chromium, sessão Instagram, VirusTotal
7 itens opcionais não configurados (navegador, busca, sessões, chaves de API) — `spectre doctor --all` lista todos
Resultado geral: PRONTO, COM RECURSOS OPCIONAIS AUSENTES"""


def test_compact_snapshot_en() -> None:
    set_language("en")
    assert render_doctor(_report()) == EN_COMPACT


def test_compact_snapshot_pt_br() -> None:
    set_language("pt-BR")
    assert render_doctor(_report()) == PT_COMPACT


def test_action_items_are_listed_with_their_hint_and_core_is_not_claimed_ok() -> None:
    set_language("en")
    report = _report(status=ACTION_REQUIRED)
    report["checks"][5] = _c("core", "Reports directory", "PermissionError", ACTION, "SPECTRE_REPORTS_DIR must be writable.")
    text = render_doctor(report)
    assert "[ACTION] Reports directory: PermissionError — SPECTRE_REPORTS_DIR must be writable." in text
    assert "Core: OK" not in text
    assert text.splitlines()[-1] == "Overall: ACTION REQUIRED"


def test_degraded_optionals_are_listed_individually() -> None:
    set_language("pt-BR")
    report = _report()
    report["checks"][8] = _c(
        "search", "SearXNG", "configured (offline)", OPTIONAL, "URL is set; instance did not respond. Optional."
    )
    report["checks"][11] = _c("auth", "TikTok", "EXPIRED", OPTIONAL)
    text = render_doctor(report)
    assert (
        "[OPCIONAL] SearXNG: configurado (fora do ar) — A URL está definida, mas a instância não respondeu. Opcional."
        in text
    )
    assert "[OPCIONAL] sessão TikTok: EXPIRED" in text
    assert "5 itens opcionais não configurados" in text


def test_disabled_ssrf_is_an_action_and_security_is_not_claimed_ok() -> None:
    set_language("en")
    report = _report(status=ACTION_REQUIRED)
    report["checks"][-1] = _c("security", "SSRF policy", "disabled", ACTION)
    text = render_doctor(report)
    assert "[ACTION] SSRF policy: disabled" in text
    assert "Security: OK" not in text


def test_all_lists_every_check_translated() -> None:
    set_language("pt-BR")
    text = render_doctor(_report(), show_all=True)
    for label in ("Python", "Banco de dados gravável", "Pasta de relatórios", "Chrome CDP", "Google CSE", "TikTok", "Shodan", "Token do GitHub", "Política SSRF"):
        assert label in text
    assert "Provedores de API" in text
    assert "NÃO CONFIGURADO" in text
    assert "OPCIONAL" in text
    assert "O doctor não abre o Chrome." in text
    assert text.splitlines()[-1] == "Resultado geral: PRONTO, COM RECURSOS OPCIONAIS AUSENTES"


def test_real_report_is_compact(settings, monkeypatch: pytest.MonkeyPatch) -> None:
    set_language("en")
    monkeypatch.setattr("spectre_osint.browser.chrome.chrome_available", lambda _s=None: False)
    report = run_doctor(settings)
    compact = render_doctor(report).splitlines()
    full = render_doctor(report, show_all=True).splitlines()
    assert len(compact) <= 8, compact
    assert len(full) > 2 * len(compact)
    assert sum("not configured" in line for line in compact) == 1
    for provider in ("Shodan", "AbuseIPDB", "GreyNoise", "AlienVault OTX"):
        assert provider not in "\n".join(compact)
        assert provider in "\n".join(full)


def test_json_contract_is_unchanged_and_language_neutral(settings) -> None:
    set_language("pt-BR")
    payload = json.loads(dumps_doctor(run_doctor(settings)))
    assert set(payload) == {"ready", "status", "version", "checks"}
    assert payload["status"] in {"READY", "READY WITH OPTIONAL FEATURES MISSING", "ACTION REQUIRED"}
    for check in payload["checks"]:
        assert set(check) == {"group", "label", "value", "state", "hint"}


def test_cli_doctor_default_and_all(settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("spectre_osint.cli.doctor.run_doctor", lambda: run_doctor(settings))
    default = runner.invoke(app, ["doctor"])
    assert default.exit_code == 0
    assert "AbuseIPDB" not in default.stdout
    assert "Overall:" in default.stdout
    full = runner.invoke(app, ["doctor", "--all"])
    assert full.exit_code == 0
    assert "AbuseIPDB" in full.stdout
    pt = runner.invoke(app, ["--lang", "pt-BR", "doctor"])
    assert "Resultado geral:" in pt.stdout


# --- every string the doctor can print has a translation -------------------------------------

_PROPER_LABELS = {
    "Python",
    "SPECTRE",
    "Chrome/Chromium",
    "Chrome CDP",
    "SearXNG",
    "Google CSE",
    "VirusTotal",
    "Shodan",
    "Censys",
    "URLScan",
    "AbuseIPDB",
    "HIBP",
    "IPinfo",
    "GreyNoise",
    "AlienVault OTX",
}
_RAW_VALUES = {"OK", "SQLite", "PostgreSQL", "NOT_CONFIGURED", "ACTIVE", "UNKNOWN"}


def _string_constants(node: ast.AST | None) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.IfExp):
        return _string_constants(node.body) + _string_constants(node.orelse)
    return []


def _doctor_literals() -> tuple[set[str], set[str], set[str]]:
    tree = ast.parse(Path(doctor_mod.__file__).read_text(encoding="utf-8"))
    labels: set[str] = set()
    values: set[str] = set()
    hints: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_check":
            if len(node.args) > 1:
                labels.update(_string_constants(node.args[1]))
            if len(node.args) > 2:
                values.update(_string_constants(node.args[2]))
            for keyword in node.keywords:
                if keyword.arg == "hint":
                    hints.update(_string_constants(keyword.value))
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") in {"status", "cdp"}:
            values.update(_string_constants(node.value))
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "hint":
            hints.update(_string_constants(node.value))
    labels.update(label for _, label in doctor_mod._SECRET_FIELDS)
    return labels, values, hints


def test_every_doctor_label_value_and_hint_is_translatable() -> None:
    labels, values, hints = _doctor_literals()
    assert hints, "AST scan found no hints; the test is not looking at the right calls"
    untranslated_labels = sorted(
        label for label in labels if label not in _PROPER_LABELS and label not in doctor_mod._LABEL_KEYS
    )
    untranslated_values = sorted(
        value for value in values if value not in _RAW_VALUES and value not in doctor_mod._VALUE_KEYS
    )
    untranslated_hints = sorted(hint for hint in hints if hint and hint not in doctor_mod._HINT_KEYS)
    assert (untranslated_labels, untranslated_values, untranslated_hints) == ([], [], [])
    for table in (doctor_mod._LABEL_KEYS, doctor_mod._VALUE_KEYS, doctor_mod._HINT_KEYS):
        for english, key in table.items():
            assert has_message(key), key
            set_language("en")
            from spectre_osint.core.i18n import t

            assert t(key) == english, key
