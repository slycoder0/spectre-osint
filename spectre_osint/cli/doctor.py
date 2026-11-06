"""Installation diagnostics. Never investigates, never prints secrets."""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

from spectre_osint import __version__
from spectre_osint.core.config import Settings
from spectre_osint.core.i18n import has_message, t, tn
from spectre_osint.core.logger import legacy_log_files
from spectre_osint.modules.search.providers import is_loopback_searxng, searxng_origin

OK = "ok"
OPTIONAL = "optional"
ACTION = "action"
# Shown, never counted: it does not change the overall status.
INFO = "info"

READY = "READY"
READY_OPTIONAL = "READY WITH OPTIONAL FEATURES MISSING"
ACTION_REQUIRED = "ACTION REQUIRED"

_SECRET_FIELDS = (
    ("virustotal_api_key", "VirusTotal"),
    ("shodan_api_key", "Shodan"),
    ("censys_api_id", "Censys"),
    ("censys_api_secret", "Censys secret"),
    ("urlscan_api_key", "URLScan"),
    ("abuseipdb_api_key", "AbuseIPDB"),
    ("hibp_api_key", "HIBP"),
    ("ipinfo_token", "IPinfo"),
    ("greynoise_api_key", "GreyNoise"),
    ("github_token", "GitHub token"),
    ("otx_api_key", "AlienVault OTX"),
    ("google_api_key", "Google CSE"),
)

_SECRET_ENV = (
    "VIRUSTOTAL_API_KEY",
    "SHODAN_API_KEY",
    "CENSYS_API_SECRET",
    "CENSYS_API_ID",
    "GITHUB_TOKEN",
    "GOOGLE_API_KEY",
    "HIBP_API_KEY",
    "ABUSEIPDB_API_KEY",
    "URLSCAN_API_KEY",
    "IPINFO_TOKEN",
    "GREYNOISE_API_KEY",
    "OTX_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
)

def _check(group: str, label: str, value: str, state: str, *, hint: str = "") -> dict[str, str]:
    return {"group": group, "label": label, "value": value, "state": state, "hint": hint}


def _scrub_secrets(text: str) -> str:
    """Replace live env secret values if they leaked into diagnostic text."""
    out = text
    for name in _SECRET_ENV:
        raw = os.environ.get(name) or ""
        if len(raw) >= 8 and raw in out:
            out = out.replace(raw, "CONFIGURED")
    return out


def _load_settings(settings: Settings | None) -> Settings | None:
    if settings is not None:
        return settings
    try:
        return Settings()
    except Exception:  # noqa: BLE001
        return None


def _writable_dir(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".spectre-doctor-write"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True, "OK"
    except OSError as exc:
        return False, str(exc.__class__.__name__)


def _database(settings: Settings) -> list[dict[str, str]]:
    url = settings.db_url
    backend = "PostgreSQL" if url.startswith("postgresql") else "SQLite"
    checks = [_check("core", "Database", backend, OK)]
    try:
        if ":memory:" in url:
            checks.append(_check("core", "Database writable", "memory", OK))
        elif url.startswith("sqlite"):
            db_path = Path(url.replace("sqlite:///", "", 1))
            parent = db_path.parent if db_path.name else Path(".")
            ok, detail = _writable_dir(parent)
            checks.append(
                _check(
                    "core",
                    "Database writable",
                    "OK" if ok else detail,
                    OK if ok else ACTION,
                    hint="" if ok else "SPECTRE_DATA_DIR must be writable.",
                )
            )
        else:
            checks.append(_check("core", "Database writable", "not probed", OPTIONAL))
    except Exception as exc:  # noqa: BLE001
        checks.append(
            _check(
                "core",
                "Database writable",
                type(exc).__name__,
                ACTION,
                hint="SPECTRE_DATA_DIR / SPECTRE_DATABASE_URL must be writable.",
            )
        )
    return checks


def _chrome(settings: Settings) -> list[dict[str, str]]:
    from spectre_osint.browser.chrome import chrome_available

    try:
        present = chrome_available(settings)
    except Exception:  # noqa: BLE001
        present = False
    checks = [
        _check(
            "browser",
            "Chrome/Chromium",
            "detected" if present else "missing",
            OK if present else OPTIONAL,
            hint="" if present else "Optional. Needed for authenticated-public sessions.",
        )
    ]
    cdp = "inactive"
    try:
        with socket.create_connection(("127.0.0.1", 9222), timeout=0.2):
            cdp = "listening"
    except OSError:
        cdp = "inactive"
    checks.append(
        _check(
            "browser",
            "Chrome CDP",
            cdp,
            OPTIONAL if cdp == "inactive" else OK,
            hint="Doctor does not launch Chrome.",
        )
    )
    return checks


def _searxng(settings: Settings) -> list[dict[str, str]]:
    origin = searxng_origin(settings)
    if not origin:
        return [
            _check(
                "search",
                "SearXNG",
                "missing",
                OPTIONAL,
                hint="Set SEARXNG_URL=http://127.0.0.1:<port> for local search.",
            )
        ]
    if not is_loopback_searxng(origin):
        return [
            _check(
                "search",
                "SearXNG",
                "invalid",
                ACTION,
                hint="SEARXNG_URL must be loopback http(s).",
            )
        ]
    status = "configured"
    state = OK
    hint = ""
    try:
        with urlopen(origin + "/", timeout=1.5) as response:  # noqa: S310
            if int(getattr(response, "status", 200) or 200) >= 500:
                status = "configured (error)"
                hint = "Instance responded with a server error. Optional."
                state = OPTIONAL
    except (URLError, OSError, TimeoutError, ValueError):
        status = "configured (offline)"
        hint = "URL is set; instance did not respond. Optional."
        state = OPTIONAL
    return [_check("search", "SearXNG", status, state, hint=hint)]


def _sessions(settings: Settings) -> list[dict[str, str]]:
    """Read session metadata only. Never opens storage_state or prints cookies."""
    from spectre_osint.browser.models import AUTH_PLATFORMS
    from spectre_osint.core.types import SessionStatus

    allowed = {item.value for item in SessionStatus}
    auth_dir = Path(settings.resolved_auth_dir)
    checks: list[dict[str, str]] = []
    for spec in AUTH_PLATFORMS.values():
        status = "NOT_CONFIGURED"
        path = auth_dir / spec.slug / "profile.json"
        try:
            if path.is_file():
                payload = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    raw = str(payload.get("status") or "NOT_CONFIGURED")
                    status = raw if raw in allowed else "UNKNOWN"
        except Exception:  # noqa: BLE001
            status = "UNKNOWN"
        state = OK if status == "ACTIVE" else OPTIONAL
        checks.append(_check("auth", spec.display_name, status, state))
    if not checks:
        checks.append(_check("auth", "Authenticated sessions", "none", OPTIONAL))
    return checks


def _providers(settings: Settings) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    cse = bool(settings.secret_present("google_api_key") and settings.google_cse_id)
    checks.append(
        _check(
            "search",
            "Google CSE",
            "CONFIGURED" if cse else "missing",
            OPTIONAL,
        )
    )
    for field, label in _SECRET_FIELDS:
        if field == "google_api_key":
            continue
        present = settings.secret_present(field)
        checks.append(
            _check(
                "providers",
                label,
                "CONFIGURED" if present else "NOT CONFIGURED",
                OPTIONAL,
            )
        )
    return checks


_LEGACY_LOGS_HINT = (
    "Written by an earlier version; may contain target data. Delete it when you no longer "
    "need it. The default ./logs is relative to the folder spectre runs from, so other "
    "folders may have their own."
)


def _legacy_logs(settings: Settings) -> dict[str, str]:
    """Logs from before B2-07 may hold target data. Pointed at, never opened or deleted.

    Informative (`INFO`): it never changes the overall status. Only the configured logs
    directory is looked at; with the default relative `./logs`, that is the one under the
    folder the command runs from.
    """
    found = legacy_log_files(Path(settings.logs_dir))
    if not found:
        return _check("security", "Legacy logs", "none", OK)
    return _check(
        "security",
        "Legacy logs",
        ", ".join(str(path) for path in found),
        INFO,
        hint=_LEGACY_LOGS_HINT,
    )


def _security(settings: Settings) -> list[dict[str, str]]:
    return [
        _check("security", "Secrets redaction", "OK", OK),
        _check(
            "security",
            "SSRF policy",
            "enabled" if settings.ssrf_enabled else "disabled",
            OK if settings.ssrf_enabled else ACTION,
        ),
        _legacy_logs(settings),
    ]


def run_doctor(settings: Settings | None = None) -> dict[str, Any]:
    """Pure diagnostics. Never starts an investigation, login, or Chrome window."""
    cfg = _load_settings(settings)
    if cfg is None:
        return {
            "ready": False,
            "status": ACTION_REQUIRED,
            "version": __version__,
            "checks": [
                _check(
                    "core",
                    "Settings",
                    "unreadable",
                    ACTION,
                    hint="Check .env syntax. Do not paste secrets into issues.",
                )
            ],
        }

    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 12)
    checks: list[dict[str, str]] = [
        _check(
            "core",
            "Python",
            py,
            OK if py_ok else ACTION,
            hint="" if py_ok else "Python 3.12 or 3.13 is required.",
        ),
        _check("core", "SPECTRE", __version__, OK),
        _check("core", "Package import", "OK", OK),
    ]
    checks.extend(_database(cfg))
    reports_ok, reports_detail = _writable_dir(Path(cfg.reports_dir))
    checks.append(
        _check(
            "core",
            "Reports directory",
            "OK" if reports_ok else reports_detail,
            OK if reports_ok else ACTION,
            hint="" if reports_ok else "SPECTRE_REPORTS_DIR must be writable.",
        )
    )
    checks.extend(_chrome(cfg))
    checks.extend(_searxng(cfg))
    checks.extend(_sessions(cfg))
    checks.extend(_providers(cfg))
    checks.extend(_security(cfg))

    has_action = any(item["state"] == ACTION for item in checks)
    has_optional = any(item["state"] == OPTIONAL for item in checks)
    if has_action:
        status = ACTION_REQUIRED
        ready = False
    elif has_optional:
        status = READY_OPTIONAL
        ready = True
    else:
        status = READY
        ready = True
    return {
        "ready": ready,
        "status": status,
        "version": __version__,
        "checks": checks,
    }


# --- presentation (B2-06) ------------------------------------------------------------------
#
# `run_doctor()` keeps producing the same language-neutral report (the `--json` contract).
# The renderers below translate it. Labels, values and hints are produced by this module
# from a closed vocabulary, so they are mapped English text -> catalog key; anything not
# in a table (proper nouns, versions, exception class names, session status codes) is
# printed as-is. `tests/test_doctor_compact.py` scans this file to keep the tables complete.

_GROUPS = ("core", "browser", "search", "auth", "providers", "security")
_SUMMARY_GROUPS = frozenset({"core", "security"})

_LABEL_KEYS = {
    "Package import": "doctor.label.package_import",
    "Database": "doctor.label.database",
    "Database writable": "doctor.label.database_writable",
    "Reports directory": "doctor.label.reports_directory",
    "Settings": "doctor.label.settings",
    "Secrets redaction": "doctor.label.secrets_redaction",
    "SSRF policy": "doctor.label.ssrf_policy",
    "Legacy logs": "doctor.label.legacy_logs",
    "Authenticated sessions": "doctor.label.authenticated_sessions",
    "Censys secret": "doctor.label.censys_secret",
    "GitHub token": "doctor.label.github_token",
}
_VALUE_KEYS = {
    "memory": "doctor.value.memory",
    "not probed": "doctor.value.not_probed",
    "detected": "doctor.value.detected",
    "missing": "doctor.value.missing",
    "inactive": "doctor.value.inactive",
    "listening": "doctor.value.listening",
    "configured": "doctor.value.configured",
    "configured (error)": "doctor.value.configured_error",
    "configured (offline)": "doctor.value.configured_offline",
    "invalid": "doctor.value.invalid",
    "CONFIGURED": "doctor.value.configured_upper",
    "NOT CONFIGURED": "doctor.value.not_configured_upper",
    "enabled": "doctor.value.enabled",
    "disabled": "doctor.value.disabled",
    "unreadable": "doctor.value.unreadable",
    "none": "doctor.value.none",
}
_HINT_KEYS = {
    "Python 3.12 or 3.13 is required.": "doctor.hint.python",
    "SPECTRE_DATA_DIR must be writable.": "doctor.hint.data_dir",
    "SPECTRE_DATA_DIR / SPECTRE_DATABASE_URL must be writable.": "doctor.hint.database",
    "SPECTRE_REPORTS_DIR must be writable.": "doctor.hint.reports_dir",
    "Optional. Needed for authenticated-public sessions.": "doctor.hint.chrome",
    "Doctor does not launch Chrome.": "doctor.hint.cdp",
    "Set SEARXNG_URL=http://127.0.0.1:<port> for local search.": "doctor.hint.searxng_missing",
    "SEARXNG_URL must be loopback http(s).": "doctor.hint.searxng_invalid",
    "Instance responded with a server error. Optional.": "doctor.hint.searxng_error",
    "URL is set; instance did not respond. Optional.": "doctor.hint.searxng_offline",
    "Check .env syntax. Do not paste secrets into issues.": "doctor.hint.settings",
    _LEGACY_LOGS_HINT: "doctor.hint.legacy_logs",
}
_STATUS_KEYS = {
    READY: "doctor.status.ready",
    READY_OPTIONAL: "doctor.status.ready_optional",
    ACTION_REQUIRED: "doctor.status.action_required",
}
# An optional check whose value says "nothing is set up here": collapsed by default.
_UNCONFIGURED_VALUES = frozenset({"missing", "NOT CONFIGURED", "NOT_CONFIGURED", "inactive", "none"})
# A check that is set up and working, even when its state is OPTIONAL (API keys).
_CONFIGURED_VALUES = frozenset({"CONFIGURED", "configured", "detected", "listening", "ACTIVE"})

KIND_ACTION = "action"
KIND_ATTENTION = "attention"
KIND_CONFIGURED = "configured"
KIND_UNCONFIGURED = "unconfigured"
KIND_OK = "ok"


def classify_check(item: dict[str, str]) -> str:
    """How the compact doctor treats one check."""
    state = item.get("state")
    value = str(item.get("value") or "")
    if state == ACTION:
        return KIND_ACTION
    if item.get("group") in _SUMMARY_GROUPS:
        return KIND_OK if state == OK else KIND_ATTENTION
    if state == OK or value in _CONFIGURED_VALUES:
        return KIND_CONFIGURED
    if value in _UNCONFIGURED_VALUES:
        return KIND_UNCONFIGURED
    return KIND_ATTENTION


def _localized(text: str, table: dict[str, str]) -> str:
    key = table.get(text)
    return t(key) if key else text


def _label(item: dict[str, str], *, compact: bool) -> str:
    label = _localized(str(item.get("label") or ""), _LABEL_KEYS)
    if compact and item.get("group") == "auth" and item.get("label") != "Authenticated sessions":
        return t("doctor.session_item", platform=label)
    return label


def _value(item: dict[str, str]) -> str:
    return _localized(str(item.get("value") or ""), _VALUE_KEYS)


def _hint(item: dict[str, str]) -> str:
    return _localized(str(item.get("hint") or ""), _HINT_KEYS)


def _state(item: dict[str, str]) -> str:
    key = f"doctor.state.{item.get('state')}"
    return t(key) if has_message(key) else str(item.get("state") or "").upper()


def _overall(report: dict[str, Any]) -> str:
    status = str(report.get("status") or "")
    key = _STATUS_KEYS.get(status)
    return t("doctor.overall", status=t(key) if key else status)


def _value_of(checks: list[dict[str, str]], label: str) -> str:
    return next((str(item.get("value") or "") for item in checks if item.get("label") == label), "?")


def _flagged(item: dict[str, str]) -> str:
    line = f"[{_state(item)}] {_label(item, compact=True)}: {_value(item)}"
    hint = _hint(item)
    return f"{line} — {hint}" if hint else line


def _render_compact(report: dict[str, Any]) -> list[str]:
    checks: list[dict[str, str]] = list(report.get("checks") or [])
    kinds = [(item, classify_check(item)) for item in checks]
    lines = [t("doctor.title", version=report.get("version") or __version__)]
    for group, key in (("core", "doctor.core_ok"), ("security", "doctor.security_ok")):
        members = [item for item in checks if item.get("group") == group]
        if members and not any(item.get("state") == ACTION for item in members):
            lines.append(
                t(key, python=_value_of(checks, "Python"), database=_value_of(checks, "Database"))
            )
    configured = [_label(item, compact=True) for item, kind in kinds if kind == KIND_CONFIGURED]
    if configured:
        lines.append(t("doctor.configured", items=", ".join(configured)))
    lines.extend(_flagged(item) for item, kind in kinds if kind == KIND_ACTION)
    lines.extend(_flagged(item) for item, kind in kinds if kind == KIND_ATTENTION)
    missing = [item for item, kind in kinds if kind == KIND_UNCONFIGURED]
    if missing:
        groups = [g for g in _GROUPS if any(item.get("group") == g for item in missing)]
        lines.append(
            tn(
                "doctor.optional_missing",
                len(missing),
                groups=", ".join(t(f"doctor.short.{g}") for g in groups),
            )
        )
    lines.append(_overall(report))
    return lines


def _render_all(report: dict[str, Any]) -> list[str]:
    lines = [t("doctor.title", version=report.get("version") or __version__), ""]
    for group in _GROUPS:
        rows = [item for item in report.get("checks") or [] if item.get("group") == group]
        if not rows:
            continue
        lines.append(t(f"doctor.group.{group}"))
        for item in rows:
            lines.append(f"  {_label(item, compact=False):<24} {_value(item):<16} {_state(item)}")
            hint = _hint(item)
            if hint:
                lines.append(f"    {hint}")
        lines.append("")
    lines.append(_overall(report))
    return lines


def render_doctor(report: dict[str, Any], *, show_all: bool = False) -> str:
    """Human-readable doctor output in the active language.

    Default: about eight lines — core and security summarized, configured items on one
    line, anything needing action or attention listed with its hint, unconfigured
    optionals collapsed into one counted line. `show_all=True` lists every check.
    """
    lines = _render_all(report) if show_all else _render_compact(report)
    return _scrub_secrets("\n".join(lines))


def dumps_doctor(report: dict[str, Any]) -> str:
    return _scrub_secrets(json.dumps(report, indent=2, sort_keys=True))
