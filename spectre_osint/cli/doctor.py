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
from spectre_osint.modules.search.providers import is_loopback_searxng, searxng_origin

OK = "ok"
OPTIONAL = "optional"
ACTION = "action"

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

_STATE_LABEL = {OK: "OK", OPTIONAL: "OPTIONAL", ACTION: "ACTION"}


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


def _security(settings: Settings) -> list[dict[str, str]]:
    return [
        _check("security", "Secrets redaction", "OK", OK),
        _check(
            "security",
            "SSRF policy",
            "enabled" if settings.ssrf_enabled else "disabled",
            OK if settings.ssrf_enabled else ACTION,
        ),
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


def render_doctor(report: dict[str, Any]) -> str:
    groups: list[tuple[str, str]] = [
        ("core", "Core"),
        ("browser", "Browser"),
        ("search", "Search"),
        ("auth", "Authenticated public sessions"),
        ("providers", "API providers"),
        ("security", "Security"),
    ]
    lines = ["SPECTRE DOCTOR", ""]
    for key, title in groups:
        rows = [item for item in report["checks"] if item["group"] == key]
        if not rows:
            continue
        lines.append(title)
        for item in rows:
            state = _STATE_LABEL.get(item["state"], str(item["state"]).upper())
            lines.append(f"  {item['label']:<24} {item['value']:<16} {state}")
            if item.get("hint"):
                lines.append(f"    {item['hint']}")
        lines.append("")
    lines.append(f"Overall: {report['status']}")
    return _scrub_secrets("\n".join(lines))


def dumps_doctor(report: dict[str, Any]) -> str:
    return _scrub_secrets(json.dumps(report, indent=2, sort_keys=True))
