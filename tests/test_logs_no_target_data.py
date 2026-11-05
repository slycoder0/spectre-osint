"""Canary: logs and warnings never contain target data (B2-07).

The invariant (CLAUDE.md): a log line or warning never carries the username, e-mail,
name, phone, investigated domain / IP / URL, a profile URL (it contains the username),
a pivot value, `str(exc)` of httpx / validation errors (they carry URLs and payload
values) or a report / case path (it contains the target slug).

Three guards, all offline:

1. **Dynamic canary.** Synthetic investigations (username `alice_osint` with the
   e-mail / name / website leads, domain `example.com` with auto-pivot) run the real
   pipeline against a mock transport that answers with timeouts, TLS failures, HTTP
   4xx/5xx/429, non-RFC statuses, SSRF blocks, validation errors and crashing callbacks.
   Logging runs at DEBUG. Every record is captured *raw* (before the production safety
   net that scrubs known target values), together with the log file and stderr, and no
   sentinel may appear in any form (case-folded, URL-encoded, slugified, hashed, inside
   URLs). Coverage markers prove the error paths really ran.
2. **Static guard.** Every `logger.*()` call in `spectre_osint/` is parsed: no f-string
   messages, no exception objects or `str(exc)`, no target-shaped names (`url`,
   `username`, `host`, `target`, ...) unless wrapped in an approved helper
   (`exc_label`, `target_ref`, `host_ref`). This catches leaks on paths the dynamic run
   does not reach.
3. **Self-tests.** The detector itself is shown to catch a leaky line in every derived
   form, so a green canary is not a blind one.

If this file fails after a change, a log line now carries target data: log the provider
slug, status, counts, the exception class (`exc_label`) or a per-run reference
(`target_ref` / `host_ref`) instead.
"""

from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import logging
import warnings
import zlib
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus

import httpx
import pytest
from pydantic import BaseModel
from typer.testing import CliRunner

import spectre_osint
from spectre_osint.cli.commands import app as cli_app
from spectre_osint.core.config import Settings, reload_settings
from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.logger import ROOT_LOGGER, get_logger, setup_logging
from spectre_osint.core.pipeline import InvestigationRunner
from spectre_osint.core.types import EntityType
from spectre_osint.services.investigations import username_request

USERNAME = "alice_osint"
NAME = "Alice Example"
EMAIL = "alice@example.com"
DOMAIN = "example.com"
PIVOT_IP = "93.184.216.34"  # A record of the synthetic domain; followed by auto-pivot
SENTINELS = (USERNAME, NAME, EMAIL, DOMAIN, PIVOT_IP)

# Pins every non-target host during the SSRF-enabled domain run. Not target data.
PROVIDER_PIN_IP = "1.1.1.1"
# What the synthetic resolver answers for the target domain: blocked by the SSRF policy,
# so the fingerprint path raises SSRFBlocked, whose message names the host.
TARGET_PRIVATE_IP = "10.0.0.5"


# --- the detector ----------------------------------------------------------------------------


def derived_forms(value: str) -> set[str]:
    """Every shape a target value takes in a log line, case-folded for matching."""
    bases = {value, value.casefold(), value.upper()}
    forms: set[str] = set()
    for base in bases:
        forms.update(
            {
                base,
                quote(base, safe=""),
                quote(base, safe="/:@"),
                quote_plus(base),
                base.replace(" ", ""),
                base.replace(" ", "-"),
                base.replace(" ", "_"),
                base.replace("_", "-"),
                base.replace(".", "-"),
                base.replace("@", "%40"),
            }
        )
    if "@" in value:
        normalized = value.strip().lower().encode("utf-8")
        forms.add(hashlib.md5(normalized).hexdigest())  # noqa: S324 — gravatar-style id
        forms.add(hashlib.sha256(normalized).hexdigest())
    try:
        forms.add(ipaddress.ip_address(value).reverse_pointer)
    except ValueError:
        pass
    return {form.casefold() for form in forms if len(form) >= 4}


_FORMS = {sentinel: derived_forms(sentinel) for sentinel in SENTINELS}


def find_leaks(text: str) -> list[str]:
    folded = text.casefold()
    hits: list[str] = []
    for sentinel, forms in _FORMS.items():
        for form in sorted(forms):
            if form in folded:
                hits.append(f"{sentinel!r} as {form!r}")
    return hits


def _leak_report(lines: Iterable[str]) -> list[str]:
    report = []
    for line in lines:
        hits = find_leaks(line)
        if hits:
            report.append(f"{line[:300]!r} -> {hits}")
    return report


# --- capture ---------------------------------------------------------------------------------


class _Capture(logging.Handler):
    """Keeps every record that reaches the `spectre` logger, before any formatter runs."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _production_formatter() -> logging.Formatter:
    for handler in logging.getLogger(ROOT_LOGGER).handlers:
        if isinstance(handler, logging.FileHandler) and handler.formatter is not None:
            return handler.formatter
    raise AssertionError("no SPECTRE file handler configured")


def _raw_lines(records: Iterable[logging.LogRecord], formatter: logging.Formatter) -> Iterator[str]:
    """The message as the call site built it, plus the traceback the sinks would write.

    `getMessage()` is the call site's own text, before the safety net. Tracebacks go
    through the production `formatException`, which is where exception messages are
    withheld; the target-value scrubbing happens later, in `format()`.
    """
    for record in records:
        yield f"{record.name} {record.levelname} {record.getMessage()}"
        if record.exc_info:
            yield formatter.formatException(record.exc_info)
        if record.stack_info:
            yield str(record.stack_info)


def _log_files(logs_dir: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8", errors="replace") for path in sorted(logs_dir.glob("*.log*"))
    )


@pytest.fixture
def capture(caplog: pytest.LogCaptureFixture) -> Iterator[_Capture]:
    """Every record, from every logger, at DEBUG.

    `spectre` records come through `_Capture` (the `spectre` logger does not propagate,
    and `setup_logging()` replaces stream handlers such as caplog's); every other logger
    (httpx, httpcore, alembic, ...) reaches caplog through the root logger. The test
    reads both lists.
    """
    logger = logging.getLogger(ROOT_LOGGER)
    saved = (list(logger.handlers), logger.level, logger.propagate)
    handler = _Capture()
    handler.caplog = caplog  # type: ignore[attr-defined]
    caplog.set_level(logging.DEBUG)
    logger.addHandler(handler)
    try:
        yield handler
    finally:
        for added in logger.handlers:
            if added not in saved[0] and added is not handler:
                added.close()
        logger.handlers[:] = saved[0]
        logger.setLevel(saved[1])
        logger.propagate = saved[2]


def _all_records(capture: _Capture) -> list[logging.LogRecord]:
    seen = {id(record) for record in capture.records}
    extra = [r for r in capture.caplog.records if id(r) not in seen]  # type: ignore[attr-defined]
    return [*capture.records, *extra]


# --- the synthetic internet ------------------------------------------------------------------

_PROFILE_HTML = """<!doctype html>
<html><head><title>{u} · {n}</title>
<link rel="canonical" href="https://{host}/{u}">
<meta property="og:title" content="{n} (@{u})">
<meta property="og:url" content="https://{host}/{u}">
<meta name="description" content="{n}. Contact {e}. Website https://{d}/">
</head><body><h1>{n}</h1><p>@{u}</p><a href="https://{d}/">{d}</a>
<a href="mailto:{e}">{e}</a></body></html>"""

_CATALOG_BEHAVIOURS = (
    "timeout",
    "tls",
    "protocol",
    "500",
    "503",
    "429",
    "403",
    "404",
    "200",
    "200",
    "999",
)


def _host(request: httpx.Request) -> str:
    return (request.headers.get("host") or request.url.host or "").split(":")[0].lower()


def _tls_error(request: httpx.Request, host: str) -> httpx.ConnectError:
    return httpx.ConnectError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, "
        f"certificate is not valid for '{host}'. (_ssl.c:1006) url={request.url}",
        request=request,
    )


def _profile_json(host: str) -> dict[str, Any]:
    return {
        "login": USERNAME,
        "username": USERNAME,
        "id": 4242,
        "name": NAME,
        "email": EMAIL,
        "blog": f"https://{DOMAIN}/",
        "bio": f"{NAME} — {EMAIL}",
        "html_url": f"https://{host}/{USERNAME}",
        "created_at": "2020-01-01T00:00:00Z",
    }


def _search_html(query: str) -> str:
    # One result per query is new (its path depends on the query), so the search pass
    # still has an unseen profile candidate after the mentions pass consumed the rest.
    per_query = zlib.crc32(query.encode("utf-8")) % 997
    rows = "".join(
        f'<div class="result"><a class="result__a" href="{href}">{USERNAME} — {NAME}</a>'
        f'<div class="result__snippet">{USERNAME} profile {NAME} {EMAIL}</div></div>'
        for href in (
            f"https://codeberg.org/{USERNAME}",
            f"https://{USERNAME.replace('_', '-')}.dev/about",
            f"https://{DOMAIN}/team/{USERNAME}",
            f"https://people.example.net/u/{USERNAME}/{per_query}",
        )
    )
    return f"<html><body>{rows}</body></html>"


def synthetic_internet(request: httpx.Request) -> httpx.Response:
    host = _host(request)
    path = request.url.path
    if host == "hn.algolia.com":
        return httpx.Response(
            200,
            json={
                "hits": [
                    {
                        "objectID": "1",
                        "title": f"{USERNAME} ships a tool",
                        "story_text": f"by {NAME} <{EMAIL}> https://github.com/{USERNAME}",
                        "author": USERNAME,
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ]
            },
        )
    if host == "html.duckduckgo.com":
        query = request.url.params.get("q") or ""
        return httpx.Response(200, text=_search_html(query), headers={"content-type": "text/html"})
    if host == "api.github.com" and path.startswith("/search/"):
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "title": f"{USERNAME} issue",
                        "html_url": f"https://github.com/{USERNAME}/tool/issues/1",
                        "body": f"{NAME} {EMAIL}",
                        "user": {"login": USERNAME},
                    }
                ]
            },
        )
    if host == "www.reddit.com":
        return httpx.Response(429, headers={"Retry-After": "0"})
    if "rdap" in host:
        raise _tls_error(request, host)
    if host == "crt.sh":
        return httpx.Response(503)
    if host.endswith("archive.org"):
        raise httpx.ReadTimeout(f"timed out reading {request.url}", request=request)
    if host.endswith("urlscan.io"):
        return httpx.Response(429, headers={"Retry-After": "0"})
    if host.endswith("ipinfo.io"):
        return httpx.Response(999)
    if host.startswith("api.") or "/api/" in path or path.endswith(".json"):
        if host == "api.github.com" or zlib.crc32(host.encode()) % 2 == 0:
            return httpx.Response(200, json=_profile_json(host))
    behaviour = _CATALOG_BEHAVIOURS[zlib.crc32(host.encode()) % len(_CATALOG_BEHAVIOURS)]
    if host in {"github.com", "gitlab.com", "codeberg.org"}:
        behaviour = "200"
    if behaviour == "timeout":
        raise httpx.ReadTimeout(f"timed out reading {request.url}", request=request)
    if behaviour == "tls":
        raise _tls_error(request, host)
    if behaviour == "protocol":
        raise httpx.RemoteProtocolError(
            f"peer closed connection while fetching {request.url}", request=request
        )
    if behaviour == "200":
        body = _PROFILE_HTML.format(u=USERNAME, n=NAME, e=EMAIL, d=DOMAIN, host=host)
        return httpx.Response(200, text=body, headers={"content-type": "text/html; charset=utf-8"})
    if behaviour == "429":
        return httpx.Response(429, headers={"Retry-After": "0"})
    return httpx.Response(int(behaviour), text=f"{USERNAME} not here")


def _fake_dns(domain: str, rdtype: str, timeout: float = 8.0) -> list[str]:
    import dns.resolver

    del timeout
    name = domain.rstrip(".").lower()
    if name.endswith("in-addr.arpa"):
        raise dns.resolver.NXDOMAIN(qnames=[name])
    if name == DOMAIN and rdtype == "A":
        return [PIVOT_IP]
    if name == DOMAIN and rdtype == "TXT":
        return [f"v=spf1 include:_spf.{DOMAIN} -all"]
    raise dns.resolver.NoAnswer()


async def _fake_resolve(host: str) -> list[str]:
    if host == DOMAIN or host.endswith("." + DOMAIN):
        return [TARGET_PRIVATE_IP]
    return [PROVIDER_PIN_IP]


async def _no_sleep(_seconds: float) -> None:
    return None


def _settings(tmp_path: Path, *, ssrf: bool) -> Settings:
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=ssrf,
        http_max_retries=2,
        http_retry_budget=5,
        pivot_budget=3,
    )
    settings.ensure_dirs()
    return settings


def _client(settings: Settings) -> HttpClient:
    return HttpClient(
        settings,
        transport=httpx.MockTransport(synthetic_internet),
        resolver=_fake_resolve,
        sleeper=_no_sleep,
        jitter_fn=lambda: 0.0,
    )


class _Payload(BaseModel):
    followers: int


def _validation_error(value: str) -> Exception:
    try:
        _Payload(followers=value)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 — pydantic.ValidationError carries input_value
        return exc
    raise AssertionError("expected a validation error")


def _crashing_progress(payload: dict[str, Any]) -> None:
    """A progress sink that fails with the payload (which names the target) in its message.

    Only on the phases whose callers guard the sink and log the failure with
    `exc_info=True` (pipeline `_emit_progress`, catalog `_emit`). Mentions and search call
    the sink unguarded, so a failure there would skip those passes (STATUS follow-up).
    """
    if payload.get("phase") in {"initializing", "catalog", "normalizing", "scoring", "report"}:
        raise RuntimeError(f"progress sink broke on {json.dumps(payload, default=str)}")


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    monkeypatch.setattr("spectre_osint.modules.dns.resolver._query_sync", _fake_dns)
    return monkeypatch


def _assert_no_leaks(capture: _Capture, logs_dir: Path, stderr: str, caught: list[Any]) -> str:
    raw = list(_raw_lines(_all_records(capture), _production_formatter()))
    leaks = {
        "raw records (before the safety net)": _leak_report(raw),
        "log file": _leak_report(_log_files(logs_dir).splitlines()),
        "stderr": _leak_report(stderr.splitlines()),
        "warnings": _leak_report(str(w.message) for w in caught),
    }
    assert {where: lines for where, lines in leaks.items() if lines} == {}
    return "\n".join(raw)


def _assert_exercised(raw: str, markers: Iterable[str]) -> None:
    missing = [marker for marker in markers if marker not in raw]
    assert missing == [], f"canary no longer reaches these paths: {missing}"


# --- 1. dynamic canary -----------------------------------------------------------------------


async def test_username_investigation_with_leads_logs_no_target_data(
    tmp_path: Path, capture: _Capture, offline: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from spectre_osint.core import pipeline
    from spectre_osint.modules.username import engine

    settings = _settings(tmp_path, ssrf=False)
    init_db(settings)
    setup_logging("DEBUG", settings.logs_dir, console_level="DEBUG")

    async def failing_email(entity: Any, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise _validation_error(entity.normalized_value)

    async def failing_website(entity: Any, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise httpx.ConnectError(f"cannot reach https://{entity.normalized_value}/ for {EMAIL}")

    real_check_site = engine._check_site

    async def sometimes_crashing_check_site(entity: Any, site: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
        if str(site.get("name") or "") == "GitLab":
            raise RuntimeError(f"site check crashed for https://gitlab.com/{entity.normalized_value}")
        return await real_check_site(entity, site, *args, **kwargs)

    offline.setattr(pipeline, "analyze_email", failing_email)
    offline.setattr(pipeline, "analyze_domain", failing_website)
    offline.setattr(engine, "_check_site", sometimes_crashing_check_site)

    request = username_request(USERNAME, display_name=NAME, email=EMAIL, website=DOMAIN)
    runner = InvestigationRunner(settings=settings, http=_client(settings))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            result = await runner.run(
                request.target,
                force_type=EntityType.USERNAME,
                extra=request.extra,
                write_report=True,
                progress=_crashing_progress,
            )
        finally:
            await runner.http.close()
            reset_engine()

    assert result.findings, "the synthetic run produced nothing; the canary is not running"
    raw = _assert_no_leaks(capture, settings.logs_dir, capsys.readouterr().err, list(caught))
    _assert_exercised(
        raw,
        (
            "HTTP timeout",
            "TLS certificate verification failed",
            "HTTP error",
            "status=429",
            "unofficial HTTP",
            "Username site check failed",
            "progress callback failed",
            "Optional email collection failed",
            "Optional website collection failed",
            "profile enrichment",
            "identity correlation",
            "discovered profile",
        ),
    )


async def test_domain_investigation_with_pivots_logs_no_target_data(
    tmp_path: Path, capture: _Capture, offline: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from spectre_osint.core import pipeline

    settings = _settings(tmp_path, ssrf=True)
    init_db(settings)
    setup_logging("DEBUG", settings.logs_dir, console_level="DEBUG")

    async def failing_ip(entity: Any, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise ValueError(f"cannot enrich {entity.normalized_value} via https://ipinfo.io/{entity.normalized_value}")

    def failing_graph_export(_graph: Any, path: Path) -> None:
        raise PermissionError(13, "Permission denied", str(path))

    offline.setattr(pipeline, "analyze_ip", failing_ip)
    offline.setattr(pipeline, "export_graphml", failing_graph_export)

    runner = InvestigationRunner(settings=settings, http=_client(settings))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            result = await runner.run(
                DOMAIN,
                force_type=EntityType.DOMAIN,
                auto_pivot=True,
                depth=2,
                write_report=True,
                progress=_crashing_progress,
            )
        finally:
            await runner.http.close()
            reset_engine()

    assert result.findings
    raw = _assert_no_leaks(capture, settings.logs_dir, capsys.readouterr().err, list(caught))
    _assert_exercised(
        raw,
        (
            "Auto-pivot",
            "Pivot failed",
            "Graph export failed",
            "Public HTTP fingerprint skipped",
            "unavailable",
            "TLS certificate verification failed",
            "HTTP timeout",
            "status=429",
            "progress callback failed",
        ),
    )


async def test_active_recon_audit_line_names_no_host(
    tmp_path: Path, capture: _Capture, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from spectre_osint.modules.network import recon

    async def refused(host: str, port: int) -> Any:
        raise ConnectionRefusedError(f"connect to {host}:{port} refused")

    monkeypatch.setattr(recon.asyncio, "open_connection", refused)
    setup_logging("DEBUG", tmp_path / "logs", console_level="DEBUG")
    result = await recon.authorized_connect_scan(DOMAIN, authorized=True, ports=(80, 443), timeout=0.1)
    assert result["findings"][0].data["host"] == DOMAIN  # the finding keeps it
    raw = _assert_no_leaks(capture, tmp_path / "logs", capsys.readouterr().err, [])
    _assert_exercised(raw, ("ACTIVE RECON AUTHORIZED",))


def _cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, ssrf: bool) -> Path:
    logs_dir = tmp_path / "logs"
    monkeypatch.setenv("SPECTRE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SPECTRE_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("SPECTRE_LOGS_DIR", str(logs_dir))
    monkeypatch.setenv("SPECTRE_DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setenv("SPECTRE_SSRF_ENABLED", "true" if ssrf else "false")
    monkeypatch.setenv("SPECTRE_HTTP_MAX_RETRIES", "2")
    reset_engine()
    reload_settings()
    return logs_dir


def _patch_cli_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI's real service call, with the synthetic internet as its HTTP transport."""
    from spectre_osint.cli import commands
    from spectre_osint.core.config import get_settings
    from spectre_osint.services import investigations

    async def run(request: Any, *, progress: Any = None) -> Any:
        settings = get_settings()
        client = _client(settings)
        try:
            return await investigations.run_investigation(
                request,
                progress=progress,
                runner_factory=lambda: InvestigationRunner(settings=settings, http=client),
            )
        finally:
            await client.close()

    monkeypatch.setattr(commands, "run_investigation", run)


@pytest.mark.parametrize(
    ("argv", "ssrf"),
    [
        (
            ["--debug", "username", USERNAME, "--name", NAME, "--email", EMAIL, "--website", DOMAIN],
            False,
        ),
        (["--debug", "domain", DOMAIN, "--auto-pivot", "--depth", "2"], True),
    ],
    ids=["username-with-leads", "domain-auto-pivot"],
)
def test_cli_debug_run_keeps_target_data_out_of_stderr_and_log_file(
    argv: list[str],
    ssrf: bool,
    tmp_path: Path,
    capture: _Capture,
    offline: pytest.MonkeyPatch,
) -> None:
    logs_dir = _cli_env(tmp_path, offline, ssrf=ssrf)
    _patch_cli_runner(offline)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            result = CliRunner().invoke(cli_app, argv)
        finally:
            reset_engine()
    assert result.exit_code == 0, result.output
    assert find_leaks(result.stdout), "the result itself should name the target on stdout"
    assert list(logs_dir.glob("*.log")), "the run wrote no log file"
    _assert_no_leaks(capture, logs_dir, result.stderr, list(caught))


# --- 2. static guard -------------------------------------------------------------------------

_LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
# Wrapping a value in one of these makes it safe to log.
_SAFE_WRAPPERS = {"exc_label", "target_ref", "host_ref", "len", "bool", "int", "float", "round"}
# Bare names / subscript keys that hold target data in this code base.
_DENY_NAMES = {
    "url",
    "urls",
    "username",
    "usernames",
    "handle",
    "handles",
    "target",
    "email",
    "emails",
    "display_name",
    "phone",
    "domain",
    "host",
    "hostname",
    "ip",
    "ips",
    "website",
    "alias",
    "aliases",
    "query",
    "value",
    "title",
    "og_title",
    "canonical",
    "inputs",
    "payload",
    "reason",  # often str(exc) handed down
    "detail",
}
# Attribute names that hold target data (`spec.display_name` is a platform name, so the
# attribute list is narrower than the bare-name list).
_DENY_ATTRS = {"normalized_value", "username", "email", "url", "host", "hostname", "target", "query"}


def _is_logger_call(node: ast.Call) -> bool:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr not in _LOG_METHODS:
        return False
    owner = func.value
    return isinstance(owner, ast.Name) and owner.id in {"logger", "log", "_log", "LOGGER"}


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


# Booleans and counters that only *mention* a target-shaped field.
_FLAG_PREFIXES = ("username_in_", "rejected_", "has_", "n_")


def _denied(name: str) -> bool:
    if name.startswith(_FLAG_PREFIXES):
        return False
    return name in _DENY_NAMES or name.endswith("_url") or name.endswith("_urls")


def _unsafe_parts(node: ast.AST, exc_names: set[str]) -> list[str]:
    if isinstance(node, ast.Call) and _call_name(node.func) in _SAFE_WRAPPERS:
        return []
    if isinstance(node, ast.Attribute) and node.attr == "__name__":
        return []  # type(exc).__name__
    if isinstance(node, ast.Call) and _call_name(node.func) in {"str", "repr", "format"}:
        inner = [arg for arg in node.args if isinstance(arg, ast.Name) and arg.id in exc_names]
        if inner:
            return [f"{_call_name(node.func)}({inner[0].id})"]
    if isinstance(node, ast.JoinedStr):
        return ["f-string argument (pass safe values as separate args)"]
    if isinstance(node, ast.Name):
        if node.id in exc_names:
            return [f"exception object {node.id!r} (use exc_label)"]
        if _denied(node.id):
            return [f"target-shaped name {node.id!r}"]
        return []
    if isinstance(node, ast.Attribute) and (
        node.attr in _DENY_ATTRS or (node.attr.endswith("_url") and not node.attr.startswith(_FLAG_PREFIXES))
    ):
        return [f"target-shaped attribute .{node.attr}"]
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
        and _denied(node.slice.value)
    ):
        return [f"target-shaped key [{node.slice.value!r}]"]
    found: list[str] = []
    for child in ast.iter_child_nodes(node):
        found.extend(_unsafe_parts(child, exc_names))
    return found


def log_call_violations(source: str, filename: str = "<string>") -> list[str]:
    tree = ast.parse(source, filename=filename)
    exc_names = {
        handler.name for handler in ast.walk(tree) if isinstance(handler, ast.ExceptHandler) and handler.name
    }
    problems: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_logger_call(node):
            continue
        args = list(node.args)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "log" and args:
            args = args[1:]
        if not args:
            continue
        message, *rest = args
        where = f"{filename}:{node.lineno}"
        if not (isinstance(message, ast.Constant) and isinstance(message.value, str)):
            problems.append(f"{where}: message is not a constant string (f-string / concatenation)")
        for arg in rest:
            for part in _unsafe_parts(arg, exc_names):
                problems.append(f"{where}: {part}")
        for keyword in node.keywords:
            if keyword.arg == "extra":
                problems.append(f"{where}: extra= is not checked; pass safe positional args")
    return problems


def _package_sources() -> list[Path]:
    root = Path(spectre_osint.__file__).parent
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def test_no_log_call_in_the_package_passes_target_shaped_values() -> None:
    root = Path(spectre_osint.__file__).parent.parent
    problems: list[str] = []
    calls = 0
    for path in _package_sources():
        source = path.read_text(encoding="utf-8")
        calls += source.count("logger.")
        problems.extend(log_call_violations(source, str(path.relative_to(root))))
    assert calls > 50, "the scan found almost no log calls; it is not looking at the package"
    assert problems == []


def test_the_package_never_calls_warnings_warn_with_dynamic_text() -> None:
    problems: list[str] = []
    for path in _package_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "warn"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "warnings"
                and not (node.args and isinstance(node.args[0], ast.Constant))
            ):
                problems.append(f"{path.name}:{node.lineno}")
    assert problems == []


# --- 3. self-tests: the canary is not blind --------------------------------------------------


@pytest.mark.parametrize(
    "leaky",
    [
        f"profile url=https://github.com/{USERNAME}",
        f"user={USERNAME.upper()}",
        f"q={quote_plus(NAME)}",
        f"q=%22{quote(NAME)}%22",
        f"lead={NAME.lower().replace(' ', '-')}",
        f"mail={quote(EMAIL, safe='')}",
        f"avatar=https://gravatar.com/avatar/{hashlib.md5(EMAIL.encode()).hexdigest()}",  # noqa: S324
        f"host={DOMAIN.upper()}",
        "report=reports/case-domain-example-com-20261105.html",
        f"ptr={ipaddress.ip_address(PIVOT_IP).reverse_pointer}",
    ],
)
def test_detector_catches_every_derived_form(leaky: str) -> None:
    assert find_leaks(leaky)


@pytest.mark.parametrize(
    "clean",
    [
        "provider=GitHub host=h:3f9a1c0d status=404 attempt=1",
        "HTTP timeout provider=crtsh host=h:0a1b2c3d err=ReadTimeout",
        "Pivot failed type=ip target=t:9e8d7c6b err=ValueError",
        "identity correlation github::t:1a2b3c4d <-> gitlab::t:1a2b3c4d score=60",
    ],
)
def test_detector_accepts_the_safe_shapes(clean: str) -> None:
    assert find_leaks(clean) == []


def test_raw_capture_sees_a_leaky_call_site_even_with_the_safety_net(
    tmp_path: Path, capture: _Capture
) -> None:
    setup_logging("DEBUG", tmp_path / "logs")
    get_logger("spectre.canary").warning("leak url=%s", f"https://github.com/{USERNAME}")
    raw = list(_raw_lines(capture.records, _production_formatter()))
    assert _leak_report(raw), "a leaky call site must fail the canary"


def test_static_guard_flags_the_classic_leaks() -> None:
    source = '''
import logging
logger = logging.getLogger("spectre.x")

def f(url, entity, report):
    try:
        pass
    except Exception as exc:
        logger.warning("failed %s", exc)
        logger.warning("failed %s", str(exc))
        logger.warning(f"failed {url}")
        logger.info("url=%s", url)
        logger.info("target=%s", entity.normalized_value)
        logger.debug("final=%s", report["final_url"])
'''
    problems = log_call_violations(source)
    assert len(problems) == 6, problems


def test_static_guard_accepts_the_safe_helpers() -> None:
    source = '''
from spectre_osint.core.redaction import exc_label, host_ref, target_ref
import logging
logger = logging.getLogger("spectre.x")

def f(url, entity, provider, status):
    try:
        pass
    except Exception as exc:
        logger.warning("failed provider=%s host=%s err=%s", provider, host_ref(url), exc_label(exc))
        logger.warning("failed %s", type(exc).__name__)
        logger.info("pivot target=%s status=%s", target_ref(entity.normalized_value), status.value)
'''
    assert log_call_violations(source) == []
