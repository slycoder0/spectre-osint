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
import re
import warnings
import zlib
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus

import httpx
import pytest
from pydantic import BaseModel, ValidationError, field_validator
from typer.testing import CliRunner

import spectre_osint
from spectre_osint.cli.commands import app as cli_app
from spectre_osint.core.config import Settings, reload_settings
from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.logger import ROOT_LOGGER, get_logger, setup_logging
from spectre_osint.core.pipeline import InvestigationRunner
from spectre_osint.core.redaction import MIN_SCRUB_LENGTH
from spectre_osint.core.types import EntityType
from spectre_osint.modules.username.engine import load_sites
from spectre_osint.services.investigations import username_request

USERNAME = "alice_osint"
NAME = "Alice Example"
EMAIL = "alice@example.com"
DOMAIN = "example.com"
PIVOT_IP = "93.184.216.34"  # A record of the synthetic domain; followed by auto-pivot
DOC_IP = "192.0.2.10"  # TEST-NET-1, the `spectre ip` target
TARGET_URL = f"https://{DOMAIN}/u/{USERNAME}"  # the `spectre url` target
SENTINELS = (USERNAME, NAME, EMAIL, DOMAIN, PIVOT_IP, DOC_IP, TARGET_URL)

# Pins every non-target host during the SSRF-enabled domain run. Not target data.
PROVIDER_PIN_IP = "1.1.1.1"
# What the synthetic resolver answers for the target domain: blocked by the SSRF policy,
# so the fingerprint path raises SSRFBlocked, whose message names the host.
TARGET_PRIVATE_IP = "10.0.0.5"


# --- the detector ----------------------------------------------------------------------------


def derived_forms(value: str) -> set[str]:
    """Every shape a target value takes in a log line, case-folded for matching.

    Same floor as the production safety net (`MIN_SCRUB_LENGTH`), but stricter where the
    net is lenient: the e-mail's local part and domain are looked for at any length, so a
    call site that logs `alice` from `alice@example.com` fails here even though the net
    would not scrub it (the net is a fallback; this detector is the rule).
    """
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
    always: set[str] = set()
    if "@" in value:
        normalized = value.strip().lower().encode("utf-8")
        forms.add(hashlib.md5(normalized).hexdigest())  # noqa: S324 — gravatar-style id
        forms.add(hashlib.sha256(normalized).hexdigest())
        local, _, domain = value.rpartition("@")
        always.update(part for part in (local, domain) if part)
    try:
        forms.add(ipaddress.ip_address(value).reverse_pointer)
    except ValueError:
        pass
    kept = {form for form in forms if len(form) >= MIN_SCRUB_LENGTH} | always
    return {form.casefold() for form in kept}


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


def _crash_site() -> dict[str, Any]:
    """The site whose check is made to crash: taken from the live catalog (the first
    anonymous one), so renaming or removing a site cannot silently disable the case."""
    return next(site for site in load_sites() if not site.get("requires_auth"))


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
    crash_site = _crash_site()

    async def sometimes_crashing_check_site(entity: Any, site: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
        if site.get("slug") == crash_site["slug"]:
            raise RuntimeError(f"site check crashed for {crash_site['url_template']} {entity.normalized_value}")
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
        (["--debug", "email", EMAIL], True),
        # TEST-NET-1 is a reserved range: the SSRF policy would refuse it up front.
        (["--debug", "ip", DOC_IP], False),
        (["--debug", "url", TARGET_URL], True),
    ],
    ids=["username-with-leads", "domain-auto-pivot", "email", "ip", "url"],
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
# A log call is `<receiver>.<method>(...)` where the receiver is a name or attribute ending
# in one of these (`logger`, `self.logger`, `_log`, `LOGGER`, `sink`), a `get_logger(...)` /
# `logging.getLogger(...)` call, or the `logging` module itself.
_LOGGER_SUFFIXES = ("log", "logger", "sink")
_LOGGER_FACTORIES = {"get_logger", "getLogger"}
# Wrapping a value in one of these makes it safe to log. `validation_label` is built only
# from the error count, pydantic type codes and the exception class (`observed.py`).
_SAFE_WRAPPERS = {
    "exc_label",
    "target_ref",
    "host_ref",
    "validation_label",
    "len",
    "bool",
    "int",
    "float",
    "round",
}
# Bare names / subscript keys / `.get()` keys that hold target data in this code base.
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
# attribute list is narrower than the bare-name list). `.error` is a validation result's
# message (`ObservedAuthority.error`): bounded today, but never a log argument.
_DENY_ATTRS = {"normalized_value", "username", "email", "url", "host", "hostname", "target", "query", "error"}
# Objects whose str() / repr() embeds URLs, payloads or the target: never logged whole,
# with %s or %r, unless the name only ever holds a safe wrapper's result.
_DOMAIN_OBJECTS = {"finding", "request", "response", "entity", "hit", "item", "err"}
_STDERR_ATTRS = {"stderr", "__stderr__"}
_PLACEHOLDER = re.compile(r"%(\([^)]*\))?[#0\- +]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[hlL]?([diouxXeEfFgGcrsa%])")


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _is_logger_receiver(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "logging" or node.id.casefold().endswith(_LOGGER_SUFFIXES)
    if isinstance(node, ast.Attribute):
        return node.attr.casefold().endswith(_LOGGER_SUFFIXES)
    if isinstance(node, ast.Call):
        return _call_name(node.func) in _LOGGER_FACTORIES
    return False


def _is_logger_call(node: ast.Call) -> bool:
    func = node.func
    return isinstance(func, ast.Attribute) and func.attr in _LOG_METHODS and _is_logger_receiver(func.value)


def _is_stderr(node: ast.AST | None) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr in _STDERR_ATTRS and isinstance(node.value, ast.Name) and node.value.id == "sys"
    return isinstance(node, ast.Name) and node.id == "stderr"


# Booleans and counters that only *mention* a target-shaped field.
_FLAG_PREFIXES = ("username_in_", "rejected_", "has_", "n_")


def _denied(name: str) -> bool:
    if name.startswith(_FLAG_PREFIXES):
        return False
    return name in _DENY_NAMES or name.endswith("_url") or name.endswith("_urls")


class _Scope:
    """What one function (or the module body) knows about its names."""

    def __init__(self) -> None:
        self.exc_names: set[str] = set()  # except-bound, or items of gather(return_exceptions=True)
        self.tainted: set[str] = set()  # assigned from target data, str(exc), an f-string, ...
        self.sanitized: set[str] = set()  # only ever assigned a safe wrapper's result


def _unsafe_parts(node: ast.AST, scope: _Scope) -> list[str]:
    if isinstance(node, ast.Call) and _call_name(node.func) in _SAFE_WRAPPERS:
        return []
    if isinstance(node, ast.Attribute) and node.attr == "__name__":
        return []  # type(exc).__name__
    if isinstance(node, ast.Call) and _call_name(node.func) in {"str", "repr", "format", "ascii"}:
        for arg in node.args:
            if isinstance(arg, ast.Name) and (
                arg.id in scope.exc_names or (arg.id in _DOMAIN_OBJECTS and arg.id not in scope.sanitized)
            ):
                return [f"{_call_name(node.func)}({arg.id})"]
    if isinstance(node, ast.JoinedStr):
        return ["f-string argument (pass safe values as separate args)"]
    if isinstance(node, ast.Name):
        if node.id in scope.exc_names:
            return [f"exception object {node.id!r} (use exc_label)"]
        if node.id in scope.tainted:
            return [f"name {node.id!r} is built from target data or an exception message"]
        if node.id in _DOMAIN_OBJECTS and node.id not in scope.sanitized:
            return [f"domain object {node.id!r} (its str/repr carries URLs and payloads)"]
        if _denied(node.id):
            return [f"target-shaped name {node.id!r}"]
        return []
    if isinstance(node, ast.Attribute) and (
        node.attr in _DENY_ATTRS or (node.attr.endswith("_url") and not node.attr.startswith(_FLAG_PREFIXES))
    ):
        return [f"target-shaped attribute .{node.attr}"]
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in _DOMAIN_OBJECTS
        and node.value.id not in scope.exc_names | scope.tainted
    ):
        return []  # `finding.id`, `response.status_code`: the attribute name is what is checked
    if _denied_key(node):
        return [f"target-shaped key {_denied_key(node)}"]
    found: list[str] = []
    for child in ast.iter_child_nodes(node):
        found.extend(_unsafe_parts(child, scope))
    return found


def _denied_key(node: ast.AST) -> str:
    """`x["final_url"]` / `x.get("profile_url")` with a target-shaped key, as text.
    A constant table (`WEIGHTS["same_avatar_url"]`) holds no target data."""
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id.isupper():
        return ""
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        key = node.slice.value
        return f"[{key!r}]" if isinstance(key, str) and _denied(key) else ""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and _denied(node.args[0].value)
    ):
        return f".get({node.args[0].value!r})"
    return ""


def _taints(value: ast.AST, scope: _Scope) -> bool:
    """An assigned value that makes its name unsafe to log: `str(exc)` / `repr(exc)` (or
    of a domain object), an f-string with data, a target-shaped key, or a plain alias,
    slice, concatenation or string method of one of those. A value merely *computed from*
    target data by some other call (`status = classify(url)`) does not count."""
    if isinstance(value, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in value.values)
    if isinstance(value, ast.Name):
        return value.id in scope.tainted or value.id in scope.exc_names or _denied(value.id)
    if _denied_key(value):
        return True
    if isinstance(value, ast.Call):
        name = _call_name(value.func)
        if name in _SAFE_WRAPPERS:
            return False
        if name in {"str", "repr", "format", "ascii"}:
            return any(
                _taints(arg, scope)
                or (isinstance(arg, ast.Name) and arg.id in _DOMAIN_OBJECTS and arg.id not in scope.sanitized)
                for arg in value.args
            )
        if isinstance(value.func, ast.Attribute):
            receiver = value.func.value
            if isinstance(receiver, ast.Constant) and isinstance(receiver.value, str):
                return any(_taints(arg, scope) for arg in value.args)  # "...".format(url), ", ".join(urls)
            return _taints(receiver, scope)  # reason.strip(), url.lower()
        return False
    if isinstance(value, ast.BoolOp):
        return any(_taints(part, scope) for part in value.values)
    if isinstance(value, ast.IfExp):
        return _taints(value.body, scope) or _taints(value.orelse, scope)
    if isinstance(value, ast.BinOp):
        return _taints(value.left, scope) or _taints(value.right, scope)
    if isinstance(value, (ast.Subscript, ast.Await)):
        return _taints(value.value, scope)
    return False


def _target_names(target: ast.AST) -> set[str]:
    """Names bound by an assignment target (`a`, `a, b`, `*rest`), not `self.x` / `d[k]`."""
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_target_names(element) for element in target.elts))
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return set()


def _is_gather_with_exceptions(node: ast.AST | None) -> bool:
    if isinstance(node, ast.Await):
        node = node.value
    return (
        isinstance(node, ast.Call)
        and _call_name(node.func) == "gather"
        and any(
            kw.arg == "return_exceptions" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
    )


def _scope_nodes(tree: ast.Module) -> list[list[ast.AST]]:
    """The module body and each outermost function, as flat node lists (nested functions
    belong to their outer function)."""
    functions: list[ast.AST] = []
    module: list[ast.AST] = []
    stack: list[ast.AST] = list(ast.iter_child_nodes(tree))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node)
            continue
        module.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return [module, *(list(ast.walk(function)) for function in functions)]


def _analyse(nodes: list[ast.AST]) -> _Scope:
    scope = _Scope()
    scope.exc_names = {node.name for node in nodes if isinstance(node, ast.ExceptHandler) and node.name}
    assignments: list[tuple[set[str], ast.AST]] = []
    for node in nodes:
        if isinstance(node, ast.Assign):
            names = set().union(*(_target_names(target) for target in node.targets))
            assignments.append((names, node.value))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            assignments.append((_target_names(node.target), node.value))
        elif isinstance(node, ast.NamedExpr):
            assignments.append((_target_names(node.target), node.value))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            assignments.append((_target_names(node.target), node.iter))
    gathered = {name for names, value in assignments if _is_gather_with_exceptions(value) for name in names}
    for node in nodes:
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)) and (
            _is_gather_with_exceptions(node.iter) or (isinstance(node.iter, ast.Name) and node.iter.id in gathered)
        ):
            scope.exc_names |= _target_names(node.target)
    by_name: dict[str, list[ast.AST]] = {}
    for names, value in assignments:
        for name in names:
            by_name.setdefault(name, []).append(value)
    scope.sanitized = {
        name
        for name, values in by_name.items()
        if all(
            isinstance(value, ast.Constant)
            or (isinstance(value, ast.Call) and _call_name(value.func) in _SAFE_WRAPPERS)
            for value in values
        )
    }
    changed = True
    while changed:
        changed = False
        for names, value in assignments:
            if names - scope.tainted and _taints(value, scope):
                scope.tainted |= names
                changed = True
    return scope


def _placeholder_mismatch(message: ast.AST, rest: list[ast.AST]) -> str | None:
    if not rest or not (isinstance(message, ast.Constant) and isinstance(message.value, str)):
        return None
    if any(isinstance(arg, ast.Starred) for arg in rest):
        return None
    matches = [m for m in _PLACEHOLDER.finditer(message.value) if m.group(2) != "%"]
    if any(m.group(1) for m in matches):  # %(name)s takes one mapping
        return None
    if len(matches) != len(rest):
        return f"{len(matches)} placeholder(s) but {len(rest)} argument(s)"
    return None


def _warn_aliases(tree: ast.Module) -> set[str]:
    return {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "warnings"
        for alias in node.names
        if alias.name == "warn"
    }


def _check_call(node: ast.Call, scope: _Scope, warn_names: set[str], where: str) -> list[str]:
    func = node.func
    problems: list[str] = []
    if _is_logger_call(node) or (
        (isinstance(func, ast.Name) and func.id in warn_names)
        or (isinstance(func, ast.Attribute) and func.attr == "warn" and _call_name(func.value) == "warnings")
    ):
        args = list(node.args)
        if isinstance(func, ast.Attribute) and func.attr == "log" and args:
            args = args[1:]
        if not args:
            return []
        message, *rest = args
        if not (isinstance(message, ast.Constant) and isinstance(message.value, str)):
            problems.append(f"{where}: message is not a constant string (f-string / concatenation / variable)")
        if _is_logger_call(node):
            for arg in rest:
                problems.extend(f"{where}: {part}" for part in _unsafe_parts(arg, scope))
            mismatch = _placeholder_mismatch(message, rest)
            if mismatch:
                problems.append(f"{where}: {mismatch}")
            if any(keyword.arg == "extra" for keyword in node.keywords):
                problems.append(f"{where}: extra= is not checked; pass safe positional args")
        return problems
    to_stderr = (isinstance(func, ast.Name) and func.id == "print" and any(
        keyword.arg == "file" and _is_stderr(keyword.value) for keyword in node.keywords
    )) or (isinstance(func, ast.Attribute) and func.attr == "write" and _is_stderr(func.value))
    if to_stderr:
        for arg in node.args:
            if isinstance(arg, ast.Constant):
                continue
            problems.extend(f"{where}: stderr {part}" for part in _unsafe_parts(arg, scope))
    return problems


def log_call_violations(source: str, filename: str = "<string>") -> list[str]:
    """Every log / warning / stderr call in `source` that could carry target data."""
    tree = ast.parse(source, filename=filename)
    warn_names = _warn_aliases(tree)
    problems: list[str] = []
    for nodes in _scope_nodes(tree):
        scope = _analyse(nodes)
        for node in nodes:
            if isinstance(node, ast.Call):
                problems.extend(_check_call(node, scope, warn_names, f"{filename}:{node.lineno}"))
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


def test_the_log_vocabulary_holds_every_word_of_every_log_template() -> None:
    """The safety net never registers a word of the log's own templates. Its vocabulary
    is a fast regex scan of the sources; this checks it against the AST, so a new log
    line (multi-line, `logger.log(LEVEL, ...)`, a `sink` receiver) cannot slip past it."""
    from spectre_osint.core.log_vocabulary import log_vocabulary

    vocabulary = log_vocabulary()
    missing: set[str] = set()
    templates = 0
    for path in _package_sources():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and _is_logger_call(node)):
                continue
            assert isinstance(node.func, ast.Attribute)
            args = node.args[1:] if node.func.attr == "log" else node.args
            if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
                templates += 1
                words = re.findall(r"[A-Za-z][A-Za-z0-9_]*", args[0].value)
                missing |= {f"{path.name}: {word}" for word in words if word.casefold() not in vocabulary}
    assert templates > 50
    assert missing == set()


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
import sys
logger = logging.getLogger("spectre.x")

def f(url, entity, provider, status, results):
    try:
        pass
    except Exception as exc:
        logger.warning("failed provider=%s host=%s err=%s", provider, host_ref(url), exc_label(exc))
        logger.warning("failed %s", type(exc).__name__)
        logger.info("pivot target=%s status=%s", target_ref(entity.normalized_value), status.value)
        err = exc_label(exc)
        logger.warning("provider=%s err=%s", provider, err)
    logger.info("items=%s done=%d%%", len(results), 100)
    logging.getLogger("spectre.y").debug("provider=%s", provider)
    sys.stderr.write("progress\\n")
    print("done", file=sys.stderr)
'''
    assert log_call_violations(source) == []


# Each snippet slipped past the first version of the guard (PR #18 review, item 3).
_GUARD_ESCAPES = {
    "message built in a variable": """
def f(url):
    msg = f"request failed for {url}"
    logger.warning("%s", msg)
""",
    "self.logger receiver": """
class Client:
    def f(self, url):
        self.logger.warning("url=%s", url)
""",
    "logging.getLogger(...) receiver": """
import logging
def f(url):
    logging.getLogger("spectre.http").warning("url=%s", url)
""",
    "logging module receiver": """
import logging
def f(url):
    logging.warning("url=%s", url)
""",
    "sink parameter": """
def f(sink, url):
    sink.warning("url=%s", url)
""",
    "gather(return_exceptions=True) items": """
import asyncio
async def f(jobs):
    for item in await asyncio.gather(*jobs, return_exceptions=True):
        logger.warning("%s", item)
""",
    ".get() of a denied key": """
def f(data):
    logger.warning("%s", data.get("profile_url"))
""",
    "str() of an error outside except": """
def f():
    err = make_error()
    logger.warning("%s", str(err))
""",
    "%r of a finding": """
def f(finding):
    logger.debug("%r", finding)
""",
    "%r of a request": """
def f(request):
    logger.debug("%r", request)
""",
    "print to stderr": """
import sys
def f(url):
    print("failed", url, file=sys.stderr)
""",
    "sys.stderr.write": """
import sys
def f(url):
    sys.stderr.write(f"failed {url}\\n")
""",
    "warn imported from warnings": """
from warnings import warn
def f(url):
    warn(f"failed {url}")
""",
    "reason = str(exc)": """
def f():
    try:
        pass
    except Exception as exc:
        reason = str(exc)
        logger.warning("%s", reason)
""",
    "str(exc) under a name the deny list does not know": """
def f():
    try:
        pass
    except Exception as exc:
        why = str(exc)
        logger.warning("%s", why)
""",
    "validation result .error": """
def f(data):
    authority = read_observed(data)
    logger.warning("%s", authority.error)
""",
    "placeholders and arguments disagree": """
def f(provider):
    logger.warning("%s failed: %s", provider)
""",
}


@pytest.mark.parametrize("snippet", list(_GUARD_ESCAPES.values()), ids=list(_GUARD_ESCAPES))
def test_static_guard_flags_what_the_first_version_missed(snippet: str) -> None:
    assert log_call_violations(snippet), "the guard let this leak through"


# --- the authority.error path (identity correlation) ----------------------------------------


class _Handle(BaseModel):
    handle: str

    @field_validator("handle")
    @classmethod
    def _always_fails(cls, value: str) -> str:
        raise ValueError(f"unexpected handle {value} at https://github.com/{value}")


def _validation_error_naming_the_target() -> ValidationError:
    try:
        _Handle(handle=USERNAME)
    except ValidationError as exc:
        assert USERNAME in str(exc)  # the message really carries the target
        return exc
    raise AssertionError("expected a validation error")


def test_invalid_observed_payload_logs_no_target_data(
    tmp_path: Path, capture: _Capture, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`authority.error` comes from a ValidationError whose message names the target;
    identity correlation logs it. Only the error count and type codes may reach the log."""
    from spectre_osint.core.entities import Finding
    from spectre_osint.core.types import FindingStatus
    from spectre_osint.modules.username import observed
    from spectre_osint.modules.username.identity import records_from_findings

    def failing_parse(_raw: Any) -> Any:
        raise _validation_error_naming_the_target()

    monkeypatch.setattr(observed, "parse_observed", failing_parse)
    setup_logging("DEBUG", tmp_path / "logs", console_level="DEBUG")
    finding = Finding(
        module="username",
        title="GitHub",
        status=FindingStatus.FOUND,
        summary="profile",
        data={
            "check_status": "CONFIRMED",
            "platform": "GitHub",
            "username": USERNAME,
            "profile_url": f"https://github.com/{USERNAME}",
            "observed": {"display_name": {"value": NAME}},
        },
    )
    authority = observed.read_observed(finding.data)
    assert authority.error and authority.fields is None
    (record,) = records_from_findings([finding])
    assert record.platform == "GitHub"
    raw = _assert_no_leaks(capture, tmp_path / "logs", capsys.readouterr().err, [])
    _assert_exercised(raw, ("observed enrichment failed validation", "value_error"))
