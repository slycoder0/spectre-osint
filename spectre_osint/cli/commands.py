"""CLI command implementations."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.prompt import Confirm

from spectre_osint import __version__
from spectre_osint.cli.auth_commands import auth_app
from spectre_osint.cli.cache_commands import cache_app
from spectre_osint.cli.display import (
    CliProgressReporter,
    configure_display,
    print_banner,
    print_providers,
    print_result,
)
from spectre_osint.core.case_manager import CaseManager
from spectre_osint.core.config import get_settings
from spectre_osint.core.database import init_db
from spectre_osint.core.exceptions import AuthorizationRequired, SpectreError
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.inputs import parse_target_inputs
from spectre_osint.core.logger import setup_logging
from spectre_osint.core.pipeline import InvestigationRunner
from spectre_osint.core.registry import default_registry
from spectre_osint.core.types import EntityType
from spectre_osint.modules.metadata import analyze_metadata
from spectre_osint.modules.network import authorized_connect_scan

app = typer.Typer(
    name="spectre",
    help="SPECTRE OSINT — Passive-first OSINT and Threat Intelligence.",
    no_args_is_help=True,
    add_completion=False,
)
case_app = typer.Typer(help="Investigation case management.")
app.add_typer(case_app, name="case")
app.add_typer(auth_app, name="auth")
app.add_typer(cache_app, name="cache")


def _cli_fail(message: str) -> None:
    typer.echo(message, err=True)
    raise typer.Exit(1)


def _bootstrap() -> None:
    try:
        settings = get_settings()
        setup_logging(settings.log_level, settings.logs_dir)
        init_db(settings)
    except OSError as exc:
        _cli_fail(
            f"Cannot write SPECTRE data/logs/reports ({exc.__class__.__name__}). "
            "Set SPECTRE_DATA_DIR / SPECTRE_REPORTS_DIR / SPECTRE_LOGS_DIR and run `spectre doctor`."
        )
    except Exception as exc:
        from sqlalchemy.exc import OperationalError

        if isinstance(exc, OperationalError):
            _cli_fail(
                f"Database is not writable ({type(exc).__name__}). "
                "Set SPECTRE_DATA_DIR / SPECTRE_DATABASE_URL and run `spectre doctor`."
            )
        raise


def _run(coro):
    try:
        return asyncio.run(coro)
    except SpectreError as exc:
        _cli_fail(str(exc))
    except OSError as exc:
        _cli_fail(
            f"Filesystem error ({exc.__class__.__name__}). "
            "Fix permissions or paths, then run `spectre doctor`."
        )


async def _investigate(
    target: str,
    *,
    force_type: EntityType | None = None,
    auto_pivot: bool = False,
    depth: int = 1,
    extra: dict | None = None,
    case_name: str | None = None,
    refresh: bool = False,
):
    _bootstrap()
    runner = InvestigationRunner()
    progress_reporter = CliProgressReporter()
    try:
        return await runner.run(
            target,
            force_type=force_type,
            auto_pivot=auto_pivot,
            depth=depth,
            extra=extra,
            case_name=case_name,
            refresh=refresh or bool((extra or {}).get("refresh")),
            progress=progress_reporter,
        )
    finally:
        await runner.close()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def _root(
    version_flag: bool = typer.Option(
        False,
        "--version",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the ASCII banner."),
    compact: bool = typer.Option(False, "--compact", help="Summary-oriented output."),
    verbose: bool = typer.Option(False, "--verbose", help="Full finding detail."),
) -> None:
    """SPECTRE OSINT."""
    configure_display(no_banner=no_banner, compact=compact, verbose=verbose)


@app.command()
def version() -> None:
    """Show version."""
    typer.echo(__version__)


@app.command()
def doctor(
    json_out: bool = typer.Option(False, "--json", help="Machine-readable diagnostics."),
) -> None:
    """Report whether this install is ready. Never investigates or prints secrets."""
    from spectre_osint.cli.doctor import dumps_doctor, render_doctor, run_doctor

    report = run_doctor()
    if json_out:
        typer.echo(dumps_doctor(report))
    else:
        typer.echo(render_doctor(report))
    if report.get("status") == "ACTION REQUIRED":
        raise typer.Exit(1)


@app.command()
def username(
    target: str = typer.Argument(..., help="Username to search on public sites"),
    alias: list[str] = typer.Option([], "--alias", help="Other usernames in the same case (not identity)."),
    display_name: str | None = typer.Option(None, "--name", help="Optional display/real name lead."),
    email: str | None = typer.Option(None, "--email", help="Optional public email lead."),
    website: str | None = typer.Option(None, "--website", help="Optional website or domain lead."),
    auto_pivot: bool = typer.Option(False, "--auto-pivot"),
    depth: int = typer.Option(1, "--depth", min=1, max=3),
    case_name: str | None = typer.Option(
        None, "--case", help="Add to this existing case. Default: create a new case."
    ),
    refresh: bool = typer.Option(False, "--refresh", help="Ignore result cache."),
) -> None:
    """Search a username across public sites from data/sites.yaml."""
    parsed = parse_target_inputs(
        target,
        aliases=alias,
        display_name=display_name,
        email=email,
        website=website,
        force_type=EntityType.USERNAME,
    )
    extra = {"refresh": refresh, "inputs": parsed.as_dict()}
    result = _run(
        _investigate(
            parsed.primary,
            force_type=EntityType.USERNAME,
            auto_pivot=auto_pivot,
            depth=depth,
            case_name=case_name,
            extra=extra,
        )
    )
    print_result(result)


@app.command()
def email(target: str = typer.Argument(..., help="Email address")) -> None:
    """Email OSINT (format, DNS, optional HIBP/GitHub/Gravatar)."""
    result = _run(_investigate(target, force_type=EntityType.EMAIL))
    print_result(result)


@app.command()
def domain(
    target: str = typer.Argument(..., help="Domain name"),
    auto_pivot: bool = typer.Option(False, "--auto-pivot"),
    depth: int = typer.Option(1, "--depth", min=1, max=3),
) -> None:
    """Domain intelligence: DNS, RDAP, CT, fingerprint, optional APIs."""
    result = _run(_investigate(target, force_type=EntityType.DOMAIN, auto_pivot=auto_pivot, depth=depth))
    print_result(result)


@app.command()
def ip(target: str = typer.Argument(..., help="IPv4 or IPv6 address")) -> None:
    """IP intelligence. Historical provider intel is labelled as such."""
    result = _run(_investigate(target, force_type=EntityType.IP))
    print_result(result)


@app.command("url")
def url_cmd(target: str = typer.Argument(..., help="http(s) URL")) -> None:
    """URL analysis with explainable heuristic risk."""
    result = _run(_investigate(target, force_type=EntityType.URL))
    print_result(result)


@app.command("hash")
def hash_cmd(target: str = typer.Argument(..., help="MD5/SHA1/SHA256/SHA512")) -> None:
    """Hash intelligence. Malware is never downloaded."""
    result = _run(_investigate(target, force_type=EntityType.HASH))
    print_result(result)


@app.command()
def company(target: str = typer.Argument(..., help="Company or organization name")) -> None:
    """Public company footprint (GitHub org, no employee scraping)."""
    result = _run(_investigate(target, force_type=EntityType.COMPANY))
    print_result(result)


@app.command()
def person(
    name: str = typer.Argument(..., help="Person name"),
    username_opt: str | None = typer.Option(None, "--username"),
    email_opt: str | None = typer.Option(None, "--email"),
) -> None:
    """Public-source people search. Similar profiles are possible_match only."""
    result = _run(
        _investigate(
            name,
            force_type=EntityType.PERSON,
            extra={"username": username_opt, "email": email_opt},
        )
    )
    print_result(result)


@app.command()
def metadata(path: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Extract metadata from a user-supplied file. No macros are executed."""
    _bootstrap()
    print_banner()
    bundle = analyze_metadata(path)
    for finding in bundle["findings"]:
        typer.echo(f"{finding.title}: {finding.summary}")
        for key, value in (finding.data or {}).items():
            typer.echo(f"  {key}: {value}")


@app.command()
def threat(target: str = typer.Argument(..., help="IP, domain, URL or hash")) -> None:
    """Aggregate threat intelligence for an indicator."""
    from spectre_osint.core.validators import detect_entity_type

    detected = detect_entity_type(target)
    result = _run(_investigate(target, force_type=detected))
    print_result(result)


@app.command()
def wayback(target: str = typer.Argument(..., help="Domain or URL")) -> None:
    """Wayback Machine CDX snapshots."""
    result = _run(_investigate(target, force_type=EntityType.DOMAIN))
    print_result(result)


@app.command()
def investigate(
    target: str = typer.Argument(..., help="Auto-detected target"),
    alias: list[str] = typer.Option([], "--alias", help="Other usernames in the same case (not identity)."),
    display_name: str | None = typer.Option(None, "--name", help="Optional display/real name lead."),
    email: str | None = typer.Option(None, "--email", help="Optional public email lead."),
    website: str | None = typer.Option(None, "--website", help="Optional website or domain lead."),
    auto_pivot: bool = typer.Option(False, "--auto-pivot"),
    depth: int = typer.Option(1, "--depth", min=1, max=3),
    case_name: str | None = typer.Option(
        None, "--case", help="Add to this existing case. Default: create a new case."
    ),
) -> None:
    """Full investigation pipeline with correlation, graph and HTML report."""
    parsed = parse_target_inputs(
        target, aliases=alias, display_name=display_name, email=email, website=website
    )
    extra = {"inputs": parsed.as_dict()}
    result = _run(
        _investigate(
            parsed.primary,
            force_type=parsed.primary_type,
            auto_pivot=auto_pivot,
            depth=depth,
            case_name=case_name,
            extra=extra,
        )
    )
    print_result(result)


@app.command()
def providers(
    probe: bool = typer.Option(False, "--probe", help="Cheap live health check (uses quota)."),
    name: str | None = typer.Option(None, "--name", help="Single provider name to check."),
) -> None:
    """Show provider configuration. Default is configuration-only (NOT PROBED)."""
    _bootstrap()

    async def _health():
        settings = get_settings()
        http = HttpClient(settings)
        registry = default_registry(http)
        try:
            return await registry.health(
                settings, probe=probe, names=[name] if name else None
            )
        finally:
            await http.close()

    rows = _run(_health())
    print_providers(rows)


@app.command()
def report(
    case_name: str | None = typer.Argument(None),
    fmt: str = typer.Option("html", "--format", help="html|markdown|json|csv|graphml|all"),
) -> None:
    """Regenerate artifacts from the latest completed run stored in the database."""
    _bootstrap()
    settings = get_settings()
    manager = CaseManager()
    if case_name is None:
        rows = manager.list_cases()
        active = next((r for r in rows if r.active), None)
        if active is None:
            raise typer.BadParameter("No active case. Pass a case name or run an investigation first.")
        case_name = active.name
    result = manager.load_result(case_name)
    if result is None:
        raise typer.BadParameter(f"No completed run found for case {case_name}")
    from spectre_osint.reporting.csv import write_csv_report
    from spectre_osint.reporting.graph import write_graph_exports
    from spectre_osint.reporting.html import write_html_report
    from spectre_osint.reporting.json import write_json_report
    from spectre_osint.reporting.markdown import write_markdown_report

    written: list[str] = []
    wanted = {fmt.lower()} if fmt.lower() != "all" else {"html", "markdown", "json", "csv", "graphml"}
    try:
        if "html" in wanted:
            written.append(str(write_html_report(result, settings.reports_dir)))
        if "markdown" in wanted:
            written.append(str(write_markdown_report(result, settings.reports_dir)))
        if "json" in wanted:
            written.append(str(write_json_report(result, settings.reports_dir)))
        if "csv" in wanted:
            written.append(str(write_csv_report(result, settings.reports_dir)))
        if "graphml" in wanted:
            written.append(str(write_graph_exports(result, settings.reports_dir)))
    except OSError as exc:
        _cli_fail(
            f"Reports directory is not writable ({exc.__class__.__name__}). "
            "Set SPECTRE_REPORTS_DIR and run `spectre doctor`."
        )
    for path in written:
        typer.echo(path)


@app.command("search")
def search_cmd(query: str = typer.Argument(..., help="Public web search query")) -> None:
    """Optional public web search (SearXNG / Google CSE). Username investigations do not require this."""
    _bootstrap()

    async def _run_search():
        settings = get_settings()
        http = HttpClient(settings)
        try:
            from spectre_osint.modules.search.engine import SearchEngine

            return await SearchEngine(http, settings).search(query)
        finally:
            await http.close()

    finding = _run(_run_search())
    typer.echo(f"{finding.status}: {finding.summary}")
    for item in (finding.data or {}).get("results") or []:
        typer.echo(f"  {item.get('title')}  {item.get('link')}")


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    """Start the localhost web dashboard (Deprecated: scheduled for removal in milestone 0.1.0b2)."""
    _bootstrap()
    settings = get_settings()
    bind = host or settings.web_host
    if bind not in {"127.0.0.1", "localhost", "::1"} and not settings.allow_public_bind:
        raise typer.BadParameter(
            "Dashboard is single-user and binds to 127.0.0.1. "
            "Set SPECTRE_ALLOW_PUBLIC_BIND=true only if you accept the risk."
        )
    typer.echo(
        "[DEPRECATION NOTICE] The web dashboard is deprecated and scheduled for removal in milestone 0.1.0b2. "
        "SPECTRE is transitioning to a CLI-first workstation with rich standalone HTML/JSON reporting.",
        err=True,
    )
    import uvicorn

    uvicorn.run("spectre_osint.web.app:app", host=bind, port=port, reload=False)


@app.command("dashboard")
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    """Alias for `spectre web` (Deprecated: scheduled for removal in milestone 0.1.0b2)."""
    web(host=host, port=port)


@app.command()
def network(
    target: str = typer.Argument(..., help="Host or domain"),
    authorized: bool = typer.Option(False, "--authorized", help="Required for active recon"),
) -> None:
    """Optional ACTIVE recon. Disabled by default. No exploitation."""
    _bootstrap()
    print_banner()
    if not authorized:
        raise typer.BadParameter("Active recon is disabled. Pass --authorized after confirming legal authorization.")
    console_ok = Confirm.ask(
        f"[red]ACTIVE RECON AUTHORIZED[/red] against [bold]{target}[/bold]. "
        "Confirm you are authorized to probe this host?"
    )
    if not console_ok:
        raise typer.Abort()
    try:
        bundle = _run(authorized_connect_scan(target, authorized=True))
    except AuthorizationRequired as exc:
        raise typer.BadParameter(str(exc)) from exc
    for finding in bundle["findings"]:
        typer.echo(finding.summary)
        typer.echo(finding.data)


@case_app.command("create")
def case_create(name: str, description: str = "") -> None:
    _bootstrap()
    row = CaseManager().create(name, description)
    typer.echo(f"Case ready: {row.name} ({row.id})")


@case_app.command("select")
def case_select(name: str) -> None:
    _bootstrap()
    row = CaseManager().select(name)
    if not row:
        raise typer.BadParameter(f"Unknown case {name}")
    typer.echo(f"Active case: {row.name}")


@case_app.command("list")
def case_list() -> None:
    _bootstrap()
    rows = CaseManager().list_cases()
    if not rows:
        typer.echo("No cases yet.")
        return
    for row in rows:
        flag = "*" if row.active else " "
        typer.echo(f"{flag} {row.name}  targets={row.targets}")


@case_app.command("runs")
def case_runs(name: str) -> None:
    """List investigation runs for a case."""
    _bootstrap()
    manager = CaseManager()
    match = next((r for r in manager.list_cases() if r.name == name), None)
    if match is None:
        raise typer.BadParameter(f"Unknown case {name}")
    runs = manager.list_runs(match.id)
    if not runs:
        typer.echo("No runs.")
        return
    for run in runs:
        typer.echo(f"{run.id}  {run.status}  {run.target}  depth={run.depth}")


@case_app.command("rollback")
def case_rollback(run_id: str) -> None:
    """Delete findings/evidence/relationships for a run. Does not undo files on disk."""
    _bootstrap()
    if not CaseManager().rollback_run(run_id):
        raise typer.BadParameter(f"Unknown run {run_id}")
    typer.echo(f"Rolled back run {run_id}")
