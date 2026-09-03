"""Rich console rendering for investigation results."""

from __future__ import annotations

import os
import shutil
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from spectre_osint import __version__
from spectre_osint.core.entities import InvestigationResult
from spectre_osint.core.presentation import (
    mention_findings,
    mention_relevance_counts,
    username_counts,
    username_rows,
)
from spectre_osint.core.timefmt import relative_age
from spectre_osint.core.types import FindingStatus
from spectre_osint.modules.search.summary import build_intelligence_summary

console = Console(highlight=False)

_NO_BANNER = False
_COMPACT = False
_VERBOSE = False

BANNER_WIDE = r"""
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
           O S I N T   I N T E L L I G E N C E
"""

BANNER_NARROW = "SPECTRE  ·  OSINT INTELLIGENCE"

STATUS_STYLE = {
    "CONFIRMED": "bold green",
    "LIKELY": "cyan",
    "FOUND": "green",
    "NOT_FOUND": "dim",
    "INCONCLUSIVE": "yellow",
    "LOGIN_REQUIRED": "yellow",
    "BLOCKED": "red",
    "PROVIDER_UNAVAILABLE": "magenta",
    "RATE_LIMITED": "yellow",
    "SESSION_EXPIRED": "yellow",
    "CHALLENGE_REQUIRED": "magenta",
    "CAPTCHA_REQUIRED": "magenta",
    "TEMPORARILY_LIMITED": "yellow",
    "OAUTH_BROWSER_REJECTED": "magenta",
    "PLAYWRIGHT_SESSION": "cyan",
    "OFFICIAL_API": "cyan",
    "BOTH": "cyan",
    "CHROME_CDP_SESSION": "cyan",
    "CHROME_NOT_FOUND": "red",
    "CDP_UNAVAILABLE": "red",
    "CHROME_PROFILE_LOCKED": "yellow",
    "WINDOWS_CDP_LAUNCH_FAILED": "red",
    "UNSUPPORTED": "dim",
    "NOT_CONFIGURED": "yellow",
    "ERROR": "red",
    "ACTIVE": "bold green",
    "EXPIRED": "yellow",
    "CACHED": "cyan",
    "LIVE": "green",
    "AUTHENTICATED_PUBLIC": "magenta",
    "ANONYMOUS_PUBLIC": "dim",
}


def configure_display(*, no_banner: bool = False, compact: bool = False, verbose: bool = False) -> None:
    global _NO_BANNER, _COMPACT, _VERBOSE
    _NO_BANNER = no_banner
    _COMPACT = compact
    _VERBOSE = verbose


def _want_banner() -> bool:
    if _NO_BANNER or os.environ.get("SPECTRE_NO_BANNER"):
        return False
    if os.environ.get("NO_BANNER"):
        return False
    return True


def print_banner() -> None:
    if not _want_banner():
        return
    width = shutil.get_terminal_size(fallback=(80, 24)).columns
    art = BANNER_WIDE if width >= 70 else BANNER_NARROW
    console.print(art, style="bold green")
    console.print(f"[dim]v{__version__}  ·  passive-first  ·  localhost[/dim]\n")


class CliProgressReporter:
    """Factual, non-spamming CLI progress presenter."""

    PHASE_TITLES = {
        "catalog": "Checking public profiles...",
        "mentions": "Searching public mentions...",
        "search": "Searching public web...",
        "discovery": "Analyzing discovery pivots...",
        "correlation": "Correlating evidence...",
        "scoring": "Scoring findings...",
        "report": "Generating report...",
        "collecting": "Collecting intelligence...",
        "normalizing": "Normalizing evidence...",
    }

    def __init__(self, console_instance: Console | None = None) -> None:
        self.console = console_instance or console
        self.current_phase: str | None = None
        self._reported_degraded: set[str] = set()
        self._last_catalog_reported: int = 0

    def __call__(self, payload: dict[str, Any]) -> None:
        phase = str(payload.get("phase") or "")
        state = str(payload.get("state") or "running")
        current = payload.get("current") if payload.get("current") is not None else payload.get("done")
        total = payload.get("total")
        provider = payload.get("provider") or payload.get("source")
        message = payload.get("message")

        # Phase transition
        if phase and phase != self.current_phase and state == "running":
            self.current_phase = phase
            msg = self.PHASE_TITLES.get(phase)
            if msg:
                if phase == "catalog" and total:
                    self.console.print(f"[cyan]•[/cyan] {msg} [dim](0/{total})[/dim]")
                else:
                    self.console.print(f"[cyan]•[/cyan] {msg}")

        # Catalog progress updates (print step milestones without flooding terminal)
        if phase == "catalog" and current is not None and total:
            curr_int = int(current)
            tot_int = int(total)
            if curr_int == tot_int or (curr_int > 0 and curr_int - self._last_catalog_reported >= 15):
                self._last_catalog_reported = curr_int
                self.console.print(f"  [dim]{curr_int}/{tot_int} checked[/dim]")

        # Degraded provider updates (printed once per provider to avoid spam)
        if state == "degraded":
            key = f"{phase}:{provider}:{message}"
            if key not in self._reported_degraded:
                self._reported_degraded.add(key)
                detail = message or f"{provider} unavailable; continuing"
                self.console.print(f"  [yellow][!][/yellow] {detail}")


def style_status(status: str) -> str:
    color = STATUS_STYLE.get(status, "white")
    return f"[{color}]{status}[/]"


def print_result(result: InvestigationResult) -> None:
    print_banner()
    kind = result.target_type.value if hasattr(result.target_type, "value") else str(result.target_type)
    header = (
        f"[bold]Target[/bold]        {result.target}\n"
        f"[bold]Mode[/bold]          {result.mode}\n"
        f"[bold]Case[/bold]          {result.case_name}\n"
        f"[bold]Started[/bold]       {result.started_at}"
    )
    console.print(
        Panel(header, title=f"SPECTRE / {kind}", border_style="cyan", padding=(0, 1))
    )

    if not _COMPACT:
        modules_ok = sorted({f.module for f in result.findings if f.status == FindingStatus.FOUND})
        for name in modules_ok:
            console.print(f"[green][+][/green] {name}")
        missing = sorted({f.module for f in result.findings if f.status == FindingStatus.NOT_CONFIGURED})
        for name in missing:
            console.print(f"[yellow][!][/yellow] {name}: Provider not configured")
            if name == "search":
                console.print("    Optional. Set loopback SEARXNG_URL or continue without search indexes.")
            else:
                console.print("    Optional API key missing. Investigation continues. Run `spectre doctor`.")
        unavailable = [f for f in result.findings if f.status == FindingStatus.PROVIDER_UNAVAILABLE]
        for finding in unavailable:
            console.print(f"[red][!][/red] {finding.module}")
            console.print(f"    Reason: {finding.summary}")
            summary = finding.summary or ""
            if "429" in summary:
                console.print("    Action: Rate limited. Wait and retry. SPECTRE does not rotate IPs.")
            elif "403" in summary or "401" in summary:
                console.print("    Action: Provider rejected the request. Check the API key; SPECTRE will not bypass.")
            else:
                console.print("    Continuing investigation...")
        limited = [f for f in result.findings if f.status == FindingStatus.RATE_LIMITED]
        for finding in limited:
            console.print(f"[yellow][!][/yellow] {finding.module}: RATE_LIMITED")
            console.print("    Action: HTTP 429 / quota. Wait and retry. SPECTRE does not bypass limits.")

    rows = username_rows(result)
    if rows:
        _print_username(result, rows)
        _print_mentions_summary(result)
        if not _COMPACT:
            _print_discovery(result)
            _print_intelligence_summary(result)
    elif not _COMPACT:
        table = Table(title="Findings", show_lines=False, expand=True)
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Status")
        table.add_column("Summary")
        for finding in result.findings[:40]:
            table.add_row(
                finding.module,
                style_status(finding.status.value),
                finding.summary[:140],
            )
        console.print(table)

    if _VERBOSE or not rows:
        ent = Table(title="Entities")
        ent.add_column("Type")
        ent.add_column("Value")
        ent.add_column("Confidence")
        ent.add_column("Source")
        for entity in result.entities[:40]:
            ent.add_row(entity.type.value, entity.normalized_value, entity.confidence.value, entity.source)
        console.print(ent)

    if result.scores and not _COMPACT:
        scores = result.scores
        bd = scores.confidence_breakdown or {}
        bd_lines = [f"  {k}: {v:+d}" for k, v in bd.items()]
        console.print(
            Panel(
                f"confidence_score = {scores.confidence_score}\n"
                f"risk_score       = {scores.risk_score} ({scores.risk_level})\n"
                f"reputation_score = {scores.reputation_score}\n\n"
                + "confidence breakdown:\n"
                + "\n".join(bd_lines or scores.confidence_explain)
                + "\n\n"
                + "\n".join(scores.confidence_explain + scores.risk_explain),
                title="Scoring (this investigation only)",
            )
        )
    if result.pivots and (_VERBOSE or not _COMPACT):
        console.print("[bold]Possible pivots[/bold]")
        for i, pivot in enumerate(result.pivots, 1):
            console.print(f"  {i}. {pivot.action}: [cyan]{pivot.target}[/cyan] — {pivot.reason}")
    console.print(f"\nEntities discovered: {len(result.entities)}")
    console.print(f"Relationships: {len(result.relationships)}")
    console.print(f"Providers queried: {len(result.providers_queried)}")
    if result.report_path:
        console.print(f"\n[bold]Report:[/bold] {result.report_path}")


def _print_username(result: InvestigationResult, rows: list[dict]) -> None:
    counts = username_counts(result)
    total = max(len(rows), 1)
    if not _COMPACT:
        table = Table(title="Username platforms", show_lines=False, expand=True)
        table.add_column("#", style="dim", no_wrap=True)
        table.add_column("Platform", style="cyan", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Confidence")
        table.add_column("Access")
        table.add_column("Cache")
        table.add_column("URL")
        if _VERBOSE:
            table.add_column("Detail")
        for idx, row in enumerate(rows, 1):
            cache_label = row.get("cache_state") or "LIVE"
            if cache_label == "CACHED":
                cache_label = f"CACHED · checked {relative_age(row.get('checked_at'))}"
            url = row["profile_url"] or "-"
            values = [
                f"{idx:02d}/{total:02d}",
                row["platform"],
                style_status(row["status"]),
                row["confidence"] or "-",
                style_status(row.get("access_mode") or "ANONYMOUS_PUBLIC"),
                cache_label,
                url,
            ]
            if _VERBOSE:
                values.append((row["detail"] or "")[:80])
            table.add_row(*values)
        console.print(table)
    console.print(
        Panel(
            f"Checked             {counts['checked']}\n"
            f"Confirmed           {counts['confirmed']}\n"
            f"Likely              {counts['likely']}\n"
            f"Not found           {counts['not_found']}\n"
            f"Blocked             {counts['blocked']}\n"
            f"Login required      {counts['login_required']}\n"
            f"Unavailable         {counts['provider_unavailable']}",
            title="USERNAME SUMMARY",
            border_style="green",
        )
    )
    _print_identity_correlation(result)


def _print_discovery(result: InvestigationResult) -> None:
    summary = build_intelligence_summary(result)
    gain = summary.get("discovery_gain") or {}
    discoveries = list(summary.get("new_discoveries") or [])
    if not any(gain.values()) and not discoveries:
        cov = summary.get("coverage") or {}
        if not cov.get("queries_issued"):
            return
    lines = [
        f"Operator inputs: {gain.get('operator_inputs', 0)}",
        f"Novel indicators: {gain.get('novel_indicators', 0)}",
        f"New handles: {gain.get('new_handles', 0)}",
        f"New external domains: {gain.get('new_external_domains', 0)}",
        f"New profile candidates: {gain.get('new_profile_candidates', 0)}",
        f"Redundant pivots suppressed: {gain.get('redundant_pivots_suppressed', 0)}",
    ]
    if discoveries:
        lines.append("Top discoveries:")
        for idx, item in enumerate(discoveries[:5], 1):
            value = item.get("value")
            kind = item.get("type")
            label = f"@{value}" if kind == "username" else value
            reason = item.get("reason") or item.get("source") or ""
            lines.append(f"  {idx}. {label}  ({kind}; {reason})")
    elif not gain.get("novel_indicators"):
        lines.append("No public identity discovered beyond operator inputs.")
    console.print(Panel("\n".join(lines), title="DISCOVERY GAIN", border_style="cyan"))


def _print_intelligence_summary(result: InvestigationResult) -> None:
    summary = build_intelligence_summary(result)
    names = ", ".join(summary.get("observed_names") or []) or "Insufficient evidence"
    handles = ", ".join(f"@{item}" for item in (summary.get("observed_handles") or [])) or "Insufficient evidence"
    profiles = ", ".join(summary.get("observed_profiles") or []) or "Insufficient evidence"
    geo = ", ".join(summary.get("geographic_indicators") or []) or "None confidently observed"
    mentions = summary.get("mentions") or {}
    nxt = "\n".join(f"• {item}" for item in (summary.get("next_pivots") or []))
    console.print(
        Panel(
            f"Observed name        {names}\n"
            f"Observed handles     {handles}\n"
            f"Observed profiles    {profiles}\n"
            f"Public mentions      {summary.get('mentions_total', 0)}"
            f"  ({mentions.get('ASSOCIATED', 0)} associated, {mentions.get('AMBIGUOUS', 0)} ambiguous)\n"
            f"Geographic           {geo}\n"
            f"Correlation          {summary.get('correlation')}\n"
            f"Next useful pivots\n{nxt}",
            title="INTELLIGENCE SUMMARY",
            border_style="green",
        )
    )


def _print_mentions_summary(result: InvestigationResult) -> None:
    findings = mention_findings(result)
    if not findings:
        return
    counts = mention_relevance_counts(result)
    lines = [
        f"Direct: {counts['DIRECT']}",
        f"Associated: {counts['ASSOCIATED']}",
        f"Ambiguous: {counts['AMBIGUOUS']}",
    ]
    if not _COMPACT:
        ranked = []
        for finding in findings:
            data = finding.data or {}
            relevance = str(data.get("relevance") or "")
            if relevance not in {"DIRECT", "ASSOCIATED"}:
                continue
            ranked.append((0 if relevance == "DIRECT" else 1, data))
        ranked.sort(key=lambda item: item[0])
        for _rank, data in ranked[:5]:
            title = str(data.get("title") or "Public mention")[:72]
            query = str(data.get("query") or "")
            lines.append(f"  {data.get('relevance')}  {query}  {title}")
        if counts["AMBIGUOUS"] or len(ranked) > 5:
            lines.append("  Full list: HTML report")
    console.print(Panel("\n".join(lines), title="PUBLIC MENTIONS", border_style="cyan"))


def _print_identity_correlation(result: InvestigationResult) -> None:
    payload = getattr(result, "identity_correlation", None) or {}
    if int(payload.get("records") or 0) < 2:
        return
    lines = [f"Max pairwise score: {payload.get('max_score', 0)} (same username is not identity)"]
    for cluster in payload.get("clusters") or []:
        names = ", ".join(cluster.get("platforms") or [])
        lines.append(f"Cluster {cluster.get('band')} {cluster.get('score')}: {names}")
        if cluster.get("evidence"):
            lines.append("  + " + ", ".join(cluster["evidence"]))
        if cluster.get("conflicts"):
            lines.append("  - " + ", ".join(cluster["conflicts"]))
    leftover = payload.get("unclustered") or []
    if leftover:
        lines.append("Unclustered: " + ", ".join(leftover))
    console.print(Panel("\n".join(lines), title="IDENTITY CORRELATION", border_style="cyan"))


def print_providers(rows: list) -> None:
    table = Table(title="SPECTRE providers")
    table.add_column("Provider")
    table.add_column("Type")
    table.add_column("Configured")
    table.add_column("Probed")
    table.add_column("Available", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Rate limit")
    table.add_column("Last check", overflow="ellipsis")
    for row in rows:
        table.add_row(
            row.name,
            getattr(row, "key_type", "KEYLESS"),
            getattr(row, "configured_label", "N/A" if not row.requires_key else ("YES" if row.configured else "NO")),
            "YES" if getattr(row, "probed", False) else "NO",
            "YES" if row.available is True else "NO" if row.available is False else "NOT PROBED",
            row.status,
            row.rate_limit,
            getattr(row, "last_check", None) or "",
        )
    Console(width=160, force_terminal=True).print(table)


def print_auth_status(rows: list[dict]) -> None:
    table = Table(title="Authenticated public sources")
    table.add_column("Platform")
    table.add_column("Capability")
    table.add_column("Session")
    table.add_column("Browser")
    table.add_column("Last check")
    table.add_column("Mode")
    suggestions: list[str] = []
    for row in rows:
        last = relative_age(row.get("last_verified")) if row.get("last_verified") else "—"
        table.add_row(
            row["platform"],
            style_status(row.get("capability") or "—"),
            style_status(row["session"]),
            row.get("browser_login") or "—",
            last if row["session"] != "NOT_CONFIGURED" else "—",
            row.get("mode") or "—",
        )
        hint = row.get("suggestion") or ""
        if hint:
            suggestions.append(f"{row['platform']}: {hint}")
    console.print(table)
    for line in suggestions:
        console.print(f"[dim]{line}[/dim]")
