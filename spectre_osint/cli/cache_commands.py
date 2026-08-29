"""CLI: spectre cache status|clear — OSINT result cache, not auth sessions."""

from __future__ import annotations

import typer
from rich.table import Table

from spectre_osint.cli.display import console, print_banner
from spectre_osint.core.config import get_settings
from spectre_osint.core.result_cache import ResultCache

cache_app = typer.Typer(help="OSINT result cache. Distinct from authenticated sessions.")


@cache_app.command("status")
def cache_status() -> None:
    print_banner()
    settings = get_settings()
    cache = ResultCache(settings)
    rows = cache.status()
    table = Table(title="Result cache")
    table.add_column("Kind")
    table.add_column("Provider")
    table.add_column("Subject")
    table.add_column("Access")
    table.add_column("Checked")
    table.add_column("TTL left")
    if not rows:
        console.print("[dim]Result cache is empty.[/dim]")
        console.print(f"[dim]HTTP cache dir: {settings.cache_dir}[/dim]")
        return
    for row in rows:
        table.add_row(
            row["kind"],
            row["provider"],
            row["subject"],
            row["access_mode"] or "—",
            str(row["checked_at"]),
            "expired" if row["expired"] else f"{row['ttl_remaining']}s",
        )
    console.print(table)
    cache.close()


@cache_app.command("clear")
def cache_clear(
    provider: str | None = typer.Option(None, "--provider", help="Clear one provider only."),
) -> None:
    settings = get_settings()
    cache = ResultCache(settings)
    deleted = cache.clear(provider)
    cache.close()
    if provider:
        console.print(f"Cleared {deleted} result-cache rows for provider {provider}.")
    else:
        console.print(f"Cleared {deleted} result-cache rows.")
