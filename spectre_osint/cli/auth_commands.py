"""CLI: spectre auth login|logout|verify|list|status|clear."""

from __future__ import annotations

import asyncio

import typer
from rich.panel import Panel

from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.manager import resolve_browser_kind
from spectre_osint.browser.models import (
    ANONYMOUS_LOOKUP_UNAFFECTED,
    AUTH_PLATFORMS,
    normalize_platform,
    official_api_suggestion,
)
from spectre_osint.cli.display import console, print_auth_status, print_banner
from spectre_osint.core.config import get_settings
from spectre_osint.core.database import init_db
from spectre_osint.core.logger import setup_logging
from spectre_osint.core.types import SessionStatus

auth_app = typer.Typer(help="Authenticated public OSINT sessions. Never stores passwords.")


def _service() -> AuthService:
    settings = get_settings()
    setup_logging(settings.log_level, settings.logs_dir)
    init_db(settings)
    return AuthService(settings)


@auth_app.command("status")
def auth_status() -> None:
    """Show session status for supported platforms. Cookies are never printed."""
    print_banner()
    print_auth_status(_service().status_rows())


@auth_app.command("list")
def auth_list() -> None:
    """List auth platforms and local session state."""
    auth_status()


@auth_app.command("login")
def auth_login(
    platform: str = typer.Argument(..., help="instagram|facebook|threads|tiktok|x|twitch"),
    profile_name: str = typer.Option("osint-research", "--profile"),
    keep_open: bool = typer.Option(False, "--keep-open"),
    timeout: int = typer.Option(300, "--timeout", min=30, max=1800),
    browser: str = typer.Option(
        "auto",
        "--browser",
        help="auto|playwright|chrome  (chrome = SPECTRE-owned Google Chrome via CDP)",
    ),
    attach: bool = typer.Option(
        False,
        "--attach",
        help="Attach to an already-open SPECTRE Chrome CDP session (never personal Chrome).",
    ),
) -> None:
    """Open a visible browser. Log in manually. SPECTRE never sees the password."""
    try:
        slug = normalize_platform(platform)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    spec = AUTH_PLATFORMS[slug]
    print_banner()
    console.print(
        Panel(
            f"[bold]SPECTRE AUTH[/bold]\n{spec.display_name} · AUTHENTICATED_PUBLIC · {spec.auth_capability.value}",
            border_style="magenta",
        )
    )
    service = _service()
    if not service.allows_browser_login(slug):
        profile = asyncio.run(
            service.login(
                slug,
                profile_name=profile_name,
                timeout_s=float(timeout),
                keep_open=keep_open,
                browser=browser,
                attach=attach,
            )
        )
        _print_login_failure(spec, profile.status)
        raise typer.Exit(code=1)
    kind = resolve_browser_kind(spec, browser, get_settings())
    if kind == "chrome" and attach:
        console.print("Attaching to SPECTRE-owned Chrome CDP...")
        console.print("Personal Chrome/Edge is never used.")
    elif kind == "chrome":
        console.print("Opening SPECTRE-owned Chrome profile...")
        console.print("Log in manually.")
        console.print("SPECTRE will connect only after authentication.")
        console.print("[dim]CDP is loopback-only. Personal Chrome/Edge is never used.[/dim]")
    else:
        console.print("Opening SPECTRE-owned Chromium profile (not your personal Chrome).")
        console.print("Log in manually using the opened browser. SPECTRE never reads the password.")
        console.print("[dim]The login form is not reloaded while waiting.[/dim]")
    console.print("[yellow][ WAITING FOR AUTHENTICATION ][/yellow]")
    console.print("[dim]2FA, if prompted, must be completed by you. CAPTCHA is never solved.[/dim]")
    profile = asyncio.run(
        service.login(
            slug,
            profile_name=profile_name,
            timeout_s=float(timeout),
            keep_open=keep_open,
            browser=browser,
            attach=attach,
        )
    )
    if profile.status != SessionStatus.ACTIVE:
        _print_login_failure(spec, profile.status)
        raise typer.Exit(code=1)
    console.print("[green]✓ Authentication detected[/green]")
    console.print("[green]✓ Session state saved[/green]")
    console.print(f"\nPlatform:\n{spec.display_name}")
    console.print(f"\nProfile:\n{profile.profile_name}")
    console.print("\nSession:\nACTIVE")
    console.print(f"\nLast verified:\n{profile.last_verified}")
    if not profile.keyring_available:
        console.print("[yellow]Warning:[/yellow] system keyring unavailable; session file mode 0600.")


def _print_login_failure(spec, status: SessionStatus) -> None:
    console.print(f"[red]Authentication not established:[/red] {status.value}")
    if status == SessionStatus.CAPTCHA_REQUIRED:
        console.print("CAPTCHA_REQUIRED — SPECTRE will not solve it.")
    elif status == SessionStatus.CHALLENGE_REQUIRED:
        console.print("CHALLENGE_REQUIRED — SPECTRE will not bypass it.")
    elif status == SessionStatus.TEMPORARILY_LIMITED:
        console.print("TEMPORARILY_LIMITED — SPECTRE will not retry or bypass this limit.")
    elif status == SessionStatus.OAUTH_BROWSER_REJECTED:
        console.print("OAUTH_BROWSER_REJECTED — Google/OAuth refused this automated Chromium session.")
        console.print("SPECTRE does not hide automation and will not bypass this control.")
    elif status == SessionStatus.BLOCKED:
        console.print("BLOCKED — SPECTRE will not bypass the block.")
    elif status == SessionStatus.EXPIRED:
        console.print("SESSION_EXPIRED — manual login required.")
    elif status == SessionStatus.UNAVAILABLE:
        console.print("Browser login is unavailable for this platform.")
    elif status == SessionStatus.CHROME_NOT_FOUND:
        console.print("CHROME_NOT_FOUND — Google Chrome was not found. Edge is not used automatically.")
        console.print("Install Google Chrome or set SPECTRE_CHROME_PATH, then run `spectre doctor`.")
    elif status == SessionStatus.CDP_UNAVAILABLE:
        console.print("CDP_UNAVAILABLE — Chrome DevTools Protocol was not reachable on loopback.")
        console.print("Close leftover SPECTRE Chrome windows, then retry or run `spectre doctor`.")
    elif status == SessionStatus.CHROME_PROFILE_LOCKED:
        console.print(
            "CHROME_PROFILE_LOCKED — SPECTRE Chrome is open without a usable CDP endpoint. "
            "Close that SPECTRE window (not personal Chrome). A previous WSL launch may have failed."
        )
    elif status == SessionStatus.WINDOWS_CDP_LAUNCH_FAILED:
        console.print("WINDOWS_CDP_LAUNCH_FAILED — Chrome opened but CDP did not listen.")
        console.print("Close the SPECTRE Chrome window, then either:")
        console.print("  1) In Windows PowerShell run %USERPROFILE%\\.spectre\\launchers\\Start-SpectreChrome.ps1")
        console.print("  2) spectre auth login <platform> --browser chrome --attach")
    suggestion = official_api_suggestion(spec)
    if suggestion:
        console.print(suggestion)
    console.print(ANONYMOUS_LOOKUP_UNAFFECTED)


@auth_app.command("logout")
def auth_logout(platform: str = typer.Argument(...)) -> None:
    """Remove the local session. Does not change the remote account."""
    service = _service()
    try:
        service.logout(platform)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print("Local SPECTRE session cleared.")
    console.print("Browser profile removed or already absent.")
    console.print("Personal Chrome untouched.")


@auth_app.command("clear")
def auth_clear(platform: str = typer.Argument(...)) -> None:
    """Alias for logout — delete local session files only."""
    auth_logout(platform)


@auth_app.command("verify")
def auth_verify(platform: str = typer.Argument(...)) -> None:
    """Check whether a saved session is still valid. Never logs in automatically."""
    service = _service()
    try:
        profile = asyncio.run(service.verify(platform))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if profile.status == SessionStatus.EXPIRED:
        console.print("SESSION_EXPIRED")
        console.print("Session expired — manual login required")
        raise typer.Exit(code=1)
    console.print(f"{profile.platform}: {profile.status.value}")
    if profile.status in {
        SessionStatus.CDP_UNAVAILABLE,
        SessionStatus.CHROME_NOT_FOUND,
        SessionStatus.CHROME_PROFILE_LOCKED,
        SessionStatus.WINDOWS_CDP_LAUNCH_FAILED,
    }:
        raise typer.Exit(code=1)
