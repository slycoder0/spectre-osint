"""Rich renderers for compact terminal output (B2-06).

Renderers take language-neutral views from `spectre_osint/services/views.py` and decide
wording (through `core/i18n.py`), layout and color. They never compute facts.

Everything a target page controls (names, platform labels, URLs) is untrusted: it is
stripped of control characters and bidi overrides by `clean_text()` and printed as
`rich.text.Text`, so it can neither inject Rich markup nor terminal escape sequences.
"""

from __future__ import annotations

import re

from rich.cells import cell_len
from rich.console import Console
from rich.text import Text

from spectre_osint import __version__
from spectre_osint.cli.theme import BANNER_ART, BANNER_SEPARATOR, Theme
from spectre_osint.core.i18n import t, tn
from spectre_osint.services.views import UsernameView

# Line breaks, including the Unicode line/paragraph separators, become one space.
_SPACE_CONTROLS = re.compile("[\t\n\r\x0b\x0c  ]")
# C0/C1 controls (ESC included), DEL, and the bidi marks/overrides/isolates that can
# visually reorder a line ("Trojan Source").
_STRIP = re.compile("[\x00-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩]")


def clean_text(value: object) -> str:
    """Untrusted text made safe to print on one terminal line."""
    return _STRIP.sub("", _SPACE_CONTROLS.sub(" ", str(value or "")))


def _print(console: Console, *parts: str | tuple[str, str]) -> None:
    console.print(Text.assemble(*parts), soft_wrap=True)


def _banner_rows(theme: Theme) -> list[tuple[str, str]]:
    """(art, text) per banner line: Unicode art on capable terminals, ASCII otherwise."""
    tagline = t("cli.banner.tagline")
    if theme.unicode:
        return [
            (BANNER_ART[0], ""),
            (BANNER_ART[1], f"  OSINT {BANNER_SEPARATOR} v{__version__}"),
            (BANNER_ART[2], f"  {tagline}"),
        ]
    title = f"SPECTRE // OSINT  v{__version__}"
    return [(title, ""), ("", tagline), ("-" * max(len(title), len(tagline)), "")]


def banner_lines(theme: Theme) -> list[str]:
    """The 3-line banner as plain text."""
    return [art + text for art, text in _banner_rows(theme)]


def render_banner(console: Console, theme: Theme) -> None:
    """Print the banner and one blank line. Callers decide whether it is wanted."""
    for art, text in _banner_rows(theme):
        _print(console, (art, theme.style("banner")), (text, theme.style("muted")))
    console.print()


def _unverified_line(view: UsernameView, *, verbose: bool) -> str:
    counts = view.unverified
    line = tn("username.unverified", counts.total)
    details = [tn(f"username.bucket.{name}", count) for name, count in counts.buckets()]
    if details:
        line = f"{line}: {', '.join(details)}"
    if counts.total and not verbose:
        line = f"{line} {t('username.unverified_hint')}"
    return line


def render_username(
    view: UsernameView,
    console: Console,
    *,
    verbose: bool = False,
    theme: Theme | None = None,
) -> None:
    """Compact username result: found profiles, per-platform names, unverified count.

    The unverified line is printed unconditionally, `0` included: hiding it would
    present "not checked" as "not there". `theme` decides icons and color (default:
    plain, ASCII icons and no style); untrusted values (URLs, names) are never styled.
    """
    theme = theme or Theme.plain()
    _print(
        console,
        (
            tn(
                "username.summary",
                len(view.found),
                target=clean_text(view.target),
                checked=view.checked,
            ),
            theme.style("title"),
        ),
    )
    platforms = [clean_text(profile.platform) for profile in view.found]
    width = max((cell_len(name) for name in platforms), default=0)
    for profile, platform in zip(view.found, platforms, strict=True):
        role = "uncertain" if profile.likely else "found"
        parts: list[str | tuple[str, str]] = [
            "  ",
            (theme.icon(role), theme.style(role)),
            " ",
            (platform, theme.style("platform")),
        ]
        url = clean_text(profile.url)
        if url:
            parts.append(" " * (width - cell_len(platform) + 2))
            parts.append(url)
        if profile.likely:
            parts.append((f" {t('username.likely')}", theme.style("muted")))
        _print(console, *parts)

    if view.names:
        console.print()
        _print(console, (t("username.names_header"), theme.style("title")))
        for observed in view.names:
            _print(
                console,
                "  ",
                (clean_text(observed.platform), theme.style("platform")),
                f": {clean_text(observed.name)}",
            )

    console.print()
    style = theme.style("unknown" if view.unverified.total else "muted")
    line = f"{theme.icon('unknown')} {_unverified_line(view, verbose=verbose)}"
    _print(console, (line, style))
    if view.report_path:
        _print(console, (t("username.report", path=clean_text(view.report_path)), theme.style("muted")))
