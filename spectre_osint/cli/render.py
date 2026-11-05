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

from spectre_osint.core.i18n import t, tn
from spectre_osint.services.views import UsernameView

_SPACE_CONTROLS = re.compile(r"[\t\n\r\x0b\x0c]")
# C0/C1 controls (ESC included), DEL, and the bidi marks/overrides/isolates that can
# visually reorder a line ("Trojan Source").
_STRIP = re.compile("[\x00-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩]")


def clean_text(value: object) -> str:
    """Untrusted text made safe to print on one terminal line."""
    return _STRIP.sub("", _SPACE_CONTROLS.sub(" ", str(value or "")))


def _print(console: Console, *parts: str | tuple[str, str]) -> None:
    console.print(Text.assemble(*parts), soft_wrap=True)


def _unverified_line(view: UsernameView, *, verbose: bool) -> str:
    counts = view.unverified
    line = tn("username.unverified", counts.total)
    details = [tn(f"username.bucket.{name}", count) for name, count in counts.buckets()]
    if details:
        line = f"{line}: {', '.join(details)}"
    if counts.total and not verbose:
        line = f"{line} {t('username.unverified_hint')}"
    return line


def render_username(view: UsernameView, console: Console, *, verbose: bool = False) -> None:
    """Compact username result: found profiles, per-platform names, unverified count.

    The unverified line is printed unconditionally, `0` included: hiding it would
    present "not checked" as "not there".
    """
    _print(
        console,
        (
            tn(
                "username.summary",
                len(view.found),
                target=clean_text(view.target),
                checked=view.checked,
            ),
            "bold",
        ),
    )
    platforms = [clean_text(profile.platform) for profile in view.found]
    width = max((cell_len(name) for name in platforms), default=0)
    for profile, platform in zip(view.found, platforms, strict=True):
        parts: list[str | tuple[str, str]] = ["  ", (platform, "cyan")]
        url = clean_text(profile.url)
        if url:
            parts.append(" " * (width - cell_len(platform) + 2))
            parts.append(url)
        if profile.likely:
            parts.append((f" {t('username.likely')}", "dim"))
        _print(console, *parts)

    if view.names:
        console.print()
        _print(console, (t("username.names_header"), "bold"))
        for observed in view.names:
            _print(console, "  ", (clean_text(observed.platform), "cyan"), f": {clean_text(observed.name)}")

    console.print()
    style = "yellow" if view.unverified.total else "dim"
    _print(console, (_unverified_line(view, verbose=verbose), style))
    if view.report_path:
        _print(console, (t("username.report", path=clean_text(view.report_path)), "dim"))
