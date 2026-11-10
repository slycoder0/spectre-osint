"""Central terminal theme (Phase 3A): colors, styles and icons in one place.

Color is used sparingly: found profiles, platform names and the unverified count. Every
renderer asks the theme for a *role* (`found`, `platform`, `muted`...) instead of
hard-coding a Rich style, so the menu (Phase 3B) and the CLI look the same.

Three icons carry meaning, always next to words that say the same thing:

=========  =======  =====  =================================================
role       Unicode  ASCII  meaning
=========  =======  =====  =================================================
found      ✔        [+]    profile found (CONFIRMED)
uncertain  ◐        [~]    uncertain (LIKELY profile)
unknown    ?        [?]    unknown: not verified (blocked, login, rate limit…)
=========  =======  =====  =================================================

Switches, any of which gives the plain theme (no color, ASCII icons, no banner):

- `--plain`;
- `NO_COLOR` set to a non-empty value (https://no-color.org);
- stdout is not a terminal (pipes, redirects, scripts).

On a terminal whose encoding cannot print the Unicode icons (e.g. a legacy `cp1252` /
`cp437` console) the icons fall back to ASCII automatically; color stays on.
"""

from __future__ import annotations

import codecs
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

UNICODE_ICONS: dict[str, str] = {"found": "✔", "uncertain": "◐", "unknown": "?"}
ASCII_ICONS: dict[str, str] = {"found": "[+]", "uncertain": "[~]", "unknown": "[?]"}

# Semantic roles -> Rich styles. Kept short on purpose: color with moderation.
STYLES: dict[str, str] = {
    "title": "bold",
    "found": "bold green",
    "platform": "cyan",
    "uncertain": "yellow",
    "unknown": "yellow",
    "muted": "dim",
    "banner": "bold green",
    "accent": "green",
}

# Small 3-line banner (shown by `spectre username` on a terminal). No big ASCII art.
BANNER_ART: tuple[str, str, str] = (
    "┌─┐┌─┐┌─┐┌─┐┌┬┐┬─┐┌─┐",
    "└─┐├─┘├┤ │   │ ├┬┘├┤ ",
    "└─┘┴  └─┘└─┘ ┴ ┴└─└─┘",
)
BANNER_SEPARATOR = "·"

# Everything a Unicode theme prints besides translated words.
_UNICODE_PROBE = "".join(UNICODE_ICONS.values()) + "".join(BANNER_ART) + BANNER_SEPARATOR


@dataclass(frozen=True)
class Theme:
    color: bool
    unicode: bool
    banner: bool

    @classmethod
    def plain(cls) -> Theme:
        return cls(color=False, unicode=False, banner=False)

    def icon(self, name: str) -> str:
        icons = UNICODE_ICONS if self.unicode else ASCII_ICONS
        return icons.get(name, "")

    def style(self, role: str) -> str:
        return STYLES.get(role, "") if self.color else ""


def supports_unicode(encoding: str | None) -> bool:
    """Whether a stream with this encoding can print the theme's Unicode glyphs."""
    if not encoding:
        return False
    try:
        codecs.lookup(encoding)
        _UNICODE_PROBE.encode(encoding)
    except (LookupError, UnicodeError):
        return False
    return True


def is_tty(stream: Any) -> bool:
    if stream is None:
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def no_color_requested(environ: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return bool(env.get("NO_COLOR"))


def resolve_theme(
    *,
    plain: bool = False,
    stream: Any = None,
    environ: Mapping[str, str] | None = None,
) -> Theme:
    """The theme for output written to `stream` (default: the current `sys.stdout`)."""
    target = sys.stdout if stream is None else stream
    if plain or no_color_requested(environ) or not is_tty(target):
        return Theme.plain()
    return Theme(color=True, unicode=supports_unicode(getattr(target, "encoding", None)), banner=True)
