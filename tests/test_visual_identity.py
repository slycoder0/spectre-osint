"""Phase 3A visual identity: themed compact output, banner, and the plain switches."""

from __future__ import annotations

import io

from rich.console import Console

from spectre_osint.cli.render import render_username
from spectre_osint.cli.theme import Theme
from spectre_osint.core.i18n import set_language
from spectre_osint.services.views import build_username_view
from tests.conftest import strip_ansi
from tests.test_username_presentation import EN_SNAPSHOT, _result, _site, alice_result

FANCY = Theme(color=True, unicode=True, banner=True)
ASCII_COLOR = Theme(color=True, unicode=False, banner=True)


def _terminal_render(view, theme: Theme, *, verbose: bool = False) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, width=100, force_terminal=True, color_system="standard", highlight=False)
    render_username(view, console, verbose=verbose, theme=theme)
    return buffer.getvalue()


UNICODE_SNAPSHOT = (
    EN_SNAPSHOT.replace("[+]", "✔").replace("[~]", "◐").replace("[?]", "?")
)


def test_fancy_theme_uses_unicode_icons_with_the_same_words() -> None:
    set_language("en")
    out = _terminal_render(build_username_view(alice_result()), FANCY)
    assert strip_ansi(out) == UNICODE_SNAPSHOT
    assert "  ✔ GitHub        https://github.com/alice_osint" in strip_ansi(out)
    assert "  ◐ Keybase       https://keybase.io/alice_osint (likely)" in strip_ansi(out)


def test_color_marks_found_profiles_platforms_and_the_unverified_line() -> None:
    set_language("en")
    out = _terminal_render(build_username_view(alice_result()), FANCY)
    assert "\x1b[1;32m✔" in out, "found icon is bold green"
    assert "\x1b[36mGitHub" in out, "platform name is cyan"
    assert "\x1b[33m◐" in out, "likely icon is yellow"
    assert "\x1b[33m? 4 not verified" in out, "pending unverified line is yellow"


def test_color_is_used_with_moderation_untrusted_values_stay_unstyled() -> None:
    """URLs and observed names come from third-party pages: printed as plain text."""
    set_language("en")
    out = _terminal_render(build_username_view(alice_result()), FANCY)
    lines = out.splitlines()
    url_line = next(line for line in lines if "github.com/alice_osint" in line)
    assert url_line.endswith("https://github.com/alice_osint"), "URL carries no style"
    name_line = next(line for line in lines if "Alice Example" in line)
    assert name_line.endswith(": Alice Example")


def test_ascii_fallback_keeps_color_and_alignment() -> None:
    set_language("en")
    out = _terminal_render(build_username_view(alice_result()), ASCII_COLOR)
    assert strip_ansi(out) == EN_SNAPSHOT
    assert "\x1b[" in out


def test_plain_theme_writes_no_escape_sequence_even_on_a_terminal() -> None:
    set_language("en")
    out = _terminal_render(build_username_view(alice_result()), Theme.plain())
    assert "\x1b" not in out
    assert out == EN_SNAPSHOT


def test_zero_unverified_line_never_disappears_in_any_theme() -> None:
    set_language("en")
    view = build_username_view(_result([_site("GitHub", "CONFIRMED", url="https://github.com/alice_osint")]))
    for theme, expected in ((FANCY, "? 0 not verified"), (ASCII_COLOR, "[?] 0 not verified"), (Theme.plain(), "[?] 0 not verified")):
        assert expected in strip_ansi(_terminal_render(view, theme)).splitlines()


def test_zero_unverified_line_is_muted_not_alarming() -> None:
    set_language("en")
    view = build_username_view(_result([_site("GitHub", "CONFIRMED", url="https://github.com/alice_osint")]))
    out = _terminal_render(view, FANCY)
    assert "\x1b[2m? 0 not verified" in out
