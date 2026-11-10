"""Central terminal theme (Phase 3A): icons, styles, Unicode/color/banner switches."""

from __future__ import annotations

import io

import pytest

from spectre_osint.cli import theme as theme_mod
from spectre_osint.cli.theme import (
    ASCII_ICONS,
    UNICODE_ICONS,
    Theme,
    resolve_theme,
    supports_unicode,
)


class _Stream(io.StringIO):
    def __init__(self, *, tty: bool, encoding: str | None) -> None:
        super().__init__()
        self._tty = tty
        self._encoding = encoding

    def isatty(self) -> bool:
        return self._tty

    @property
    def encoding(self) -> str | None:  # type: ignore[override]
        return self._encoding


def test_icons_are_found_uncertain_unknown() -> None:
    assert UNICODE_ICONS == {"found": "✔", "uncertain": "◐", "unknown": "?"}
    assert ASCII_ICONS == {"found": "[+]", "uncertain": "[~]", "unknown": "[?]"}
    assert all(icon.isascii() for icon in ASCII_ICONS.values())


@pytest.mark.parametrize(
    ("encoding", "expected"),
    [("utf-8", True), ("UTF8", True), ("utf-16", True), ("cp1252", False), ("ascii", False), ("cp437", False), (None, False), ("not-a-codec", False)],
)
def test_supports_unicode_depends_on_the_console_encoding(encoding: str | None, expected: bool) -> None:
    assert supports_unicode(encoding) is expected


def test_utf8_terminal_gets_color_unicode_icons_and_banner() -> None:
    theme = resolve_theme(stream=_Stream(tty=True, encoding="utf-8"), environ={})
    assert (theme.color, theme.unicode, theme.banner) == (True, True, True)
    assert theme.icon("found") == "✔"
    assert theme.icon("uncertain") == "◐"
    assert theme.icon("unknown") == "?"
    assert theme.style("found")


def test_terminal_without_unicode_falls_back_to_ascii_icons_automatically() -> None:
    theme = resolve_theme(stream=_Stream(tty=True, encoding="cp1252"), environ={})
    assert theme.color is True
    assert theme.unicode is False
    assert [theme.icon(name) for name in ("found", "uncertain", "unknown")] == ["[+]", "[~]", "[?]"]


def test_plain_forces_ascii_without_color_or_banner() -> None:
    theme = resolve_theme(plain=True, stream=_Stream(tty=True, encoding="utf-8"), environ={})
    assert (theme.color, theme.unicode, theme.banner) == (False, False, False)
    assert theme.icon("found") == "[+]"
    assert theme.style("found") == ""


def test_no_color_turns_off_color_unicode_and_banner() -> None:
    theme = resolve_theme(stream=_Stream(tty=True, encoding="utf-8"), environ={"NO_COLOR": "1"})
    assert theme == Theme.plain()


def test_empty_no_color_does_not_count() -> None:
    """no-color.org: only a NO_COLOR that is present *and* not empty disables color."""
    theme = resolve_theme(stream=_Stream(tty=True, encoding="utf-8"), environ={"NO_COLOR": ""})
    assert theme.color is True


def test_stdout_that_is_not_a_tty_gets_the_plain_theme() -> None:
    theme = resolve_theme(stream=_Stream(tty=False, encoding="utf-8"), environ={})
    assert theme == Theme.plain()


def test_a_stream_whose_isatty_raises_is_not_a_tty() -> None:
    class Broken(io.StringIO):
        def isatty(self) -> bool:
            raise ValueError("closed")

    assert resolve_theme(stream=Broken(), environ={}) == Theme.plain()
    assert theme_mod.is_tty(None) is False


def test_plain_theme_has_no_style_for_any_role() -> None:
    plain = Theme.plain()
    for role in theme_mod.STYLES:
        assert plain.style(role) == ""


def test_unknown_role_or_icon_never_raises() -> None:
    fancy = Theme(color=True, unicode=True, banner=True)
    assert fancy.style("no-such-role") == ""
    assert fancy.icon("no-such-icon") == ""
