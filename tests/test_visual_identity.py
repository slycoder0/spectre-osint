"""Phase 3A visual identity: themed compact output, banner, and the plain switches."""

from __future__ import annotations

import io

import pytest
from rich.console import Console
from typer.testing import CliRunner

from spectre_osint import __version__
from spectre_osint.cli import commands
from spectre_osint.cli import theme as theme_mod
from spectre_osint.cli.commands import app
from spectre_osint.cli.render import banner_lines, render_username
from spectre_osint.cli.theme import Theme
from spectre_osint.core.i18n import set_language
from spectre_osint.services.views import build_username_view
from tests.conftest import strip_ansi
from tests.test_username_presentation import EN_SNAPSHOT, _result, _site, alice_result

FANCY = Theme(color=True, unicode=True, banner=True)
ASCII_COLOR = Theme(color=True, unicode=False, banner=True)
runner = CliRunner()


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


# --- banner -----------------------------------------------------------------------------------



def test_banner_is_three_small_lines_with_version_and_tagline() -> None:
    set_language("en")
    lines = banner_lines(FANCY)
    assert len(lines) == 3
    assert max(len(line) for line in lines) <= 72, "small banner, no big ASCII art"
    joined = "\n".join(lines)
    assert f"v{__version__}" in joined
    assert "passive-first" in joined
    assert "█" not in joined


def test_banner_falls_back_to_ascii_with_the_icons() -> None:
    set_language("en")
    lines = banner_lines(ASCII_COLOR)
    assert len(lines) == 3
    assert all(line.isascii() for line in lines)
    assert "SPECTRE" in lines[0]


def test_banner_tagline_is_translated() -> None:
    set_language("pt-BR")
    assert "fontes públicas" in "\n".join(banner_lines(FANCY))


@pytest.fixture
def fake_username(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("SPECTRE_LOGS_DIR", str(tmp_path / "logs"))
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("SPECTRE_NO_BANNER", raising=False)
    monkeypatch.delenv("NO_BANNER", raising=False)
    from spectre_osint.core.config import reload_settings

    reload_settings()

    async def fake(request, *, progress=None, **_kwargs):
        return alice_result()

    monkeypatch.setattr(commands, "run_investigation", fake)


@pytest.fixture
def tty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend stdout is a UTF-8 terminal (the runner's stdout is a UTF-8 buffer)."""
    monkeypatch.setattr(theme_mod, "is_tty", lambda _stream: True)


def _stdout(args: list[str]) -> str:
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    return strip_ansi(result.stdout)


def test_username_on_a_terminal_starts_with_the_small_banner(fake_username, tty) -> None:
    out = _stdout(["username", "alice_osint"]).splitlines()
    assert out[:3] == banner_lines(FANCY)
    assert out[3] == ""
    assert out[4].startswith("alice_osint — 3 profiles found")
    assert "  ✔ GitHub        https://github.com/alice_osint" in out


def test_banner_is_printed_once_even_with_verbose(fake_username, tty) -> None:
    out = _stdout(["--verbose", "username", "alice_osint"])
    assert out.count(f"v{__version__}") == 1
    assert "█" not in out


def test_piped_stdout_gets_no_banner_and_ascii_icons(fake_username) -> None:
    assert _stdout(["username", "alice_osint"]) == EN_SNAPSHOT


def test_plain_flag_disables_banner_color_and_unicode(fake_username, tty) -> None:
    result = runner.invoke(app, ["--plain", "username", "alice_osint"])
    assert result.exit_code == 0, result.output
    assert result.stdout == EN_SNAPSHOT
    assert "\x1b" not in result.stdout


def test_no_color_env_disables_banner_color_and_unicode(fake_username, tty, monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert _stdout(["username", "alice_osint"]) == EN_SNAPSHOT


def test_no_banner_flag_keeps_the_unicode_icons(fake_username, tty) -> None:
    out = _stdout(["--no-banner", "username", "alice_osint"])
    assert f"v{__version__}" not in out
    assert out == UNICODE_SNAPSHOT


@pytest.mark.parametrize("env", ["SPECTRE_NO_BANNER", "NO_BANNER"])
def test_banner_env_switches_still_work(fake_username, tty, monkeypatch, env) -> None:
    monkeypatch.setenv(env, "1")
    assert f"v{__version__}" not in _stdout(["username", "alice_osint"])


def test_other_commands_print_no_banner_without_verbose(tty) -> None:
    result = runner.invoke(app, ["doctor", "--json"])
    assert f"v{__version__}" not in result.stdout
    assert result.stdout.lstrip().startswith("{")


def test_help_documents_plain() -> None:
    assert "--plain" in strip_ansi(runner.invoke(app, ["--help"]).stdout)


def test_plain_turns_off_rich_styling_for_the_legacy_sections() -> None:
    from spectre_osint.cli.display import configure_display, get_console

    configure_display(plain=True)
    assert get_console().color_system is None
    configure_display()
    assert get_console() is not None


def test_plain_disables_the_live_progress_bar() -> None:
    from spectre_osint.cli.progress_bar import LiveProgress, make_progress_display

    display = make_progress_display(verbose=False, plain=True)
    assert isinstance(display, LiveProgress)
    assert display.enabled is False


def test_no_module_keeps_a_stale_reference_to_the_display_console() -> None:
    """`configure_display(plain=True)` rebuilds the console; importing it by name would
    keep the colored one. Modules call `get_console()` instead."""
    import ast
    from pathlib import Path

    package = Path(commands.__file__).resolve().parents[1]
    offenders = []
    for path in package.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "spectre_osint.cli.display":
                if any(alias.name == "console" for alias in node.names):
                    offenders.append(path.name)
    assert offenders == []
