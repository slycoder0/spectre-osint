"""Live progress bar (B2-06): stderr only, translated, silent when stderr is not a TTY."""

from __future__ import annotations

import io

from rich.console import Console

from spectre_osint.cli.display import CliProgressReporter
from spectre_osint.cli.progress_bar import LiveProgress, make_progress_display
from spectre_osint.core.i18n import set_language


def _events(progress: LiveProgress) -> None:
    progress({"phase": "initializing", "state": "running"})
    progress({"phase": "catalog", "state": "running", "current": 0, "total": 57})
    progress({"phase": "catalog", "state": "running", "current": 12, "total": 57})
    progress({"phase": "catalog", "state": "degraded", "provider": "x", "message": "x unavailable"})
    progress({"phase": "catalog", "state": "running", "current": 57, "total": 57})


def test_disabled_when_the_console_is_not_a_terminal() -> None:
    buffer = io.StringIO()
    progress = LiveProgress(Console(file=buffer, force_terminal=False))
    assert progress.enabled is False
    with progress:
        _events(progress)
        progress({"phase": "mentions", "state": "running"})
    assert buffer.getvalue() == ""


def test_renders_translated_phase_and_real_counts_on_a_terminal() -> None:
    set_language("pt-BR")
    buffer = io.StringIO()
    progress = LiveProgress(Console(file=buffer, force_terminal=True, width=100), auto_refresh=False)
    assert progress.enabled is True
    with progress:
        _events(progress)
        progress.refresh()
        snapshot = buffer.getvalue()
    assert "Consultando perfis públicos" in snapshot
    assert "57/57" in snapshot


def test_phase_without_total_shows_no_fake_count() -> None:
    set_language("en")
    buffer = io.StringIO()
    progress = LiveProgress(Console(file=buffer, force_terminal=True, width=100), auto_refresh=False)
    with progress:
        progress({"phase": "catalog", "state": "running", "current": 3, "total": 9})
        progress({"phase": "mentions", "state": "running"})
        progress.refresh()
        snapshot = buffer.getvalue()
    tail = snapshot.rsplit("Searching public mentions", 1)[-1]
    assert "Searching public mentions" in snapshot
    assert "3/9" not in tail
    assert "%" not in tail


def test_unknown_phase_keeps_the_current_label_and_never_raises() -> None:
    set_language("en")
    buffer = io.StringIO()
    progress = LiveProgress(Console(file=buffer, force_terminal=True, width=100), auto_refresh=False)
    with progress:
        progress({"phase": "catalog", "state": "running", "current": 1, "total": 2})
        progress({"phase": "brand_new_phase", "state": "running"})
        progress({"state": "running"})
        progress({})
        progress.refresh()
        snapshot = buffer.getvalue()
    assert "Checking public profiles" in snapshot
    assert "brand_new_phase" not in snapshot


def test_events_outside_the_context_are_ignored() -> None:
    buffer = io.StringIO()
    progress = LiveProgress(Console(file=buffer, force_terminal=True, width=100))
    progress({"phase": "catalog", "state": "running", "current": 1, "total": 2})
    assert buffer.getvalue() == ""


def test_default_live_progress_writes_to_stderr() -> None:
    assert LiveProgress().console.stderr is True


def test_factory_picks_bar_by_default_and_line_reporter_on_verbose() -> None:
    bar = make_progress_display(verbose=False)
    assert isinstance(bar, LiveProgress)
    with make_progress_display(verbose=True) as reporter:
        assert isinstance(reporter, CliProgressReporter)
        assert reporter.console.stderr is True
