"""Live progress for investigations (B2-06): a transient Rich bar on stderr.

The bar exists only while an investigation runs and only when stderr is a terminal;
piped or redirected runs get no progress output at all, so stdout stays a clean result.
It shows the translated phase and real counts when the pipeline reports them (catalog
sites checked); phases without a known total pulse instead of inventing a percentage,
as the progress contract in `core/progress.py` requires.

`--verbose` keeps the factual line-by-line reporter instead, also on stderr.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)

from spectre_osint.core.i18n import has_message, t

ProgressSink = Callable[[dict[str, Any]], None]


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


class LiveProgress:
    def __init__(
        self,
        console: Console | None = None,
        *,
        auto_refresh: bool = True,
        enabled: bool | None = None,
    ) -> None:
        self.console = console or Console(stderr=True, highlight=False)
        self.enabled = bool(self.console.is_terminal) if enabled is None else enabled
        self._auto_refresh = auto_refresh
        self._progress: Progress | None = None
        self._task: TaskID | None = None
        self._phase: str | None = None

    def __enter__(self) -> LiveProgress:
        if self.enabled:
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("{task.description}"),
                BarColumn(),
                TextColumn("{task.fields[count]}"),
                TimeElapsedColumn(),
                console=self.console,
                transient=True,
                auto_refresh=self._auto_refresh,
            )
            self._progress.start()
            self._task = self._progress.add_task(t("progress.initializing"), total=None, count="")
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._progress is not None:
            self._progress.stop()
        self._progress = None
        self._task = None
        self._phase = None

    def refresh(self) -> None:
        if self._progress is not None:
            self._progress.refresh()

    def __call__(self, payload: dict[str, Any]) -> None:
        progress = self._progress
        if progress is None or self._task is None or not isinstance(payload, dict):
            return
        phase = str(payload.get("phase") or "")
        if not phase or not has_message(f"progress.{phase}"):
            return
        if phase != self._phase:
            progress.remove_task(self._task)
            self._task = progress.add_task(t(f"progress.{phase}"), total=None, count="")
            self._phase = phase
        current = _as_int(payload.get("current", payload.get("done")))
        total = _as_int(payload.get("total"))
        if current is not None and total:
            progress.update(self._task, total=total, completed=min(current, total), count=f"{current}/{total}")


def make_progress_display(
    *, verbose: bool, plain: bool = False
) -> contextlib.AbstractContextManager[ProgressSink]:
    """The progress sink for one investigation, as a context manager.

    `--plain` means no animation and no style: the live bar is off (like a pipe) and the
    verbose reporter writes without color.
    """
    if verbose:
        from spectre_osint.cli.display import CliProgressReporter

        reporter_console = Console(stderr=True, highlight=False, color_system=None if plain else "auto")
        return contextlib.nullcontext(CliProgressReporter(reporter_console))
    return LiveProgress(enabled=False) if plain else LiveProgress()
