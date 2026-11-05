"""Run investigations for any front end (CLI today, menu in Phase 3).

A request describes *what* to investigate; `run_investigation()` drives the existing
`InvestigationRunner` and hands back its `InvestigationResult` untouched. No printing,
no Rich, no Typer: progress goes to the callback the caller passes, and environment
setup (settings, logging, database) stays with the caller.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from spectre_osint.core.entities import InvestigationResult
from spectre_osint.core.inputs import parse_target_inputs
from spectre_osint.core.types import EntityType

ProgressCallback = Callable[[dict[str, Any]], None]


class _Runner(Protocol):
    async def run(
        self,
        target: str,
        *,
        force_type: EntityType | None = None,
        case_name: str | None = None,
        auto_pivot: bool = False,
        depth: int = 1,
        extra: dict[str, Any] | None = None,
        refresh: bool = False,
        progress: ProgressCallback | None = None,
    ) -> InvestigationResult: ...

    async def close(self) -> None: ...


@dataclass(frozen=True)
class InvestigationRequest:
    target: str
    force_type: EntityType | None = None
    auto_pivot: bool = False
    depth: int = 1
    extra: dict[str, Any] | None = None
    case_name: str | None = None
    refresh: bool = False


def username_request(
    target: str,
    *,
    aliases: Sequence[str] = (),
    display_name: str | None = None,
    email: str | None = None,
    website: str | None = None,
    auto_pivot: bool = False,
    depth: int = 1,
    case_name: str | None = None,
    refresh: bool = False,
) -> InvestigationRequest:
    """A username investigation. Operator leads are recorded as inputs, never as evidence."""
    parsed = parse_target_inputs(
        target,
        aliases=list(aliases),
        display_name=display_name,
        email=email,
        website=website,
        force_type=EntityType.USERNAME,
    )
    return InvestigationRequest(
        target=parsed.primary,
        force_type=EntityType.USERNAME,
        auto_pivot=auto_pivot,
        depth=depth,
        extra={"refresh": refresh, "inputs": parsed.as_dict()},
        case_name=case_name,
        refresh=refresh,
    )


def _default_runner() -> _Runner:
    from spectre_osint.core.pipeline import InvestigationRunner

    return InvestigationRunner()


async def run_investigation(
    request: InvestigationRequest,
    *,
    progress: ProgressCallback | None = None,
    runner_factory: Callable[[], _Runner] = _default_runner,
) -> InvestigationResult:
    """Run one investigation and always release the runner's HTTP resources."""
    runner = runner_factory()
    try:
        return await runner.run(
            request.target,
            force_type=request.force_type,
            auto_pivot=request.auto_pivot,
            depth=request.depth,
            extra=request.extra,
            case_name=request.case_name,
            refresh=request.refresh or bool((request.extra or {}).get("refresh")),
            progress=progress,
        )
    finally:
        await runner.close()
