"""Service layer (B2-06): requests in, InvestigationResult out — no printing, no Rich."""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from spectre_osint.core.entities import InvestigationResult, utcnow
from spectre_osint.core.types import EntityType
from spectre_osint.services import investigations
from spectre_osint.services.investigations import (
    InvestigationRequest,
    run_investigation,
    username_request,
)


def test_username_request_carries_parsed_operator_inputs() -> None:
    request = username_request(
        "@alice_osint",
        aliases=["alice-example"],
        display_name="Alice Example",
        email="alice@example.test",
        refresh=True,
        depth=2,
        auto_pivot=True,
        case_name="case-x",
    )
    assert request.target == "alice_osint"
    assert request.force_type == EntityType.USERNAME
    assert request.refresh is True
    assert (request.depth, request.auto_pivot, request.case_name) == (2, True, "case-x")
    extra = request.extra or {}
    assert extra["refresh"] is True
    inputs = extra["inputs"]
    assert inputs["primary"] == "alice_osint"
    assert inputs["aliases"] == ["alice-example"]
    assert inputs["display_name"] == "Alice Example"
    assert inputs["email"] == "alice@example.test"


class _FakeRunner:
    instances: list[_FakeRunner] = []

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.closed = False
        _FakeRunner.instances.append(self)

    async def run(self, target: str, **kwargs: Any) -> InvestigationResult:
        self.calls.append((target, kwargs))
        if self.fail:
            raise RuntimeError("boom")
        return InvestigationResult(
            case_id="c",
            case_name="n",
            target=target,
            target_type=EntityType.USERNAME,
            mode="PASSIVE_OSINT",
            started_at=utcnow(),
        )

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_run_investigation_forwards_the_request_and_progress() -> None:
    events: list[dict[str, Any]] = []
    runner = _FakeRunner()
    request = InvestigationRequest(
        target="alice_osint",
        force_type=EntityType.USERNAME,
        depth=2,
        auto_pivot=True,
        case_name="case-x",
        extra={"inputs": {"primary": "alice_osint"}},
        refresh=True,
    )
    result = await run_investigation(request, progress=events.append, runner_factory=lambda: runner)
    assert result.target == "alice_osint"
    ((target, kwargs),) = runner.calls
    assert target == "alice_osint"
    assert kwargs["force_type"] == EntityType.USERNAME
    assert kwargs["depth"] == 2
    assert kwargs["auto_pivot"] is True
    assert kwargs["case_name"] == "case-x"
    assert kwargs["extra"] == {"inputs": {"primary": "alice_osint"}}
    assert kwargs["refresh"] is True
    assert kwargs["progress"] == events.append
    assert runner.closed is True


@pytest.mark.asyncio
async def test_refresh_flag_in_extra_is_honored() -> None:
    runner = _FakeRunner()
    request = InvestigationRequest(target="alice_osint", extra={"refresh": True})
    await run_investigation(request, runner_factory=lambda: runner)
    assert runner.calls[0][1]["refresh"] is True


@pytest.mark.asyncio
async def test_runner_is_closed_when_the_investigation_fails() -> None:
    runner = _FakeRunner(fail=True)
    with pytest.raises(RuntimeError):
        await run_investigation(InvestigationRequest(target="alice_osint"), runner_factory=lambda: runner)
    assert runner.closed is True


def test_service_layer_never_prints_or_imports_rich() -> None:
    for module in (investigations, __import__("spectre_osint.services.views", fromlist=["x"])):
        source = inspect.getsource(module)
        assert "import rich" not in source and "from rich" not in source
        assert "print(" not in source
        assert "typer" not in source
