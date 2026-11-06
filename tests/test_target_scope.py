"""The log safety net lives for one investigation, not for the process (PR #18 review, item 2).

The menu (Phase 3) runs many investigations in one process. Values registered by one
investigation must be gone when it ends: no unbounded growth (500 investigations used to
leave ~11k forms and ~11 ms of regex per log line), no plaintext targets kept in memory,
and no reference shared between investigations (a new salt per scope).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from spectre_osint.core import redaction
from spectre_osint.core.database import reset_engine
from spectre_osint.core.pipeline import InvestigationRunner
from spectre_osint.core.redaction import register_target_values, scrub_target_values, target_ref
from spectre_osint.core.types import EntityType


def test_values_do_not_survive_their_scope_even_after_500_investigations() -> None:
    for index in range(500):
        with redaction.target_scope():
            register_target_values(f"user_{index}", f"Person Number {index}", f"p{index}@example.org")
            assert scrub_target_values(f"user_{index}") != f"user_{index}"
    assert scrub_target_values("user_0") == "user_0"
    assert scrub_target_values("user_499") == "user_499"
    assert redaction.registered_form_count() == 0


def test_two_investigations_in_one_process_do_not_share_targets_or_references(isolated_db) -> None:
    seen: list[dict[str, str]] = []

    async def fake_collect(entity: Any, _extra: dict[str, Any]) -> dict[str, Any]:
        seen.append(
            {
                "target": entity.normalized_value,
                "first": scrub_target_values("value=first_target_1"),
                "second": scrub_target_values("value=second_target_2"),
                "ref": target_ref("same_value_123"),
            }
        )
        return {}

    async def two_runs() -> None:
        runner = InvestigationRunner(settings=isolated_db)
        runner._collect = fake_collect  # type: ignore[method-assign]
        try:
            for target in ("first_target_1", "second_target_2"):
                await runner.run(target, force_type=EntityType.USERNAME, write_report=False)
        finally:
            await runner.close()

    try:
        asyncio.run(two_runs())
    finally:
        reset_engine()

    first, second = seen
    assert first["first"] != "value=first_target_1", "the first target is scrubbed in its own run"
    assert second["first"] == "value=first_target_1", "the first target leaked into the second run"
    assert second["second"] != "value=second_target_2"
    assert first["ref"] != second["ref"], "the same value got the same reference in two investigations"
    assert scrub_target_values("value=second_target_2") == "value=second_target_2"


def test_a_scope_holds_at_most_the_form_limit() -> None:
    limit = redaction.MAX_SCOPE_FORMS
    with redaction.target_scope():
        register_target_values("first_value_kept")
        register_target_values(*(f"value_{index:05d}" for index in range(limit * 4)))
        assert redaction.registered_form_count() <= limit
        assert scrub_target_values("first_value_kept") != "first_value_kept"
    assert redaction.registered_form_count() == 0


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def test_a_value_that_does_not_fit_is_registered_whole_or_not_at_all() -> None:
    """With one slot left, an e-mail used to enter raw while `%40` and the domain stayed
    out: the limit cut through the forms of one value (second review of PR #18)."""
    redaction.clear_target_values()
    limit = redaction.MAX_SCOPE_FORMS
    collect = _Collect()
    redaction.logger.addHandler(collect)
    try:
        with redaction.target_scope():
            # One form each: no "_", ".", " " or reserved character to derive another.
            register_target_values(*(f"fillvalue{index:05d}" for index in range(limit - 1)))
            assert redaction.registered_form_count() == limit - 1
            register_target_values("alice@example.com")
            register_target_values("bob.other@example.org")
            lines = ["mail=alice@example.com", "mail=alice%40example.com", "host=example.com"]
            fates = [scrub_target_values(line) == line for line in lines]
            assert len(set(fates)) == 1, [scrub_target_values(line) for line in lines]
            assert redaction.registered_form_count() <= limit
    finally:
        redaction.logger.removeHandler(collect)
    assert sum("log safety net full" in message for message in collect.messages) == 1


def test_a_nested_scope_is_the_investigation_scope() -> None:
    """A pivot or a helper that opens a scope inside an investigation shares its values
    and its references; only the outermost scope discards them."""
    with redaction.target_scope():
        register_target_values("outer_value")
        outer_ref = target_ref("outer_value")
        with redaction.target_scope():
            assert scrub_target_values("outer_value") == outer_ref
            register_target_values("inner_value")
        assert scrub_target_values("inner_value") == target_ref("inner_value")
    assert scrub_target_values("outer_value inner_value") == "outer_value inner_value"


def test_tasks_and_worker_threads_started_inside_a_scope_see_it() -> None:
    async def inside() -> list[str]:
        with redaction.target_scope():
            register_target_values("alice_osint")

            async def task() -> str:
                return scrub_target_values("alice_osint")

            from_task = await asyncio.gather(task())
            from_thread = await asyncio.to_thread(scrub_target_values, "alice_osint")
            return [*from_task, from_thread]

    assert all(text.startswith("t:") for text in asyncio.run(inside()))


# --- the contract of target_scope(): a task that logs the target ends inside the scope ------
# These pin today's behavior (second review of PR #18); the pipeline awaits its gather
# inside the scope, so neither case leaks now. A change here is a change of contract.


def test_contract_a_task_awaited_after_the_scope_closes_logs_in_clear() -> None:
    redaction.clear_target_values()

    async def main() -> tuple[str, str, str]:
        with redaction.target_scope():
            register_target_values("alice_osint")
            ref_inside = target_ref("alice_osint")

            async def late() -> tuple[str, str]:
                return scrub_target_values("alice_osint"), target_ref("alice_osint")

            task = asyncio.create_task(late())  # created inside, not awaited inside
        text, ref_after = await task
        return ref_inside, text, ref_after

    ref_inside, text, ref_after = asyncio.run(main())
    assert text == "alice_osint", "the scope's values are gone once it closes"
    assert ref_after != ref_inside, "the closed scope's salt was replaced"


def test_contract_a_task_created_before_the_scope_never_sees_it() -> None:
    redaction.clear_target_values()

    async def main() -> tuple[str, str]:
        gate = asyncio.Event()

        async def early() -> str:
            await gate.wait()
            return scrub_target_values("alice_osint")

        task = asyncio.create_task(early())  # copies the context before the scope exists
        await asyncio.sleep(0)
        with redaction.target_scope():
            register_target_values("alice_osint")
            in_scope = scrub_target_values("alice_osint")
            gate.set()
            return in_scope, await task

    in_scope, from_task = asyncio.run(main())
    assert in_scope.startswith("t:")
    assert from_task == "alice_osint"
