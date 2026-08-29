"""Deterministic public-search query planner. No network."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from spectre_osint.core.logger import get_logger
from spectre_osint.modules.mentions.relevance import lead_host, normalize_case_inputs

logger = get_logger("spectre.search")

DEFAULT_BUDGET = 12
MAX_PER_INPUT = 4


@dataclass(frozen=True)
class PlannedQuery:
    text: str
    query_type: str
    input_kind: str


def _quote(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith('"') and text.endswith('"') and len(text) > 1:
        return text
    return f'"{text}"'


def _handle(value: str) -> str:
    return str(value or "").strip().lstrip("@")


def _domain_token(value: str) -> str:
    host = lead_host(value)
    return host or str(value or "").strip()


def plan_queries(
    case_inputs: dict[str, Any] | None,
    *,
    budget: int = DEFAULT_BUDGET,
    max_per_input: int = MAX_PER_INPUT,
) -> list[PlannedQuery]:
    """Build a small, deduped query set from operator-provided leads."""
    leads = normalize_case_inputs(case_inputs)
    ordered: list[PlannedQuery] = []
    seen: set[str] = set()

    def add(text: str, query_type: str, input_kind: str) -> None:
        raw = " ".join(str(text or "").split()).strip()
        if not raw:
            return
        key = raw.lower()
        if key in seen:
            return
        per = sum(1 for item in ordered if item.input_kind == input_kind)
        if per >= max_per_input:
            return
        if len(ordered) >= max(1, int(budget)):
            return
        seen.add(key)
        ordered.append(PlannedQuery(text=raw, query_type=query_type, input_kind=input_kind))

    usernames = [_handle(item) for item in leads["usernames"] if _handle(item)]
    names = [item for item in leads["names"] if item]
    emails = [item for item in leads["emails"] if item]
    domains = [_domain_token(item) for item in leads["domains"] if _domain_token(item)]

    for handle in usernames:
        add(_quote(handle), "username", "username")
        add(f"@{handle}", "handle", "username")
        add(f"inurl:{handle}", "inurl", "username")
        add(f"{_quote(handle)} profile", "profile", "username")

    for name in names:
        add(_quote(name), "name", "name")

    for handle in usernames:
        for name in names:
            add(f"{_quote(name)} {_quote(handle)}", "pair", "pair")

    for handle in usernames:
        for domain in domains:
            add(f"{_quote(handle)} {_quote(domain)}", "username_domain", "domain")
    for name in names:
        for domain in domains:
            add(f"{_quote(name)} {_quote(domain)}", "name_domain", "domain")

    for email in emails:
        add(_quote(email), "email", "email")

    logger.debug(
        "query planner inputs=%s generated=%s deduped=%s budget=%s",
        sum(len(v) for v in leads.values()),
        len(seen),
        len(ordered),
        budget,
    )
    return ordered
