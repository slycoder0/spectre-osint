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
    originating_lead: str = ""
    target_value: str = ""


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

    def add(text: str, query_type: str, input_kind: str, *, originating_lead: str = "", target_value: str = "") -> None:
        raw = " ".join(str(text or "").split()).strip()
        if not raw:
            return
        key = raw.lower()
        if key in seen:
            return
        lead = originating_lead or target_value or raw
        per = sum(1 for item in ordered if item.input_kind == input_kind and item.originating_lead == lead)
        if per >= max_per_input:
            return
        if len(ordered) >= max(1, int(budget)):
            return
        seen.add(key)
        ordered.append(
            PlannedQuery(
                text=raw,
                query_type=query_type,
                input_kind=input_kind,
                originating_lead=lead,
                target_value=target_value or lead,
            )
        )

    usernames = [_handle(item) for item in leads["usernames"] if _handle(item)]
    names = [item for item in leads["names"] if item]
    emails = [item for item in leads["emails"] if item]
    domains = [_domain_token(item) for item in leads["domains"] if _domain_token(item)]

    # --- TIER 0: PRIMARY TARGET (Exact quote for primary username) ---
    if usernames:
        primary = usernames[0]
        add(_quote(primary), "username", "username", originating_lead=primary, target_value=primary)

    # --- TIER 1: HIGH-INFORMATION EXACT LEADS (Exact Email & Domain/Website) ---
    max_high = max(len(emails), len(domains)) if (emails or domains) else 0
    for i in range(max_high):
        if i < len(emails):
            add(_quote(emails[i]), "email", "email", originating_lead=emails[i], target_value=emails[i])
        if i < len(domains):
            add(_quote(domains[i]), "domain", "domain", originating_lead=domains[i], target_value=domains[i])

    # --- TIER 2: OTHER PRIMARY CONTEXT (Display Name) ---
    for name in names:
        add(_quote(name), "name", "name", originating_lead=name, target_value=name)

    # --- TIER 3: OPERATOR ALIASES (Exact quotes for alias usernames) ---
    for alias in usernames[1:]:
        add(_quote(alias), "username", "username", originating_lead=alias, target_value=alias)

    # --- TIER 4: DEPTH & COMBINATIONS (Secondary templates & combined queries) ---
    # Username variants round-robin
    username_depth_families = (
        (lambda h: f"@{h}", "handle"),
        (lambda h: f"inurl:{h}", "inurl"),
        (lambda h: f"{_quote(h)} profile", "profile"),
    )

    for builder, qtype in username_depth_families:
        for handle in usernames:
            add(builder(handle), qtype, "username", originating_lead=handle, target_value=handle)

    # Paired queries (name + handle)
    for handle in usernames:
        for name in names:
            add(f"{_quote(name)} {_quote(handle)}", "pair", "pair", originating_lead=handle, target_value=handle)

    # Username + Domain queries
    for handle in usernames:
        for domain in domains:
            add(f"{_quote(handle)} {_quote(domain)}", "username_domain", "domain", originating_lead=handle, target_value=handle)

    # Name + Domain queries
    for name in names:
        for domain in domains:
            add(f"{_quote(name)} {_quote(domain)}", "name_domain", "domain", originating_lead=name, target_value=name)

    logger.debug(
        "query planner inputs=%s generated=%s deduped=%s budget=%s",
        sum(len(v) for v in leads.values()),
        len(seen),
        len(ordered),
        budget,
    )
    return ordered
