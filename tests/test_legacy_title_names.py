"""Defense in depth: a title-derived display name is never active, even in old data.

B2-03B2 made enrichment emit page-title names with `rejected_by="page_title_unverified"`.
Data written *before* that — a stale result-cache row, a finding persisted in SQLite and
reloaded by `spectre report` — carries the same title with `source` `html_title` /
`html_og.title` and **no** `rejected_by`. The single activity rule in `observed.py` now
treats those two sources as inactive for `display_name` regardless of `rejected_by`, so
the compact view, identity correlation, reports and `flatten_observed()` all agree.
The only title-derived name allowed is the explicit Instagram exception, which enrichment
records under its own source, `instagram_og.title`.
"""

from __future__ import annotations

from typing import Any

import pytest

from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.presentation import observed_profile_fields
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.modules.username.enrichment import flatten_observed
from spectre_osint.modules.username.identity import (
    compare_records,
    correlate_identities,
    records_from_findings,
)
from spectre_osint.modules.username.observed import (
    PAGE_TITLE_SOURCES,
    read_observed,
    transport_row_is_active,
)
from spectre_osint.services.views import build_username_view

HANDLE = "alice_osint"
STAMP = "2026-11-05T14:44:33.549501+00:00"


def _legacy_name(value: str, source: str, original: str | None = None) -> dict[str, Any]:
    """Pre-B2-03B2 transport: no `rejected_by`, original as the old code recorded it."""
    return {
        "display_name": {
            "value": value,
            "original": original if original is not None else value,
            "source": source,
            "observed_at": STAMP,
            "source_method": "HTML",
        }
    }


def _json_name(value: str, source: str = "github_api.name") -> dict[str, Any]:
    return {
        "display_name": {
            "value": value,
            "original": value,
            "source": source,
            "observed_at": STAMP,
            "source_method": "JSON_API",
        }
    }


def _finding(platform: str, observed: dict[str, Any], status: str = "LIKELY") -> Finding:
    return Finding(
        module="username",
        title=platform,
        status=FindingStatus.FOUND,
        summary=f"{platform}: {status}",
        data={
            "platform": platform,
            "username": HANDLE,
            "check_status": status,
            "profile_url": f"https://{platform.lower().replace(' ', '')}.example/{HANDLE}",
            # The top-level compatibility copy the old engine wrote. Not evidence once
            # `observed` exists; kept here to prove nothing falls back to it.
            "display_name": observed["display_name"]["value"],
            "observed": observed,
        },
        confidence=Confidence.MEDIUM,
    )


LEGACY_CASES = [
    ("Codeberg", f"{HANDLE} - Codeberg.org", "html_title", HANDLE),
    ("Scratch", "Imagine, Program, Share", "html_og.title", "Scratch - Imagine, Program, Share"),
    ("Telegram", f"Contact @{HANDLE}", "html_title", "AlIcE_oSiNt"),
    (
        "SoundCloud",
        f"Stream {HANDLE} music | Listen to songs, albums, playlists for free on SoundCloud",
        "html_title",
        HANDLE,
    ),
    ("Launchpad", f"{HANDLE} does not use Launchpad", "html_og.title", None),
]


def test_page_title_sources_are_exactly_the_two_title_extractors() -> None:
    assert frozenset({"html_title", "html_og.title"}) == PAGE_TITLE_SOURCES


@pytest.mark.parametrize(("platform", "value", "source", "original"), LEGACY_CASES, ids=[c[0] for c in LEGACY_CASES])
def test_legacy_title_name_is_inactive_everywhere(
    platform: str, value: str, source: str, original: str | None
) -> None:
    observed = _legacy_name(value, source, original)
    data = {"observed": observed}
    assert transport_row_is_active("display_name", observed["display_name"]) is False
    assert "display_name" not in read_observed(data).active()
    assert [row for row in observed_profile_fields(data) if row["field"] == "display_name"] == []
    assert flatten_observed(observed)["display_name"] is None
    (record,) = records_from_findings([_finding(platform, observed)])
    assert record.display_name == ""


@pytest.mark.parametrize(
    "source", ["instagram_og.title", "github_api.name", "hugging_face_api.fullname", "html_jsonld.name"]
)
def test_structured_and_instagram_names_stay_active(source: str) -> None:
    observed = _json_name("Alice Example", source)
    assert transport_row_is_active("display_name", observed["display_name"]) is True
    assert "display_name" in read_observed({"observed": observed}).active()


def test_title_sources_only_affect_display_name() -> None:
    row = {"value": "https://alice.example", "original": "https://alice.example", "source": "html_title", "observed_at": STAMP}
    assert transport_row_is_active("website", row) is True


def _legacy_result() -> InvestigationResult:
    findings = [_finding("GitHub", _json_name("Alice Example"), status="CONFIRMED")]
    findings += [_finding(p, _legacy_name(v, s, o)) for p, v, s, o in LEGACY_CASES]
    return InvestigationResult(
        case_id="c",
        case_name="legacy",
        target=HANDLE,
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[Entity.create(EntityType.USERNAME, HANDLE, "user", Confidence.CONFIRMED)],
        findings=findings,
    )


def test_compact_view_shows_only_structured_names_for_legacy_data() -> None:
    view = build_username_view(_legacy_result())
    assert [(n.platform, n.name) for n in view.names] == [("GitHub", "Alice Example")]


def test_identity_correlation_has_no_title_name_conflicts_for_legacy_data() -> None:
    result = _legacy_result()
    payload = correlate_identities(result.findings)
    conflicts = [c for pair in payload.get("pairs") or [] for c in pair.get("conflicts") or []]
    assert "distinct_display_name" not in conflicts
    records = {r.platform: r for r in records_from_findings(result.findings)}
    pair = compare_records(records["GitHub"], records["Codeberg"])
    assert "distinct_display_name" not in pair["conflicts"]
