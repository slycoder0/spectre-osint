"""B2-03B2: a page title is page metadata, never an observed person name.

og:title / <title> without structured proof is kept in `observed` with `rejected_by`
and its raw text in `original`, and every consumer treats it as absent. Synthetic
fixtures only; no network.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.presentation import observed_profile_fields, username_rows
from spectre_osint.core.types import AccessMode, Confidence, EntityType, FindingStatus
from spectre_osint.modules.search.summary import build_intelligence_summary
from spectre_osint.modules.username.catalog import SiteDefinition
from spectre_osint.modules.username.engine import _check_site
from spectre_osint.modules.username.enrichment import enrich_profile, flatten_observed
from spectre_osint.modules.username.identity import compare_records, records_from_findings
from spectre_osint.modules.username.observed import parse_observed, read_observed
from spectre_osint.reporting.html import write_html_report
from spectre_osint.reporting.json import write_json_report

HANDLE = "alice_osint"
TOKEN = "page_title_unverified"
STAMP = "2026-01-01T12:00:00+00:00"

# The five live A1 cases, rebuilt around the synthetic handle.
JUNK_TITLES: list[tuple[str, str, str]] = [
    ("Codeberg", "<title>alice_osint - Codeberg.org</title>", "alice_osint - Codeberg.org"),
    (
        "SoundCloud",
        "<title>Stream alice_osint music | Listen to songs, albums, playlists for free on SoundCloud</title>",
        "Stream alice_osint music | Listen to songs, albums, playlists for free on SoundCloud",
    ),
    ("Telegram", "<title>Contact @alice_osint</title>", "Contact @alice_osint"),
    (
        "Scratch",
        '<title>Scratch</title><meta property="og:title" content="Imagine, Program, Share">',
        "Imagine, Program, Share",
    ),
    (
        "Launchpad",
        '<meta property="og:title" content="alice_osint does not use Launchpad">',
        "alice_osint does not use Launchpad",
    ),
]


def _html(head: str) -> str:
    return f"<html><head>{head}</head><body><p>profile</p></body></html>"


def _title(head: str) -> str:
    start = head.find("<title>")
    return head[start + 7 : head.find("</title>")] if start >= 0 else ""


def _enrich_junk(platform: str, head: str) -> dict[str, Any]:
    return enrich_profile(
        platform=platform,
        username=HANDLE,
        profile_url=f"https://{platform.lower()}.example/{HANDLE}",
        html=_html(head),
        meta={"title": _title(head)},
        observed_at=STAMP,
    )


def _github_observed() -> dict[str, Any]:
    return enrich_profile(
        platform="GitHub",
        username=HANDLE,
        profile_url=f"https://github.com/{HANDLE}",
        site={"slug": "github", "display_name_fields": ["name"]},
        json_data={"login": HANDLE, "id": 7, "name": "Alice Example"},
        observed_at=STAMP,
    )


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
            "profile_url": f"https://{platform.lower()}.example/{HANDLE}",
            "observed": observed,
        },
        confidence=Confidence.HIGH,
    )


def _result(findings: list[Finding]) -> InvestigationResult:
    return InvestigationResult(
        case_id="c",
        case_name="b2-03b2",
        target=HANDLE,
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        finished_at=utcnow(),
        entities=[Entity.create(EntityType.USERNAME, HANDLE, "user", Confidence.CONFIRMED)],
        findings=findings,
    )


# 1. The five live cases are recorded, rejected, and never active.
@pytest.mark.parametrize(("platform", "head", "raw"), JUNK_TITLES, ids=[c[0] for c in JUNK_TITLES])
def test_page_title_is_rejected_not_active(platform: str, head: str, raw: str) -> None:
    observed = _enrich_junk(platform, head)
    row = observed["display_name"]
    assert row["rejected_by"] == TOKEN
    assert row["original"] == raw
    assert row["source"] in {"html_title", "html_og.title"}
    assert row["source_method"] == "HTML"
    assert "display_name" not in read_observed({"observed": observed}).active()
    assert [r for r in observed_profile_fields({"observed": observed}) if r["field"] == "display_name"] == []


def test_original_is_the_title_actually_used() -> None:
    """A generic og:title falls through to <title>; `original` must be the <title> text."""
    observed = enrich_profile(
        platform="Codeberg",
        username=HANDLE,
        profile_url=f"https://codeberg.example/{HANDLE}",
        meta={"og_title": "Codeberg", "title": "alice_osint - Codeberg.org"},
        observed_at=STAMP,
    )
    assert observed["display_name"]["source"] == "html_title"
    assert observed["display_name"]["original"] == "alice_osint - Codeberg.org"
    assert observed["display_name"]["rejected_by"] == TOKEN


# 2. Identity: the rejected value is absent from the comparison, not a zero.
def test_rejected_title_removes_false_name_conflict() -> None:
    github = _finding("GitHub", _github_observed(), status="CONFIRMED")
    codeberg = _finding("Codeberg", _enrich_junk("Codeberg", JUNK_TITLES[0][1]))
    untitled = _finding("Codeberg", _enrich_junk("Codeberg", ""))

    by_platform = {rec.platform: rec for rec in records_from_findings([github, codeberg])}
    left, right = by_platform["GitHub"], by_platform["Codeberg"]
    assert left.display_name == "Alice Example"
    assert right.display_name == ""
    pair = compare_records(left, right)
    assert "distinct_display_name" not in pair["conflicts"]
    assert "same_display_name" not in pair["evidence"]
    assert all(row["code"] not in {"distinct_display_name", "same_display_name"} for row in pair["evidence_detail"])

    baseline = compare_records(*records_from_findings([github, untitled]))
    assert pair["score"] == baseline["score"]
    assert pair["conflicts"] == baseline["conflicts"]
    assert pair["evidence"] == baseline["evidence"]


# 3. Summary, presentation and report never show the rejected value.
def test_rejected_titles_are_not_presented_or_reported(tmp_path) -> None:
    findings = [_finding("GitHub", _github_observed(), status="CONFIRMED")]
    findings += [_finding(platform, _enrich_junk(platform, head)) for platform, head, _ in JUNK_TITLES]
    result = _result(findings)

    assert build_intelligence_summary(result)["observed_names"] == ["Alice Example"]

    shown = [
        item["value"]
        for row in username_rows(result)
        for item in row["observed"]
        if item["field"] == "display_name"
    ]
    assert shown == ["Alice Example"]

    html = write_html_report(result, tmp_path / "reports").read_text(encoding="utf-8")
    assert "Alice Example" in html
    for _, _, raw in JUNK_TITLES:
        assert raw not in html


# 4. The rejected transport is valid and round-trips.
def test_rejected_transport_round_trips() -> None:
    transport = _enrich_junk("Codeberg", JUNK_TITLES[0][1])
    parsed = parse_observed(transport)
    assert parsed.root["display_name"].rejected_by == TOKEN
    assert parsed.to_transport() == transport
    assert parse_observed(parsed.to_transport()).to_transport() == transport


# Ajuste 1: flatten_observed ignores every rejected field, not only display_name.
def test_flatten_observed_ignores_any_rejected_field() -> None:
    def row(value: Any, rejected: bool) -> dict[str, Any]:
        out: dict[str, Any] = {"value": value, "original": value, "source": "synthetic", "observed_at": STAMP}
        if rejected:
            out["rejected_by"] = "synthetic_rejection"
        return out

    observed = {
        "display_name": row("Alice Example", True),
        "bio": row("Synthetic bio text", True),
        "location": row("Lisbon", True),
        "website": row("https://alice.example/", True),
        "social_links": row(["https://x.com/alice_osint"], True),
        "organization": row("Example Labs", False),
        "external_links": row(["https://blog.alice.example/"], False),
    }
    flat = flatten_observed(observed)
    assert flat["display_name"] is None
    assert flat["bio"] is None
    assert flat["public_location"] is None
    assert flat["website"] is None
    assert flat["organization"] == "Example Labs"
    assert flat["public_links"] == ["https://blog.alice.example/"]

    rejected_title = flatten_observed(_enrich_junk("Telegram", JUNK_TITLES[2][1]))
    assert rejected_title["display_name"] is None


# Structured sources stay active.
def test_jsonld_person_name_beats_rejected_title() -> None:
    head = (
        '<meta property="og:title" content="Imagine, Program, Share">'
        '<script type="application/ld+json">{"@type": "Person", "name": "Alice Example"}</script>'
    )
    observed = _enrich_junk("Scratch", head)
    assert observed["display_name"]["value"] == "Alice Example"
    assert observed["display_name"]["source"] == "html_jsonld.name"
    assert "rejected_by" not in observed["display_name"]


@pytest.mark.parametrize("mode", [AccessMode.ANONYMOUS_PUBLIC, AccessMode.AUTHENTICATED_PUBLIC])
def test_instagram_handle_bound_og_title_stays_active(mode: AccessMode) -> None:
    observed = enrich_profile(
        platform="Instagram",
        username=HANDLE,
        profile_url=f"https://www.instagram.com/{HANDLE}/",
        meta={"og_title": "Alice Example (@ALICE_OSINT) • Instagram photos and videos"},
        access_mode=mode,
        observed_at=STAMP,
    )
    assert observed["display_name"]["value"] == "Alice Example"
    assert observed["display_name"]["source"] == "instagram_og.title"
    assert "rejected_by" not in observed["display_name"]


@pytest.mark.parametrize(
    "meta",
    [
        {"og_title": "Alice Example • Instagram photos and videos"},
        {"og_title": "Alice Example (@someone_else) • Instagram photos and videos"},
        {"title": "Alice Example (@alice_osint) • Instagram photos and videos"},
    ],
    ids=["no-handle", "other-handle", "title-tag-only"],
)
def test_instagram_title_without_handle_binding_is_rejected(meta: dict[str, str]) -> None:
    observed = enrich_profile(
        platform="Instagram",
        username=HANDLE,
        profile_url=f"https://www.instagram.com/{HANDLE}/",
        meta=meta,
        observed_at=STAMP,
    )
    assert observed["display_name"]["rejected_by"] == TOKEN


def test_generic_titles_still_produce_no_row() -> None:
    for platform, meta in (
        ("TryHackMe", {"title": "TryHackMe | Cyber Security Training", "og_title": "TryHackMe | Cyber Security Training"}),
        ("Docker Hub", {"title": "Docker Hub | Container Image Library"}),
        ("GitHub", {"title": HANDLE}),
    ):
        observed = enrich_profile(
            platform=platform, username=HANDLE, profile_url="https://x.example/", meta=meta, observed_at=STAMP
        )
        assert "display_name" not in observed, platform


# Ajuste 2: the engine no longer copies the raw og:title into top-level / evidence /
# entity metadata, which the JSON report dumps verbatim.
def _settings(tmp_path) -> Settings:
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    return settings


@pytest.mark.asyncio
async def test_engine_does_not_expose_raw_page_title_as_a_name(tmp_path) -> None:
    raw = "alice_osint does not use Launchpad"
    body = (
        "<html><head><title>alice_osint in Launchpad</title>"
        f'<meta property="og:title" content="{raw}">'
        f'<link rel="canonical" href="https://launchpad.example/~{HANDLE}">'
        f'</head><body><div class="user-profile">~{HANDLE}</div></body></html>'
    )
    site = SiteDefinition.model_validate(
        {
            "name": "Launchpad Synthetic",
            "category": "Development",
            "profile_url": "https://launchpad.example/~{username}",
            "check_method": "generic_html",
            "confidence_strategy": "multi_signal",
            "expected_status": [200],
            "not_found_status": [404],
            "profile_markers": ["user-profile"],
            "success_patterns": ["user-profile"],
        }
    ).to_dict()
    settings = _settings(tmp_path)
    http = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, text=body)))
    entity = Entity.create(EntityType.USERNAME, HANDLE, "t", Confidence.CONFIRMED)
    try:
        res = await _check_site(entity, site, http, asyncio.Semaphore(2))
    finally:
        await http.close()

    finding = res["finding"]
    data = finding.data
    assert data["check_status"] in {"LIKELY", "CONFIRMED"}
    assert data["observed"]["display_name"]["rejected_by"] == TOKEN
    assert data["observed"]["display_name"]["original"] == raw
    assert data["display_name"] is None
    for ev in res["evidence"]:
        assert json.loads(ev.raw_reference or "{}").get("public_name") is None
    for ent in res["entities"]:
        assert ent.metadata.get("public_name") is None

    result = _result([finding])
    result.evidence = list(res["evidence"])
    result.entities = [*result.entities, *res["entities"]]
    report = json.loads(write_json_report(result, tmp_path / "reports").read_text(encoding="utf-8"))
    assert report["findings"][0]["data"]["display_name"] is None
    assert all(e.get("metadata", {}).get("public_name") is None for e in report["entities"])
