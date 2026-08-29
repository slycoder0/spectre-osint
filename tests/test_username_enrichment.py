"""Profile enrichment and provenance. Identity weights stay unchanged."""

from __future__ import annotations

import logging

import httpx
import pytest

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.presentation import observed_profile_fields, username_rows
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.modules.username.engine import analyze_username
from spectre_osint.modules.username.enrichment import enrich_profile
from spectre_osint.modules.username.identity import (
    BANDS,
    CLUSTER_MIN,
    CONFLICTS,
    WEIGHTS,
    compare_records,
    correlate_identities,
    records_from_findings,
)
from spectre_osint.reporting.html import write_html_report


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


def _finding(platform: str, status: str = "LIKELY", **data: object) -> Finding:
    payload = {
        "platform": platform,
        "username": "alice",
        "check_status": status,
        "profile_url": f"https://{platform.lower().replace(' ', '')}.example/alice",
        **data,
    }
    return Finding(
        module="username",
        title=platform,
        status=FindingStatus.FOUND if status in {"LIKELY", "CONFIRMED"} else FindingStatus.INCONCLUSIVE,
        summary=f"{platform}: {status}",
        data=payload,
        confidence=Confidence.HIGH,
    )


def test_weights_and_thresholds_unchanged() -> None:
    assert WEIGHTS == {
        "same_username": 6,
        "same_display_name": 16,
        "similar_bio": 10,
        "same_organization": 10,
        "same_location": 8,
        "same_personal_domain": 42,
        "same_personal_url": 40,
        "cross_profile_link": 38,
        "same_public_id": 32,
        "same_public_email": 35,
        "same_avatar_url": 18,
    }
    assert CONFLICTS == {
        "distinct_display_name": -28,
        "distinct_personal_domain": -32,
        "distinct_organization": -18,
        "distinct_location": -12,
        "distinct_public_id": -40,
        "distinct_public_email": -35,
    }
    assert CLUSTER_MIN == 60
    assert BANDS[0] == (80, "STRONG")


def test_github_api_name_and_website() -> None:
    observed = enrich_profile(
        platform="GitHub",
        username="alice",
        profile_url="https://github.com/alice",
        site={
            "display_name_fields": ["name", "login"],
            "website_fields": ["blog"],
            "bio_field": "bio",
            "avatar_field": "avatar_url",
            "location_field": "location",
            "json_id_field": "login",
        },
        json_data={
            "login": "alice",
            "id": 42,
            "name": "Alice Example",
            "blog": "https://www.alice.dev/?utm_source=gh",
            "bio": "Builder of tools",
            "company": "Example Labs",
            "email": "alice@alice.dev",
            "avatar_url": "https://avatars.example/alice.png",
            "location": "Lisbon",
        },
    )
    assert observed["display_name"]["value"] == "Alice Example"
    assert observed["display_name"]["source"] == "github_api.name"
    assert observed["website"]["value"] == "https://alice.dev/"
    assert observed["personal_domain"]["value"] == "alice.dev"
    assert observed["public_id"]["value"] == "42"
    assert observed["organization"]["value"] == "Example Labs"
    assert observed["public_email"]["value"] == "alice@alice.dev"
    assert "login" not in observed["display_name"]["source"]


def test_instagram_og_title_display_name_without_inventing_bio() -> None:
    observed = enrich_profile(
        platform="Instagram",
        username="alice",
        profile_url="https://www.instagram.com/alice/",
        meta={"og_title": "Alice Example (@alice) • Instagram photos and videos", "title": "Instagram"},
    )
    assert observed["display_name"]["value"] == "Alice Example"
    assert observed["display_name"]["source"] == "instagram_og.title"
    assert "bio" not in observed


def test_generic_tryhackme_title_is_rejected_as_observed_name() -> None:
    observed = enrich_profile(
        platform="TryHackMe",
        username="alice_osint",
        profile_url="https://tryhackme.com/p/alice_osint",
        meta={"title": "TryHackMe | Cyber Security Training", "og_title": "TryHackMe | Cyber Security Training"},
    )
    assert "display_name" not in observed


def test_real_tryhackme_display_name_is_preserved() -> None:
    observed = enrich_profile(
        platform="TryHackMe",
        username="alice_osint",
        profile_url="https://tryhackme.com/p/alice_osint",
        meta={"title": "Alice Example | TryHackMe", "og_title": "Alice Example | TryHackMe"},
    )
    assert observed["display_name"]["value"] == "Alice Example"
    assert observed["display_name"]["source"] == "html_og.title"


def test_existing_platform_filters_continue_working() -> None:
    observed_docker = enrich_profile(
        platform="Docker Hub",
        username="alice_osint",
        profile_url="https://hub.docker.com/u/alice_osint",
        meta={"title": "Docker Hub | Container Image Library"},
    )
    assert "display_name" not in observed_docker

    observed_gh = enrich_profile(
        platform="GitHub",
        username="alice_osint",
        profile_url="https://github.com/alice_osint",
        meta={"title": "Alice Dev · GitHub"},
    )
    assert observed_gh["display_name"]["value"] == "Alice Dev"


def test_operator_provided_name_is_not_observed() -> None:
    observed = enrich_profile(
        platform="GitHub",
        username="alice",
        profile_url="https://github.com/alice",
        site={"display_name_fields": ["name"], "website_fields": ["blog"]},
        json_data={"login": "alice", "name": None, "blog": ""},
    )
    assert "display_name" not in observed
    assert "website" not in observed


def test_empty_fields_are_omitted() -> None:
    observed = enrich_profile(
        platform="GitHub",
        username="alice",
        profile_url="https://github.com/alice",
        json_data={"login": "alice"},
    )
    assert "bio" not in observed
    assert "public_email" not in observed
    assert observed_profile_fields({"observed": observed}) == []


def test_platform_url_is_not_personal_domain() -> None:
    observed = enrich_profile(
        platform="Chess.com",
        username="alice",
        profile_url="https://www.chess.com/member/alice",
        site={"display_name_fields": ["name"], "website_fields": ["url"]},
        json_data={"username": "alice", "name": "", "url": "https://www.chess.com/member/alice"},
    )
    assert "website" not in observed
    assert "personal_domain" not in observed


def test_identity_debug_uses_record_keys(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="spectre.username")
    records = records_from_findings(
        [
            _finding("GitHub", username="alice", display_name="Alice Example", website="https://alice.dev"),
            _finding("Instagram", username="alice_sec", display_name="Alice Example", website="https://alice.dev"),
        ]
    )
    pair = compare_records(records[0], records[1])
    assert pair["score"] >= 10
    blob = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "identity correlation github::alice <-> instagram::alice_sec" in blob
    assert "same_display_name" in blob
    assert "same_personal_domain" in blob


def test_same_personal_domain_two_profiles() -> None:
    left = _finding(
        "GitHub",
        display_name="Alice Example",
        website="https://alice.dev",
        observed={"website": {"value": "https://alice.dev", "source": "github_api.blog"}},
    )
    right = _finding(
        "Instagram",
        display_name="Alice Example",
        website="http://www.alice.dev/",
        observed={"website": {"value": "https://alice.dev", "source": "html_rel_me"}},
    )
    pair = compare_records(records_from_findings([left])[0], records_from_findings([right])[0])
    assert "same_personal_domain" in pair["evidence"]
    assert pair["score"] >= 42
    detail = [row for row in pair["evidence_detail"] if row["code"] == "same_personal_domain"]
    assert detail
    assert detail[0]["left"]["source"] == "github_api.blog"


def test_cross_profile_link() -> None:
    records = records_from_findings(
        [
            _finding("Instagram", public_links=["https://github.com/alice"], website="https://github.com/alice"),
            _finding("GitHub", profile_url="https://github.com/alice"),
        ]
    )
    pair = compare_records(records[0], records[1])
    assert "cross_profile_link" in pair["evidence"]


def test_conflicting_names_still_conflict() -> None:
    pair = compare_records(
        records_from_findings([_finding("GitHub", display_name="Alice Example")])[0],
        records_from_findings([_finding("Steam", display_name="Bob Other")])[0],
    )
    assert "distinct_display_name" in pair["conflicts"]


def test_unenriched_profiles_still_correlate() -> None:
    pair = compare_records(
        records_from_findings([_finding("GitHub")])[0],
        records_from_findings([_finding("Steam")])[0],
    )
    assert pair["evidence"] == ["same_username"]
    assert pair["band"] == "LOW"


def test_mentions_do_not_become_identity_records() -> None:
    mention = Finding(
        module="mentions",
        title="Public mention",
        status=FindingStatus.OBSERVED,
        summary="OBSERVED",
        data={
            "query": "Alice Example",
            "kind": "name",
            "check_status": "LIKELY",
            "display_name": "Alice Example",
            "website": "https://alice.dev",
            "not_profile": True,
        },
        confidence=Confidence.LOW,
    )
    records = records_from_findings([_finding("GitHub"), mention])
    assert len(records) == 1
    assert records[0].platform == "GitHub"


def test_provenance_persists_in_report_and_gui(tmp_path) -> None:
    observed = {
        "display_name": {
            "value": "Alice Example",
            "source": "github_api.name",
            "observed_at": "2026-01-01T00:00:00+00:00",
        }
    }
    finding = _finding("GitHub", display_name="Alice Example", observed=observed, check_status="CONFIRMED")
    user = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id="c",
        case_name="enrich-demo",
        target="alice",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        finished_at=utcnow(),
        entities=[user],
        findings=[finding],
        identity_correlation=correlate_identities(
            [
                finding,
                _finding(
                    "Instagram",
                    display_name="Alice Example",
                    website="https://alice.dev",
                    observed={"display_name": {"value": "Alice Example", "source": "instagram_og.title"}},
                ),
            ]
        ),
    )
    rows = username_rows(result)
    assert rows[0]["observed"][0]["source"] == "github_api.name"
    html = write_html_report(result, tmp_path / "reports").read_text(encoding="utf-8")
    assert "github_api.name" in html
    assert "Observed profile data" in html
    assert "Why this score?" in html


@pytest.mark.asyncio
async def test_github_engine_enrichment_debug(tmp_path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="spectre.username")

    def handler(request: httpx.Request) -> httpx.Response:
        if "api.github.com/users/alice" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "login": "alice",
                    "id": 7,
                    "name": "Alice Example",
                    "blog": "https://alice.dev",
                    "bio": "Public notes",
                },
            )
        return httpx.Response(404, json={"message": "Not Found"})

    settings = _settings(tmp_path)
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        bundle = await analyze_username(
            Entity.create(EntityType.USERNAME, "alice", "t", Confidence.CONFIRMED),
            http,
            categories=["Development"],
        )
    finally:
        await http.close()
    github = next(f for f in bundle["findings"] if f.title == "GitHub")
    assert github.data["display_name"] == "Alice Example"
    assert github.data["website"] == "https://alice.dev/"
    assert github.data["observed"]["display_name"]["source"] == "github_api.name"
    messages = [rec.getMessage() for rec in caplog.records]
    assert any(msg.startswith("profile enrichment provider=GitHub") for msg in messages)
    assert any("fields=" in msg and "sources=" in msg for msg in messages)
    assert all("cookie" not in msg.lower() and "<html" not in msg.lower() for msg in messages)
