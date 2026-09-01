"""Deterministic offline contract tests for flat JSON API providers.

Scope (8 providers):
1. GitHub                  (json_id_field: login)
2. Docker Hub              (json_id_field: username)
3. Chess.com               (json_id_field: username)
4. Lichess                 (json_id_field: id)
5. Bluesky                 (json_id_field: handle)
6. Mastodon-mastodon.social (json_id_field: subject)
7. Hugging Face            (json_id_field: user)
8. Modrinth                (json_id_field: username)

100% offline via httpx.MockTransport. No live network. Synthetic fixtures only.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.types import (
    Confidence,
    EntityType,
    FindingStatus,
    RelationType,
    UsernameCheckStatus,
)
from spectre_osint.modules.username.catalog import SiteDefinition, load_catalog
from spectre_osint.modules.username.engine import _check_site

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "username" / "json_api"


def _load_fixture(filename: str) -> dict[str, Any]:
    path = FIXTURES_DIR / filename
    return json.loads(path.read_text(encoding="utf-8"))


def _get_provider_site(slug: str) -> dict[str, Any]:
    catalog = load_catalog()
    site = catalog.get_by_slug(slug)
    if site is None:
        raise ValueError(f"Provider with slug '{slug}' not found in catalog")
    return site.to_dict()


def _make_expected_url_client(
    expected_url: str,
    status_code: int = 200,
    *,
    json_data: Any = None,
    text: str | None = None,
    headers: dict[str, str] | None = None,
) -> HttpClient:
    """Create an HttpClient with a MockTransport enforcing the exact expected request URL."""

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) != expected_url:
            raise AssertionError(
                f"Unexpected offline request URL: {request.url} (expected: {expected_url})"
            )
        if text is not None:
            return httpx.Response(status_code, text=text, headers=headers or {})
        return httpx.Response(status_code, json=json_data, headers=headers or {})

    settings = Settings(ssrf_enabled=False, http_max_retries=1)
    transport = httpx.MockTransport(handler)
    return HttpClient(settings, transport=transport)


# ==============================================================================
# A. PRESENT CONTRACT TESTS (8 PROVIDERS)
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("slug", "fixture_name", "expected_display_name"),
    [
        ("github", "github_present.json", "Synthetic Developer"),
        ("docker_hub", "docker_hub_present.json", "Synthetic Container Engineer"),
        ("chess_com", "chess_com_present.json", "Synthetic Chess Master"),
        ("lichess", "lichess_present.json", "Synthetic Grandmaster"),
        ("bluesky", "bluesky_present.json", "Synthetic Bluesky User"),
        ("mastodon_mastodon_social", "mastodon_mastodon_social_present.json", None),
        ("hugging_face", "hugging_face_present.json", "Synthetic AI Researcher"),
        ("modrinth", "modrinth_present.json", "Synthetic Mod Creator"),
    ],
)
async def test_json_flat_present_contract(
    slug: str, fixture_name: str, expected_display_name: str | None
) -> None:
    """Verify that valid flat JSON responses confirm existence and produce evidence."""
    site = _get_provider_site(slug)
    fixture_data = _load_fixture(fixture_name)
    username = "synthetic_user"

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=fixture_data)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        finding = res["finding"]
        data = finding.data

        # Status & Confidence
        assert finding.status == FindingStatus.FOUND
        assert data["check_status"] == UsernameCheckStatus.CONFIRMED.value
        assert finding.confidence == Confidence.CONFIRMED
        assert data["confidence"] == Confidence.CONFIRMED.value
        assert data["http_status"] == 200

        # Identity resolution reason references json_id_field
        assert "JSON identity field" in data["reason"]

        # Display name extraction
        assert data.get("display_name") == expected_display_name

        # Evidence and Entity creation
        assert len(res["evidence"]) == 1
        evidence = res["evidence"][0]
        assert evidence.source == site["name"]
        assert evidence.confidence == Confidence.CONFIRMED

        profiles = [e for e in res["entities"] if e.type == EntityType.SOCIAL_PROFILE]
        assert len(profiles) == 1
        assert profiles[0].value == site["profile_url"].format(username=username)

        has_profile_rels = [
            r
            for r in res["relationships"]
            if r.relation == RelationType.HAS_PROFILE
            and r.from_entity_id == entity.id
            and r.to_entity_id == profiles[0].id
        ]
        assert len(has_profile_rels) == 1
    finally:
        await http.close()


# ==============================================================================
# B. HTTP 200 WITHOUT IDENTITY FIELD (8 PROVIDERS)
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("slug", "fixture_name"),
    [
        ("github", "github_absent.json"),
        ("docker_hub", "docker_hub_absent.json"),
        ("chess_com", "chess_com_absent.json"),
        ("lichess", "lichess_absent.json"),
        ("bluesky", "bluesky_absent.json"),
        ("mastodon_mastodon_social", "mastodon_mastodon_social_absent.json"),
        ("hugging_face", "hugging_face_absent.json"),
        ("modrinth", "modrinth_absent.json"),
    ],
)
async def test_json_flat_absent_contract_http_200_missing_id(
    slug: str, fixture_name: str
) -> None:
    """Verify that HTTP 200 without the required json_id_field evaluates to NOT_FOUND."""
    site = _get_provider_site(slug)
    fixture_data = _load_fixture(fixture_name)
    username = "nonexistent_user"

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=fixture_data)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        finding = res["finding"]
        data = finding.data

        assert finding.status == FindingStatus.NOT_FOUND
        assert data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
        assert finding.confidence is None
        assert "without identity field" in data["reason"]

        # No evidence or profiles generated
        assert res["evidence"] == []
        assert res["entities"] == []
        assert res["relationships"] == []
    finally:
        await http.close()


# ==============================================================================
# B2. HTTP 200 WITH EMPTY/WHITESPACE/INVALID IDENTITY VALUE
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("slug", "id_field"),
    [
        ("github", "login"),
        ("docker_hub", "username"),
        ("chess_com", "username"),
        ("lichess", "id"),
        ("bluesky", "handle"),
        ("mastodon_mastodon_social", "subject"),
        ("hugging_face", "user"),
        ("modrinth", "username"),
    ],
)
async def test_json_flat_absent_contract_http_200_empty_string_id(
    slug: str, id_field: str
) -> None:
    """Verify that HTTP 200 with an empty string identity evaluates strictly to NOT_FOUND."""
    site = _get_provider_site(slug)
    username = "empty_id_user"
    payload = {id_field: ""}

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=payload)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        finding = res["finding"]
        data = finding.data

        assert finding.status == FindingStatus.NOT_FOUND
        assert data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
        assert finding.confidence is None
        assert "without identity field" in data["reason"]
        assert res["evidence"] == []
        assert res["entities"] == []
        assert res["relationships"] == []
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_json_flat_whitespace_identity_rejected() -> None:
    """Verify that HTTP 200 with whitespace-only identity evaluates to NOT_FOUND."""
    site = _get_provider_site("github")
    username = "whitespace_user"
    payload = {"login": "   "}

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=payload)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        finding = res["finding"]
        assert finding.status == FindingStatus.NOT_FOUND
        assert finding.data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
        assert res["evidence"] == []
    finally:
        await http.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_value",
    [
        False,
        True,
        [],
        {},
    ],
)
async def test_json_flat_non_scalar_and_boolean_identities_rejected(invalid_value: Any) -> None:
    """Verify that boolean and container identities are strictly rejected as NOT_FOUND."""
    site = _get_provider_site("github")
    username = "invalid_type_user"
    payload = {"login": invalid_value}

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=payload)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        finding = res["finding"]
        assert finding.status == FindingStatus.NOT_FOUND
        assert finding.data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
        assert res["evidence"] == []
    finally:
        await http.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("numeric_id", [0, 123])
async def test_json_flat_integer_identity_accepted(numeric_id: int) -> None:
    """Verify that integer scalar identity values (including 0) are accepted as CONFIRMED."""
    synthetic_site = SiteDefinition.model_validate(
        {
            "name": "Synthetic Numeric API",
            "category": "Tech",
            "profile_url": "https://api.example.com/users/{username}",
            "check_url": "https://api.example.com/users/{username}",
            "check_method": "json_api",
            "json_id_field": "id",
            "expected_status": [200],
            "not_found_status": [404],
            "enabled": True,
            "confidence_strategy": "explicit_api",
        }
    ).to_dict()

    username = "numeric_user"
    payload = {"id": numeric_id}
    expected_url = synthetic_site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=payload)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, synthetic_site, http, sem, refresh=True)
        finding = res["finding"]
        assert finding.status == FindingStatus.FOUND
        assert finding.data["check_status"] == UsernameCheckStatus.CONFIRMED.value
        assert f"id={numeric_id}" in finding.data["reason"]
        assert len(res["evidence"]) == 1
    finally:
        await http.close()


# ==============================================================================
# C. CONFIGURED NOT_FOUND STATUS (404 and Bluesky 400/404)
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("slug", "not_found_code"),
    [
        ("github", 404),
        ("docker_hub", 404),
        ("chess_com", 404),
        ("lichess", 404),
        ("bluesky", 400),
        ("bluesky", 404),
        ("mastodon_mastodon_social", 404),
        ("hugging_face", 404),
        ("modrinth", 404),
    ],
)
async def test_json_flat_configured_not_found_status(slug: str, not_found_code: int) -> None:
    """Verify that configured not_found_status evaluates strictly to NOT_FOUND."""
    site = _get_provider_site(slug)
    username = "missing_user"

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(
        expected_url, not_found_code, json_data={"error": "Not Found"}
    )
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        finding = res["finding"]
        assert finding.status == FindingStatus.NOT_FOUND
        assert finding.data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
        assert finding.data["http_status"] == not_found_code
        assert res["evidence"] == []
    finally:
        await http.close()


# ==============================================================================
# D. METADATA & PROVENANCE VALIDATION
# ==============================================================================


@pytest.mark.asyncio
async def test_github_metadata_and_provenance() -> None:
    """Verify rich metadata extraction and provenance mappings for GitHub."""
    site = _get_provider_site("github")
    fixture_data = _load_fixture("github_present.json")
    username = "synthetic_user"

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=fixture_data)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        data = res["finding"].data
        observed = data["observed"]

        # Display name
        assert data["display_name"] == "Synthetic Developer"
        assert observed["display_name"]["source"] == "github_api.name"
        assert observed["display_name"]["value"] == "Synthetic Developer"

        # Website and Domain entity (normalized with trailing slash for origin URLs)
        assert data["website"] == "https://synthetic-blog.example.com/"
        assert observed["website"]["source"] == "github_api.blog"
        assert observed["personal_domain"]["value"] == "synthetic-blog.example.com"
        domain_entities = [e for e in res["entities"] if e.type == EntityType.DOMAIN]
        assert len(domain_entities) == 1
        assert domain_entities[0].value == "synthetic-blog.example.com"

        # Bio
        assert data["bio"] == "Synthetic open source maintainer and security researcher"
        assert observed["bio"]["source"] == "github_api.bio"

        # Avatar
        assert data["avatar_url"] == "https://avatars.example.com/u/1001"
        assert observed["avatar_url"]["source"] == "github_api.avatar_url"

        # Location
        assert data["public_location"] == "San Francisco, CA"
        assert observed["location"]["source"] == "github_api.location"
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_docker_hub_metadata_and_provenance() -> None:
    """Verify metadata extraction for Docker Hub."""
    site = _get_provider_site("docker_hub")
    fixture_data = _load_fixture("docker_hub_present.json")
    username = "synthetic_user"

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=fixture_data)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        data = res["finding"].data
        assert data["display_name"] == "Synthetic Container Engineer"
        assert data["observed"]["display_name"]["source"] == "docker_hub_api.full_name"
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_chess_com_metadata_and_platform_url_rejection() -> None:
    """Verify Chess.com metadata and rejection of chess.com platform URLs as personal website."""
    site = _get_provider_site("chess_com")
    fixture_data = _load_fixture("chess_com_present.json")
    username = "synthetic_user"

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=fixture_data)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        data = res["finding"].data
        observed = data["observed"]

        assert data["display_name"] == "Synthetic Chess Master"
        assert observed["display_name"]["source"] == "chess_com_api.name"

        assert data["avatar_url"] == "https://images.chesscomfiles.com/uploads/v1/user/123.png"
        assert observed["avatar_url"]["source"] == "chess_com_api.avatar"

        assert data["public_location"] == "Reykjavik, Iceland"
        assert observed["location"]["source"] == "chess_com_api.location"

        # Platform URL (chess.com/member/...) is NOT treated as a personal website
        assert data["website"] is None
        assert "website" not in observed
        assert [e for e in res["entities"] if e.type == EntityType.DOMAIN] == []
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_lichess_metadata_and_title_exclusion_regression() -> None:
    """Verify Lichess realName extraction and regression proof that chess titles are NOT display names."""
    site = _get_provider_site("lichess")
    sem = asyncio.Semaphore(1)

    # 1. Present with realName -> extracted as display_name
    present_data = _load_fixture("lichess_present.json")
    username = "synthetic_user"
    expected_url = site["check_url"].format(username=username)
    http1 = _make_expected_url_client(expected_url, 200, json_data=present_data)
    entity1 = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)
    try:
        res1 = await _check_site(entity1, site, http1, sem, refresh=True)
        data1 = res1["finding"].data
        assert data1["display_name"] == "Synthetic Grandmaster"
        assert data1["observed"]["display_name"]["source"] == "lichess_api.profile.realName"
    finally:
        await http1.close()

    # 2. Regression check: payload with title="GM" but username matching handle -> title is NOT emitted as display_name
    no_realname_data = {
        "id": "synthetic_user",
        "username": "synthetic_user",
        "title": "GM",
    }
    http2 = _make_expected_url_client(expected_url, 200, json_data=no_realname_data)
    entity2 = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)
    try:
        res2 = await _check_site(entity2, site, http2, sem, refresh=True)
        data2 = res2["finding"].data
        assert data2.get("display_name") is None
        assert "display_name" not in data2["observed"]
    finally:
        await http2.close()


@pytest.mark.asyncio
async def test_bluesky_metadata_and_provenance() -> None:
    """Verify Bluesky displayName and avatar extraction."""
    site = _get_provider_site("bluesky")
    fixture_data = _load_fixture("bluesky_present.json")
    username = "synthetic_user"

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=fixture_data)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        data = res["finding"].data
        observed = data["observed"]

        assert data["display_name"] == "Synthetic Bluesky User"
        assert observed["display_name"]["source"] == "bluesky_api.displayName"

        assert (
            data["avatar_url"]
            == "https://cdn.bsky.app/img/avatar/plain/did:plc:synthetic123456/avatar.jpg"
        )
        assert observed["avatar_url"]["source"] == "bluesky_api.avatar"
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_hugging_face_metadata_and_provenance() -> None:
    """Verify Hugging Face fullname extraction."""
    site = _get_provider_site("hugging_face")
    fixture_data = _load_fixture("hugging_face_present.json")
    username = "synthetic_user"

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=fixture_data)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        data = res["finding"].data
        assert data["display_name"] == "Synthetic AI Researcher"
        assert data["observed"]["display_name"]["source"] == "hugging_face_api.fullname"
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_modrinth_metadata_and_provenance() -> None:
    """Verify Modrinth metadata extraction (name, bio, avatar)."""
    site = _get_provider_site("modrinth")
    fixture_data = _load_fixture("modrinth_present.json")
    username = "synthetic_user"

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=fixture_data)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        data = res["finding"].data
        observed = data["observed"]

        assert data["display_name"] == "Synthetic Mod Creator"
        assert observed["display_name"]["source"] == "modrinth_api.name"

        assert data["bio"] == "Synthetic developer building Minecraft mods and plugins"
        assert observed["bio"]["source"] == "modrinth_api.bio"

        assert data["avatar_url"] == "https://cdn.modrinth.com/user/avatar.png"
        assert observed["avatar_url"]["source"] == "modrinth_api.avatar_url"
    finally:
        await http.close()
