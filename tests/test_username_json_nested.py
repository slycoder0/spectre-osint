"""Deterministic offline contract tests for nested JSON API providers.

Scope:
1. Keybase   (json_id_field: them.0.id)
2. Reddit    (json_id_field: data.name)
3. crates.io (json_id_field: user.login)

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
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, UsernameCheckStatus
from spectre_osint.modules.username.catalog import load_catalog
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
# A. PRESENT CONTRACT TESTS
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("slug", "fixture_name", "expected_display_name"),
    [
        ("keybase", "keybase_present.json", "Synthetic Keybase User"),
        ("reddit", "reddit_present.json", "Synthetic Subreddit Title"),
        ("crates_io", "crates_io_present.json", "Synthetic Crates Developer"),
    ],
)
async def test_json_nested_present_contract(
    slug: str, fixture_name: str, expected_display_name: str
) -> None:
    """Verify that valid nested JSON responses confirm existence and produce evidence."""
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

        # Identity resolution reason
        assert "JSON identity field" in data["reason"]

        # Display name extraction
        assert data["display_name"] == expected_display_name

        # Evidence and Entity creation
        assert len(res["evidence"]) == 1
        evidence = res["evidence"][0]
        assert evidence.source == site["name"]
        assert evidence.confidence == Confidence.CONFIRMED

        profiles = [e for e in res["entities"] if e.type == EntityType.SOCIAL_PROFILE]
        assert len(profiles) == 1
        assert profiles[0].value == site["profile_url"].format(username=username)
        assert len(res["relationships"]) == 1
    finally:
        await http.close()


# ==============================================================================
# B. ABSENT CONTRACT TESTS
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("slug", "fixture_name"),
    [
        ("keybase", "keybase_absent.json"),
        ("reddit", "reddit_absent.json"),
        ("crates_io", "crates_io_absent.json"),
    ],
)
async def test_json_nested_absent_contract_http_200_missing_id(
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


@pytest.mark.asyncio
@pytest.mark.parametrize("slug", ["keybase", "reddit", "crates_io"])
async def test_json_nested_absent_contract_http_404(slug: str) -> None:
    """Verify that HTTP 404 response evaluates strictly to NOT_FOUND."""
    site = _get_provider_site(slug)
    username = "missing_user"

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 404, json_data={"detail": "Not Found"})
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        finding = res["finding"]
        assert finding.status == FindingStatus.NOT_FOUND
        assert finding.data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
        assert finding.data["http_status"] == 404
        assert res["evidence"] == []
    finally:
        await http.close()


# ==============================================================================
# C. NESTED PATH TRAVERSAL EDGE CASES
# ==============================================================================


@pytest.mark.asyncio
async def test_keybase_nested_list_and_dict_traversal() -> None:
    """Explicitly verify list index traversal for them.0.id and edge cases."""
    site = _get_provider_site("keybase")
    username = "alice"
    expected_url = site["check_url"].format(username=username)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    # 1. Empty list -> NOT_FOUND
    http1 = _make_expected_url_client(expected_url, 200, json_data={"them": []})
    try:
        res1 = await _check_site(entity, site, http1, sem, refresh=True)
        assert res1["finding"].data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
    finally:
        await http1.close()

    # 2. None value at list root -> NOT_FOUND
    http2 = _make_expected_url_client(expected_url, 200, json_data={"them": None})
    try:
        res2 = await _check_site(entity, site, http2, sem, refresh=True)
        assert res2["finding"].data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
    finally:
        await http2.close()

    # 3. Non-dict element in list -> NOT_FOUND
    http3 = _make_expected_url_client(expected_url, 200, json_data={"them": ["string_not_dict"]})
    try:
        res3 = await _check_site(entity, site, http3, sem, refresh=True)
        assert res3["finding"].data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
    finally:
        await http3.close()

    # 4. Valid nested id at index 0 -> CONFIRMED
    http4 = _make_expected_url_client(
        expected_url, 200, json_data={"them": [{"id": "user_id_001"}]}
    )
    try:
        res4 = await _check_site(entity, site, http4, sem, refresh=True)
        assert res4["finding"].data["check_status"] == UsernameCheckStatus.CONFIRMED.value
        assert "them.0.id=user_id_001" in res4["finding"].data["reason"]
    finally:
        await http4.close()


@pytest.mark.asyncio
async def test_reddit_nested_dict_traversal() -> None:
    """Explicitly verify nested dict traversal for data.name and edge cases."""
    site = _get_provider_site("reddit")
    username = "alice"
    expected_url = site["check_url"].format(username=username)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    # 1. Missing name field inside data dict -> NOT_FOUND
    http1 = _make_expected_url_client(expected_url, 200, json_data={"data": {}})
    try:
        res1 = await _check_site(entity, site, http1, sem, refresh=True)
        assert res1["finding"].data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
    finally:
        await http1.close()

    # 2. None value for data.name -> NOT_FOUND
    http2 = _make_expected_url_client(expected_url, 200, json_data={"data": {"name": None}})
    try:
        res2 = await _check_site(entity, site, http2, sem, refresh=True)
        assert res2["finding"].data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
    finally:
        await http2.close()

    # 3. Non-dict intermediate for data -> NOT_FOUND
    http3 = _make_expected_url_client(expected_url, 200, json_data={"data": "string_not_dict"})
    try:
        res3 = await _check_site(entity, site, http3, sem, refresh=True)
        assert res3["finding"].data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
    finally:
        await http3.close()

    # 4. Valid nested data.name -> CONFIRMED
    http4 = _make_expected_url_client(
        expected_url, 200, json_data={"data": {"name": "alice_reddit"}}
    )
    try:
        res4 = await _check_site(entity, site, http4, sem, refresh=True)
        assert res4["finding"].data["check_status"] == UsernameCheckStatus.CONFIRMED.value
        assert "data.name=alice_reddit" in res4["finding"].data["reason"]
    finally:
        await http4.close()


@pytest.mark.asyncio
async def test_crates_io_nested_dict_traversal() -> None:
    """Explicitly verify nested dict traversal for user.login and edge cases."""
    site = _get_provider_site("crates_io")
    username = "alice"
    expected_url = site["check_url"].format(username=username)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    # 1. Missing login field inside user dict -> NOT_FOUND
    http1 = _make_expected_url_client(expected_url, 200, json_data={"user": {}})
    try:
        res1 = await _check_site(entity, site, http1, sem, refresh=True)
        assert res1["finding"].data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
    finally:
        await http1.close()

    # 2. None value for user.login -> NOT_FOUND
    http2 = _make_expected_url_client(expected_url, 200, json_data={"user": {"login": None}})
    try:
        res2 = await _check_site(entity, site, http2, sem, refresh=True)
        assert res2["finding"].data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
    finally:
        await http2.close()

    # 3. Non-dict intermediate for user -> NOT_FOUND
    http3 = _make_expected_url_client(expected_url, 200, json_data={"user": []})
    try:
        res3 = await _check_site(entity, site, http3, sem, refresh=True)
        assert res3["finding"].data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
    finally:
        await http3.close()

    # 4. Valid nested user.login -> CONFIRMED
    http4 = _make_expected_url_client(
        expected_url, 200, json_data={"user": {"login": "alice_crates"}}
    )
    try:
        res4 = await _check_site(entity, site, http4, sem, refresh=True)
        assert res4["finding"].data["check_status"] == UsernameCheckStatus.CONFIRMED.value
        assert "user.login=alice_crates" in res4["finding"].data["reason"]
    finally:
        await http4.close()


# ==============================================================================
# D. METADATA & PROVENANCE VALIDATION
# ==============================================================================


@pytest.mark.asyncio
async def test_keybase_metadata_correctly_maps_location_not_website() -> None:
    """Verify Keybase metadata extracts location_field and does NOT emit location as website."""
    site = _get_provider_site("keybase")
    fixture_data = _load_fixture("keybase_present.json")
    username = "synthetic_user"

    expected_url = site["check_url"].format(username=username)
    http = _make_expected_url_client(expected_url, 200, json_data=fixture_data)
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        finding = res["finding"]
        data = finding.data

        # 1. Display name extracted from them.0.profile.full_name
        assert data["display_name"] == "Synthetic Keybase User"

        # 2. Public location extracted from them.0.profile.location
        assert data["public_location"] == "San Francisco, CA"

        # 3. Website is None; location is NOT treated as website
        assert data["website"] is None

        # 4. No domain or website entities created from location string
        domain_entities = [e for e in res["entities"] if e.type == EntityType.DOMAIN]
        assert domain_entities == []

        # 5. Observed provenance mapping
        observed = data["observed"]
        assert "location" in observed
        assert observed["location"]["value"] == "San Francisco, CA"
        assert observed["location"]["source"] == "keybase_api.them.0.profile.location"

        assert "display_name" in observed
        assert observed["display_name"]["value"] == "Synthetic Keybase User"
        assert observed["display_name"]["source"] == "keybase_api.them.0.profile.full_name"

        assert "website" not in observed
        assert "personal_domain" not in observed
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_reddit_and_crates_metadata_extraction() -> None:
    """Verify metadata extraction for Reddit and crates.io without spurious fields."""
    sem = asyncio.Semaphore(1)

    # 1. Reddit: distinct display name from data.name
    reddit_site = _get_provider_site("reddit")
    reddit_payload = {
        "data": {
            "name": "alice_reddit",
            "id": "synthetic_reddit_id_001",
            "subreddit": {
                "title": "Alice Custom Title",
            },
        }
    }
    username_r = "alice"
    expected_url_r = reddit_site["check_url"].format(username=username_r)
    http_reddit = _make_expected_url_client(expected_url_r, 200, json_data=reddit_payload)
    entity_r = Entity.create(EntityType.USERNAME, username_r, "test", Confidence.CONFIRMED)
    try:
        res_r = await _check_site(entity_r, reddit_site, http_reddit, sem, refresh=True)
        data_r = res_r["finding"].data
        assert data_r["display_name"] == "alice_reddit"
        assert data_r["observed"]["display_name"]["source"] == "reddit_api.data.name"
    finally:
        await http_reddit.close()

    # 2. crates.io display_name from user.name
    crates_site = _get_provider_site("crates_io")
    crates_fixture = _load_fixture("crates_io_present.json")
    username_c = "synthetic_user"
    expected_url_c = crates_site["check_url"].format(username=username_c)
    http_crates = _make_expected_url_client(expected_url_c, 200, json_data=crates_fixture)
    entity_c = Entity.create(EntityType.USERNAME, username_c, "test", Confidence.CONFIRMED)
    try:
        res_c = await _check_site(entity_c, crates_site, http_crates, sem, refresh=True)
        data_c = res_c["finding"].data
        assert data_c["display_name"] == "Synthetic Crates Developer"
        assert data_c["observed"]["display_name"]["source"] == "crates_io_api.user.name"
    finally:
        await http_crates.close()


# ==============================================================================
# E. TRANSPORT STATUS ISOLATION (401/403/429/5xx)
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.parametrize("slug", ["keybase", "reddit", "crates_io"])
@pytest.mark.parametrize(
    ("status_code", "expected_check_status", "expected_finding_status"),
    [
        (401, UsernameCheckStatus.BLOCKED, FindingStatus.BLOCKED),
        (403, UsernameCheckStatus.BLOCKED, FindingStatus.BLOCKED),
        (429, UsernameCheckStatus.RATE_LIMITED, FindingStatus.RATE_LIMITED),
        (408, UsernameCheckStatus.PROVIDER_UNAVAILABLE, FindingStatus.PROVIDER_UNAVAILABLE),
        (500, UsernameCheckStatus.PROVIDER_UNAVAILABLE, FindingStatus.PROVIDER_UNAVAILABLE),
        (502, UsernameCheckStatus.PROVIDER_UNAVAILABLE, FindingStatus.PROVIDER_UNAVAILABLE),
        (503, UsernameCheckStatus.PROVIDER_UNAVAILABLE, FindingStatus.PROVIDER_UNAVAILABLE),
        (504, UsernameCheckStatus.PROVIDER_UNAVAILABLE, FindingStatus.PROVIDER_UNAVAILABLE),
    ],
)
async def test_json_nested_transport_status_isolation(
    slug: str,
    status_code: int,
    expected_check_status: UsernameCheckStatus,
    expected_finding_status: FindingStatus,
) -> None:
    """Verify offline transport status code classification across all 3 providers."""
    site = _get_provider_site(slug)
    username = "status_test_user"
    expected_url = site["check_url"].format(username=username)

    http = _make_expected_url_client(
        expected_url, status_code, json_data={"error": f"HTTP {status_code}"}
    )
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        finding = res["finding"]
        data = finding.data

        assert finding.status == expected_finding_status
        assert data["check_status"] == expected_check_status.value
        assert res["evidence"] == []
    finally:
        await http.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("slug", ["keybase", "reddit", "crates_io"])
async def test_json_nested_malformed_json_yields_provider_unavailable(slug: str) -> None:
    """Verify that invalid JSON syntax at HTTP 200 evaluates to PROVIDER_UNAVAILABLE."""
    site = _get_provider_site(slug)
    username = "malformed_json_user"
    expected_url = site["check_url"].format(username=username)

    http = _make_expected_url_client(
        expected_url,
        200,
        text="<html><head><title>502 Bad Gateway</title></head><body>invalid json</body></html>",
        headers={"content-type": "application/json"},
    )
    sem = asyncio.Semaphore(1)
    entity = Entity.create(EntityType.USERNAME, username, "test", Confidence.CONFIRMED)

    try:
        res = await _check_site(entity, site, http, sem, refresh=True)
        finding = res["finding"]
        assert finding.status == FindingStatus.PROVIDER_UNAVAILABLE
        assert finding.data["check_status"] == UsernameCheckStatus.PROVIDER_UNAVAILABLE.value
        assert "invalid JSON" in finding.data["reason"]
    finally:
        await http.close()
