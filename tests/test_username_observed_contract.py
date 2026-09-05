"""B2-03A observed field contract. Shape is validated; behavior is unchanged.

An observed profile attribute is not a verified civil attribute. These tests pin the
serialized contract, not the meaning of the values.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from spectre_osint.browser.auth import AuthService
from spectre_osint.core.case_manager import CaseManager
from spectre_osint.core.config import Settings
from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.presentation import observed_profile_fields
from spectre_osint.core.result_cache import ResultCache
from spectre_osint.core.types import AccessMode, Confidence, EntityType, FindingStatus
from spectre_osint.modules.username.catalog import SiteDefinition, load_catalog
from spectre_osint.modules.username.engine import analyze_username
from spectre_osint.modules.username.enrichment import enrich_profile, flatten_observed
from spectre_osint.modules.username.identity import compare_records, records_from_findings
from spectre_osint.modules.username.observed import (
    EXTRACTION_METHODS,
    LEGACY_KEYS,
    MULTIPLE_SOURCES,
    ObservedField,
    ObservedFields,
    ObservedItem,
    SourceMethod,
    parse_observed,
    project_items,
)

_STAMP = "2026-01-01T12:00:00+00:00"

_GITHUB_SITE = {
    "slug": "github",
    "display_name_fields": ["name"],
    "website_fields": ["blog"],
    "bio_field": "bio",
    "avatar_field": "avatar_url",
    "location_field": "location",
}
_GITHUB_JSON = {
    "login": "alice",
    "id": 42,
    "name": "Alice Example",
    "blog": "https://www.alice.dev/?utm_source=gh",
    "bio": "Builder of tools",
    "company": "Example Labs",
    "email": "alice@alice.dev",
    "avatar_url": "https://avatars.example/alice.png",
    "location": "Lisbon",
}


def _github_observed(**kwargs: object) -> dict[str, dict]:
    params: dict = {
        "platform": "GitHub",
        "username": "alice",
        "profile_url": "https://github.com/alice",
        "site": _GITHUB_SITE,
        "json_data": _GITHUB_JSON,
        "observed_at": _STAMP,
    }
    params.update(kwargs)
    return enrich_profile(**params)


# A. scalar observation
def test_observed_field_validates_a_scalar_observation() -> None:
    field = ObservedField(
        value="Alice Example",
        original="Alice Example (@alice) - GitHub",
        source="github_api.name",
        observed_at=_STAMP,
    )
    assert field.value == "Alice Example"
    assert field.observed_at == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert field.provider_slug is None
    assert field.rejected_by is None
    # An observation with no known metadata serializes to exactly the legacy keys.
    assert sorted(field.to_transport()) == sorted(LEGACY_KEYS)


# B. list-valued links
def test_observed_field_validates_list_valued_links() -> None:
    links = ["https://a.example/alice", "https://b.example/alice"]
    field = ObservedField(
        value=links,
        original=links,
        source="html_rel_me",
        observed_at=_STAMP,
        source_method=SourceMethod.HTML,
    )
    assert field.value == links
    assert field.to_transport()["value"] == links


# C. unknown keys rejected
def test_unknown_keys_are_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        ObservedField(
            value="x",
            original="x",
            source="s",
            observed_at=_STAMP,
            confidence="HIGH",  # type: ignore[call-arg]
        )
    assert "extra_forbidden" in str(exc.value)

    with pytest.raises(ValidationError):
        parse_observed({"bio": {**_legacy_row(), "verified": True}})


def _legacy_row() -> dict[str, str]:
    return {
        "value": "Alice",
        "original": "Alice",
        "source": "github_api.name",
        "observed_at": _STAMP,
    }


# D. a new observation needs a valid, timezone-aware timestamp
def test_new_observations_require_an_aware_timestamp() -> None:
    with pytest.raises(ValidationError):
        ObservedField(value="x", original="x", source="s", observed_at="2026-01-01T12:00:00")
    with pytest.raises(ValidationError):
        ObservedField(value="x", original="x", source="s", observed_at="not-a-date")
    with pytest.raises(ValidationError):
        ObservedField.model_validate({"value": "x", "original": "x", "source": "s"})
    # enrich_profile always stamps an aware time, even from a naive caller value.
    naive = _github_observed(observed_at="2026-01-01T12:00:00")
    assert naive["display_name"]["observed_at"] == _STAMP


# E. JSON-compatible serialization
def test_transport_is_json_compatible() -> None:
    observed = _github_observed(source_url="https://api.github.com/users/alice")
    encoded = json.dumps(observed)
    assert json.loads(encoded) == observed
    for name, row in observed.items():
        assert isinstance(row["value"], (str, list)), name
        assert isinstance(row["observed_at"], str), name
        if isinstance(row["value"], list):
            assert all(isinstance(item, str) for item in row["value"]), name


# F. legacy four-key rows still parse
def test_legacy_four_key_observation_still_parses() -> None:
    legacy = {"display_name": _legacy_row()}
    parsed = parse_observed(legacy)
    assert isinstance(parsed, ObservedFields)
    assert parsed["display_name"].source == "github_api.name"
    assert parsed["display_name"].source_method is None
    # Byte-identical round trip: no key gains a synthetic value.
    assert parsed.to_transport() == legacy
    assert parse_observed(parsed) is parsed

    # A row written before timezone discipline is read as UTC, not rejected.
    naive = {"bio": {**_legacy_row(), "observed_at": "2026-01-01T12:00:00"}}
    assert parse_observed(naive)["bio"].observed_at == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


# G. provider_slug is the catalog slug
def test_provider_slug_comes_from_the_catalog() -> None:
    github = next(site for site in load_catalog().sites if site.slug == "github")
    assert github.name == "GitHub"
    observed = _github_observed(site=github.to_dict())
    assert observed["display_name"]["provider_slug"] == github.slug == "github"
    assert observed["username"]["provider_slug"] == github.slug

    # Renaming the provider must not move its stable identifier (B2-02B). The frozen
    # `source` string still follows the display name; provider_slug does not.
    renamed = _github_observed(
        platform="GitHub Enterprise Cloud",
        site={**github.to_dict(), "name": "GitHub Enterprise Cloud"},
    )
    assert renamed["display_name"]["provider_slug"] == "github"
    assert renamed["display_name"]["source"] == "github_enterprise_cloud_api.name"

    # A custom/legacy definition without a declared slug keeps the effective slug
    # that catalog loading already produced. No second slug algorithm.
    custom = SiteDefinition.model_validate(
        {
            "name": "Example Service",
            "category": "Development",
            "profile_url": "https://example.test/users/{username}",
            "check_method": "generic_html",
            "confidence_strategy": "multi_signal",
            "expected_status": [200],
            "not_found_status": [404],
            "success_patterns": ["user-profile"],
            "not_found_patterns": ["page not found"],
        }
    )
    assert custom.slug == "example_service"
    assert _github_observed(platform=custom.name, site=custom.to_dict())["username"][
        "provider_slug"
    ] == custom.slug

    # No catalog entry at all means no slug rather than a re-derived one.
    assert "provider_slug" not in _github_observed(site=None)["display_name"]


# H. source_method differentiates the observation origins
def test_source_method_differentiates_observation_origins() -> None:
    observed = _github_observed()
    assert observed["username"]["source_method"] == "INPUT"
    assert observed["display_name"]["source_method"] == "JSON_API"
    assert observed["website"]["source_method"] == "JSON_API"
    assert observed["personal_domain"]["source_method"] == "DERIVED"

    anonymous_html = enrich_profile(
        platform="TryHackMe",
        username="alice_osint",
        profile_url="https://tryhackme.com/p/alice_osint",
        site={"slug": "tryhackme"},
        meta={"title": "Alice Example | TryHackMe", "og_title": "Alice Example | TryHackMe"},
        observed_at=_STAMP,
    )
    assert anonymous_html["display_name"]["source_method"] == "HTML"

    authenticated = enrich_profile(
        platform="Instagram",
        username="alice",
        profile_url="https://www.instagram.com/alice/",
        site={"slug": "instagram"},
        meta={"og_title": "Alice Example (@alice) • Instagram photos and videos"},
        access_mode=AccessMode.AUTHENTICATED_PUBLIC,
        observed_at=_STAMP,
    )
    assert authenticated["display_name"]["source_method"] == "AUTHENTICATED_PUBLIC"
    assert authenticated["display_name"]["source"] == "instagram_og.title"
    # The handle is operator input regardless of how the page was fetched.
    assert authenticated["username"]["source_method"] == "INPUT"

    # MIXED is a row-level marker, never an extraction origin, so it is not produced
    # by any single put(). See the list-provenance tests below.
    assert {m.value for m in SourceMethod} == {
        "INPUT",
        "JSON_API",
        "HTML",
        "AUTHENTICATED_PUBLIC",
        "DERIVED",
        "MIXED",
    }


# I. source_url is preserved
def test_source_url_is_preserved() -> None:
    observed = _github_observed(source_url="https://api.github.com/users/alice")
    assert observed["display_name"]["source_url"] == "https://api.github.com/users/alice"
    assert observed["personal_domain"]["source_url"] == "https://api.github.com/users/alice"
    # Operator input was not read from a URL, so none is claimed for it.
    assert "source_url" not in observed["username"]
    # Without a more precise value the profile URL is used, not invented.
    assert _github_observed()["display_name"]["source_url"] == "https://github.com/alice"


# J. derived fields say what they came from
def test_personal_domain_is_marked_derived_from_website() -> None:
    observed = _github_observed()
    assert observed["personal_domain"]["derived_from"] == "website"
    assert observed["personal_domain"]["value"] == "alice.dev"
    # The source string still points at the website's own extraction path.
    assert observed["personal_domain"]["source"] == observed["website"]["source"] == "github_api.blog"
    assert "derived_from" not in observed["website"]


# K. pre-existing source strings are byte-identical
def test_existing_source_strings_are_byte_identical() -> None:
    observed = _github_observed()
    assert observed["username"]["source"] == "github.username"
    assert observed["display_name"]["source"] == "github_api.name"
    assert observed["website"]["source"] == "github_api.blog"
    assert observed["personal_domain"]["source"] == "github_api.blog"
    assert observed["bio"]["source"] == "github_api.bio"
    assert observed["location"]["source"] == "github_api.location"
    assert observed["avatar_url"]["source"] == "github_api.avatar_url"
    assert observed["public_id"]["source"] == "github_api.id"
    assert observed["organization"]["source"] == "github_api.company"
    assert observed["public_email"]["source"] == "github_api.email"

    html = enrich_profile(
        platform="Example Site",
        username="alice",
        profile_url="https://example.test/alice",
        html=(
            '<html><head><link rel="canonical" href="https://example.test/alice">'
            '<meta property="og:title" content="Alice Example">'
            '<meta property="og:image" content="https://cdn.example.test/a.png">'
            '<script type="application/ld+json">'
            '{"@type":"Person","name":"Alice Example","email":"alice@alice.dev",'
            '"sameAs":["https://github.com/alice","https://alice.dev/"]}'
            "</script></head>"
            '<body><a rel="me" href="https://mastodon.social/@alice">me</a></body></html>'
        ),
        observed_at=_STAMP,
    )
    sources = {name: row["source"] for name, row in html.items()}
    assert sources["display_name"] == "html_jsonld.name"
    assert sources["public_email"] == "html_jsonld.email"
    assert sources["website"] == "html_jsonld.sameAs"
    assert sources["personal_domain"] == "html_jsonld.sameAs"
    assert sources["external_links"] == "html_jsonld.sameAs"
    assert sources["avatar_url"] == "html_og.image"
    assert sources["username"] == "example_site.username"
    # social_links here really is heterogeneous — JSON-LD sameAs contributed the
    # GitHub URL and rel=me the Mastodon one — so the row says so and the items carry
    # the exact strings. Claiming "html_rel_me" for the whole row was the P2 defect.
    assert sources["social_links"] == "multiple"
    assert sorted(i["source"] for i in html["social_links"]["items"]) == [
        "html_jsonld.sameAs",
        "html_rel_me",
    ]


# L. persistence round trip keeps the new metadata
def test_observed_survives_case_persistence_round_trip(settings) -> None:
    init_db(settings)
    try:
        observed = _github_observed(source_url="https://api.github.com/users/alice")
        manager = CaseManager()
        case = manager.create("observed-contract")
        run = manager.start_run(case.id, "alice", "USERNAME")
        entity = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)
        manager.persist_result(
            InvestigationResult(
                case_id=case.id,
                case_name=case.name,
                target="alice",
                target_type=EntityType.USERNAME,
                mode="PASSIVE_OSINT",
                started_at=utcnow(),
                finished_at=utcnow(),
                run_id=run.id,
                entities=[entity],
                findings=[
                    Finding(
                        module="username",
                        title="GitHub",
                        status=FindingStatus.FOUND,
                        summary="GitHub: CONFIRMED",
                        data={
                            "platform": "GitHub",
                            "username": "alice",
                            "check_status": "CONFIRMED",
                            "profile_url": "https://github.com/alice",
                            "observed": observed,
                        },
                        confidence=Confidence.CONFIRMED,
                        entity_id=entity.id,
                    )
                ],
            )
        )
        manager.finish_run(run.id, status="completed")
        loaded = manager.load_result("observed-contract")
        assert loaded is not None
        stored = loaded.findings[0].data["observed"]
        assert stored == observed
        assert stored["display_name"]["provider_slug"] == "github"
        assert stored["display_name"]["source_method"] == "JSON_API"
        assert stored["display_name"]["source_url"] == "https://api.github.com/users/alice"
        assert stored["personal_domain"]["derived_from"] == "website"
        # It still validates after a database round trip.
        assert parse_observed(stored).to_transport() == observed
    finally:
        reset_engine()


# M. no migration was added
def test_no_schema_migration_is_introduced() -> None:
    versions = Path("spectre_osint/migrations/versions")
    revisions = sorted(p.name for p in versions.glob("*.py") if p.name != "__init__.py")
    assert revisions == ["0001_initial.py"]


# N. flatten_observed output is unchanged
def test_flatten_observed_is_unchanged_by_the_new_metadata() -> None:
    observed = _github_observed(source_url="https://api.github.com/users/alice")
    assert flatten_observed(observed) == {
        "display_name": "Alice Example",
        "bio": "Builder of tools",
        "avatar_url": "https://avatars.example/alice.png",
        "website": "https://alice.dev/",
        "public_location": "Lisbon",
        "organization": "Example Labs",
        "public_email": "alice@alice.dev",
        "public_id": "42",
        "public_links": ["https://alice.dev/"],
    }
    # A consumer that only reads value/source/observed_at sees the same rows.
    stripped = {
        name: {key: row[key] for key in LEGACY_KEYS if key in row}
        for name, row in observed.items()
    }
    assert observed_profile_fields({"observed": observed}) == observed_profile_fields(
        {"observed": stripped}
    )


# O. identity scores are unchanged
def test_identity_scores_are_unchanged_by_the_contract() -> None:
    observed = _github_observed(source_url="https://api.github.com/users/alice")
    legacy = {
        name: {key: row[key] for key in LEGACY_KEYS if key in row}
        for name, row in observed.items()
    }

    def pair(left_observed: dict, right_observed: dict) -> dict:
        findings = []
        for platform, url, obs in (
            ("GitHub", "https://github.com/alice", left_observed),
            ("GitLab", "https://gitlab.com/alice", right_observed),
        ):
            flat = flatten_observed(obs)
            findings.append(
                Finding(
                    module="username",
                    title=platform,
                    status=FindingStatus.FOUND,
                    summary=f"{platform}: CONFIRMED",
                    data={
                        "platform": platform,
                        "username": "alice",
                        "check_status": "CONFIRMED",
                        "profile_url": url,
                        "observed": obs,
                        **flat,
                    },
                    confidence=Confidence.CONFIRMED,
                )
            )
        records = records_from_findings(findings)
        return compare_records(records[0], records[1])

    new_pair = pair(observed, observed)
    old_pair = pair(legacy, legacy)
    assert new_pair["score"] == old_pair["score"]
    assert new_pair["evidence"] == old_pair["evidence"]
    assert new_pair["conflicts"] == old_pair["conflicts"]
    assert new_pair["evidence_detail"] == old_pair["evidence_detail"]


# H (end to end). The engine, not the extractor, knows how the page was fetched.
@pytest.mark.asyncio
async def test_engine_attributes_authenticated_public_and_effective_url(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        auth_dir=tmp_path / "auth",
        browser_profiles_dir=tmp_path / "browser-profiles",
        chrome_profiles_dir=tmp_path / "chrome-profiles",
        browser_backend="fake",
        keyring_enabled=False,
    )
    settings.ensure_dirs()
    service = AuthService(settings)
    await service.login("instagram")

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200, text="Please log in to continue", headers={"content-type": "text/html"}
        )

    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    bundle = await analyze_username(
        entity,
        http,
        categories=["Social"],
        auth_service=service,
        result_cache=ResultCache(settings),
    )
    insta = next(f for f in bundle["findings"] if f.title == "Instagram")
    assert insta.data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
    observed = insta.data["observed"]
    assert observed, "authenticated-public fetch produced no observations"
    for name, row in observed.items():
        expected = "INPUT" if name == "username" else "AUTHENTICATED_PUBLIC"
        assert row["source_method"] == expected, name
        assert row["provider_slug"] == "instagram", name
    assert observed["username"].get("source_url") is None
    non_input = [row for name, row in observed.items() if name != "username"]
    assert all(row["source_url"] == insta.data["final_url"] for row in non_input)
    # Still the plain transport, and still valid.
    assert parse_observed(observed).to_transport() == observed


_MIXED_HTML = (
    '<html><head><script type="application/ld+json">'
    '{"@type":"Person","name":"Alice Example",'
    '"sameAs":["https://github.com/alice","https://mastodon.social/@alice"]}'
    "</script></head><body>"
    '<a rel="me" href="https://mastodon.social/@alice">also here</a>'
    "</body></html>"
)


def _mixed_observed(**kwargs: object) -> dict[str, dict]:
    params: dict = {
        "platform": "GitHub",
        "username": "alice",
        "profile_url": "https://github.com/alice",
        "site": _GITHUB_SITE,
        "json_data": {"login": "alice", "name": "Alice Example", "twitter_username": "alice"},
        "html": _MIXED_HTML,
        "source_url": "https://api.github.com/users/alice",
        "observed_at": _STAMP,
    }
    params.update(kwargs)
    return enrich_profile(**params)


# P2 (review comment 3929900408). One row-level source cannot describe a list whose
# items came from different extractors.
def test_list_items_keep_their_own_provenance() -> None:
    row = _mixed_observed()["social_links"]
    assert row["value"] == [
        "https://x.com/alice",
        "https://github.com/alice",
        "https://mastodon.social/@alice",
    ]
    by_value: dict[str, list[dict]] = {}
    for item in row["items"]:
        by_value.setdefault(item["value"], []).append(item)

    # The X URL came from the JSON API and must not be attributed to HTML.
    x_item = by_value["https://x.com/alice"][0]
    assert x_item["source"] == "github_api.twitter_username"
    assert x_item["source_method"] == "JSON_API"

    gh_item = by_value["https://github.com/alice"][0]
    assert gh_item["source"] == "html_jsonld.sameAs"
    assert gh_item["source_method"] == "HTML"

    for item in row["items"]:
        assert item["provider_slug"] == "github"
        assert item["source_url"] == "https://api.github.com/users/alice"
        assert item["observed_at"] == _STAMP
        assert item["original"] == item["value"]


def test_duplicate_value_from_two_sources_keeps_both_observations() -> None:
    row = _mixed_observed()["social_links"]
    # The compatibility list stays deduplicated.
    assert row["value"].count("https://mastodon.social/@alice") == 1
    dupes = [i for i in row["items"] if i["value"] == "https://mastodon.social/@alice"]
    assert sorted(i["source"] for i in dupes) == ["html_jsonld.sameAs", "html_rel_me"]


def test_mixed_list_row_metadata_does_not_claim_one_source() -> None:
    row = _mixed_observed()["social_links"]
    assert row["source"] == "multiple"
    assert row["source_method"] == "MIXED"


def test_homogeneous_list_keeps_its_exact_source() -> None:
    row = _github_observed(
        json_data={**_GITHUB_JSON, "twitter_username": "alice"},
    )["social_links"]
    assert row["value"] == ["https://x.com/alice"]
    assert row["source"] == "github_api.twitter_username"
    assert row["source_method"] == "JSON_API"
    assert [i["source"] for i in row["items"]] == ["github_api.twitter_username"]


def test_authenticated_public_list_items_carry_their_access_mode() -> None:
    row = enrich_profile(
        platform="Instagram",
        username="alice",
        profile_url="https://www.instagram.com/alice/",
        site={"slug": "instagram"},
        html=_MIXED_HTML,
        access_mode=AccessMode.AUTHENTICATED_PUBLIC,
        source_url="https://www.instagram.com/alice/",
        observed_at=_STAMP,
    )["social_links"]
    assert row["source_method"] == "AUTHENTICATED_PUBLIC"
    assert {i["source_method"] for i in row["items"]} == {"AUTHENTICATED_PUBLIC"}
    assert sorted({i["source"] for i in row["items"]}) == ["html_jsonld.sameAs", "html_rel_me"]


def test_repeating_one_extractor_does_not_repeat_the_observation() -> None:
    """The same value from the same source twice is one observation, not two."""
    row = enrich_profile(
        platform="Example Site",
        username="alice",
        profile_url="https://example.test/alice",
        site={"slug": "example_site"},
        html=(
            '<html><body><a rel="me" href="https://mastodon.social/@alice">a</a>'
            '<a rel="me" href="https://mastodon.social/@alice">again</a></body></html>'
        ),
        observed_at=_STAMP,
    )["social_links"]
    assert row["value"] == ["https://mastodon.social/@alice"]
    assert len(row["items"]) == 1
    assert row["source"] == "html_rel_me"


def test_scalar_observations_carry_no_items_key() -> None:
    observed = _mixed_observed()
    assert list(observed) == ["username", "display_name", "social_links"]
    for name in ("username", "display_name"):
        assert "items" not in observed[name], name
    assert "items" not in _github_observed()["personal_domain"]
    assert "items" in observed["social_links"]


def test_legacy_list_row_without_items_still_parses() -> None:
    legacy = {
        "social_links": {
            "value": ["https://x.com/alice", "https://github.com/alice"],
            "original": ["https://x.com/alice", "https://github.com/alice"],
            "source": "html_rel_me",
            "observed_at": _STAMP,
        }
    }
    parsed = parse_observed(legacy)
    assert parsed["social_links"].items is None
    assert parsed.to_transport() == legacy

    with pytest.raises(ValidationError):
        parse_observed(
            {
                "social_links": {
                    **legacy["social_links"],
                    "items": [{**_legacy_row(), "confidence": "HIGH"}],
                }
            }
        )

    # The compatibility door treats a naive item stamp exactly like a naive row stamp.
    # The row must still agree with its items, so it is built consistently.
    naive_item = parse_observed(
        {
            "social_links": {
                "value": ["https://x.com/alice"],
                "original": ["https://x.com/alice"],
                "source": "html_rel_me",
                "observed_at": "2026-01-01T12:00:00",
                "items": [
                    {
                        "value": "https://x.com/alice",
                        "original": "https://x.com/alice",
                        "source": "html_rel_me",
                        "observed_at": "2026-01-01T12:00:00",
                    }
                ],
            }
        }
    )
    assert naive_item["social_links"].observed_at == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    members = naive_item["social_links"].items
    assert members is not None
    assert members[0].observed_at == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def test_item_timestamps_keep_the_iso_offset_spelling() -> None:
    row = _mixed_observed()["social_links"]
    assert row["observed_at"] == _STAMP
    assert all(i["observed_at"] == _STAMP for i in row["items"])
    encoded = json.dumps(row)
    assert "Z\"" not in encoded
    assert json.loads(encoded) == row


def test_mixed_list_provenance_survives_persistence_and_cache(settings, tmp_path: Path) -> None:
    from spectre_osint.core.result_cache import ResultCache

    observed = _mixed_observed()
    expected = [
        (i["value"], i["source"], i["source_method"]) for i in observed["social_links"]["items"]
    ]

    cache = ResultCache(settings)
    try:
        cache.set("username", "GitHub", "alice", {"observed": observed}, access_mode="ANONYMOUS_PUBLIC")
        hit = cache.get("username", "GitHub", "alice", "ANONYMOUS_PUBLIC")
        assert hit is not None
        assert hit.payload["observed"] == observed
    finally:
        cache.close()

    init_db(settings)
    try:
        manager = CaseManager()
        case = manager.create("mixed-provenance")
        run = manager.start_run(case.id, "alice", "USERNAME")
        entity = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)
        manager.persist_result(
            InvestigationResult(
                case_id=case.id,
                case_name=case.name,
                target="alice",
                target_type=EntityType.USERNAME,
                mode="PASSIVE_OSINT",
                started_at=utcnow(),
                finished_at=utcnow(),
                run_id=run.id,
                entities=[entity],
                findings=[
                    Finding(
                        module="username",
                        title="GitHub",
                        status=FindingStatus.FOUND,
                        summary="GitHub: CONFIRMED",
                        data={
                            "platform": "GitHub",
                            "username": "alice",
                            "check_status": "CONFIRMED",
                            "profile_url": "https://github.com/alice",
                            "observed": observed,
                        },
                        confidence=Confidence.CONFIRMED,
                        entity_id=entity.id,
                    )
                ],
            )
        )
        manager.finish_run(run.id, status="completed")
        loaded = manager.load_result("mixed-provenance")
        assert loaded is not None
        stored = loaded.findings[0].data["observed"]
        assert [
            (i["value"], i["source"], i["source_method"]) for i in stored["social_links"]["items"]
        ] == expected
        assert parse_observed(stored).to_transport() == observed
    finally:
        reset_engine()


def test_presentation_and_flatten_ignore_item_provenance() -> None:
    observed = _mixed_observed()
    rows = observed_profile_fields({"observed": observed})
    social = next(r for r in rows if r["field"] == "social_links")
    assert social["value"] == observed["social_links"]["value"]
    assert social["source"] == "multiple"
    assert set(social) == {"field", "value", "source", "observed_at", "kind"}
    assert flatten_observed(observed)["public_links"] == [
        "https://x.com/alice",
        "https://github.com/alice",
        "https://mastodon.social/@alice",
    ]


# Codex P2 (comment 3930279744). A row carrying `items` must not contradict them.
def test_row_contradicting_its_items_is_rejected() -> None:
    truthful = _mixed_observed()["social_links"]

    def mutated(**overrides: object) -> dict:
        return parse_observed({"social_links": {**truthful, **overrides}})

    # A value the items never observed.
    with pytest.raises(ValidationError):
        mutated(value=[*truthful["value"], "https://evil.example/alice"])
    # A single source claimed over heterogeneous items.
    with pytest.raises(ValidationError):
        mutated(source="html_rel_me")
    with pytest.raises(ValidationError):
        mutated(source_method="HTML")
    # Row metadata the items do not support.
    with pytest.raises(ValidationError):
        mutated(provider_slug="gitlab")
    with pytest.raises(ValidationError):
        mutated(source_url="https://elsewhere.example/")
    with pytest.raises(ValidationError):
        mutated(observed_at="2030-01-01T00:00:00+00:00")
    # Reordering the compatibility list no longer matches first-seen order.
    with pytest.raises(ValidationError):
        mutated(value=list(reversed(truthful["value"])))
    # A scalar row may not carry items, and an empty items list is not an observation.
    with pytest.raises(ValidationError):
        mutated(value="https://x.com/alice", original="https://x.com/alice")
    with pytest.raises(ValidationError):
        mutated(items=[])

    # The truthful row itself round-trips.
    assert parse_observed({"social_links": truthful}).to_transport() == {"social_links": truthful}


def test_row_level_rejection_is_independent_of_items() -> None:
    """rejected_by describes the field, not the items, so it is not projected."""
    truthful = _mixed_observed()["social_links"]
    parsed = parse_observed({"social_links": {**truthful, "rejected_by": "some_future_rule"}})
    assert parsed["social_links"].rejected_by == "some_future_rule"
    assert parsed["social_links"].items is not None


# Codex P2 (comment 3930386406). MIXED is a row marker, never an acquisition method.
def test_mixed_is_not_a_valid_item_or_itemless_row_method() -> None:
    truthful = _mixed_observed()["social_links"]

    # An item may not claim MIXED: it would leave the authoritative record with no
    # real acquisition method.
    with pytest.raises(ValidationError):
        ObservedItem(
            value="https://x.com/alice",
            original="https://x.com/alice",
            source="html_rel_me",
            observed_at=_STAMP,
            source_method=SourceMethod.MIXED,
        )
    # Not even when the row-level method would agree with it.
    with pytest.raises(ValidationError):
        parse_observed(
            {
                "social_links": {
                    "value": ["https://x.com/alice"],
                    "original": ["https://x.com/alice"],
                    "source": "html_rel_me",
                    "source_method": "MIXED",
                    "observed_at": _STAMP,
                    "items": [
                        {
                            "value": "https://x.com/alice",
                            "original": "https://x.com/alice",
                            "source": "html_rel_me",
                            "source_method": "MIXED",
                            "observed_at": _STAMP,
                        }
                    ],
                }
            }
        )

    # A row without items has nothing for MIXED to point at.
    with pytest.raises(ValidationError):
        parse_observed(
            {
                "social_links": {
                    "value": ["https://x.com/alice"],
                    "original": ["https://x.com/alice"],
                    "source": "multiple",
                    "source_method": "MIXED",
                    "observed_at": _STAMP,
                }
            }
        )
    # Named a real extractor, so only the MIXED rule can reject it — an item-less
    # `source: "multiple"` is refused on its own account, see the marker test below.
    with pytest.raises(ValidationError) as itemless:
        parse_observed(
            {
                "social_links": {
                    "value": ["https://x.com/alice"],
                    "original": ["https://x.com/alice"],
                    "source": "html_rel_me",
                    "source_method": "MIXED",
                    "observed_at": _STAMP,
                }
            }
        )
    assert "needs items to point at" in str(itemless.value)

    # A row over genuinely heterogeneous items still uses it.
    assert truthful["source_method"] == "MIXED"
    assert all(i["source_method"] in {"JSON_API", "HTML"} for i in truthful["items"])
    assert EXTRACTION_METHODS == {
        SourceMethod.INPUT,
        SourceMethod.JSON_API,
        SourceMethod.HTML,
        SourceMethod.AUTHENTICATED_PUBLIC,
        SourceMethod.DERIVED,
    }
    assert SourceMethod.MIXED not in EXTRACTION_METHODS


# Codex P2 (comment 3930465367). Rejection is field-level; an item may not carry it.
def test_item_may_not_carry_rejection_metadata() -> None:
    truthful = _mixed_observed()["social_links"]

    # The valid list observation is untouched, and no emitted item carries rejection.
    assert parse_observed({"social_links": truthful}).to_transport() == {"social_links": truthful}
    assert all("rejected_by" not in item for item in truthful["items"])

    # One nested item gains `rejected_by` and nothing else, so every row and item
    # projection field stays truthful. The payload is refused because the key is
    # forbidden on an item, not because the row was made to contradict its items.
    poisoned = {
        **truthful,
        "items": [
            {**item, "rejected_by": "some_rule"} if index == 0 else dict(item)
            for index, item in enumerate(truthful["items"])
        ],
    }
    with pytest.raises(ValidationError) as exc:
        parse_observed({"social_links": poisoned})
    message = str(exc.value)
    assert "extra_forbidden" in message
    assert "items.0.rejected_by" in message
    assert "row contradicts its items" not in message

    # An item has no rejection state to begin with; the field keeps its own.
    assert "rejected_by" not in ObservedItem.model_fields
    assert "rejected_by" in ObservedField.model_fields
    with pytest.raises(ValidationError) as direct:
        ObservedItem(
            value="https://x.com/alice",
            original="https://x.com/alice",
            source="html_rel_me",
            observed_at=_STAMP,
            rejected_by="some_rule",  # type: ignore[call-arg]
        )
    assert "extra_forbidden" in str(direct.value)


# Codex P2 (comment 3934332467). INPUT is operator input, so it has no source URL.
def _input_row(**overrides: object) -> dict:
    row = {
        "value": "alice",
        "original": "alice",
        "source": "github.username",
        "observed_at": _STAMP,
        "provider_slug": "github",
        "source_method": "INPUT",
    }
    row.update(overrides)
    return row


def test_input_provenance_cannot_claim_a_source_url() -> None:
    url = "https://example.test/alice"

    # Scalar row, the reproduction path: every other key is truthful, and the payload is
    # refused for naming a page operator input was never read from.
    with pytest.raises(ValidationError) as exc:
        parse_observed({"username": _input_row(source_url=url)})
    assert [e["loc"] for e in exc.value.errors()] == [("username",)]
    assert "INPUT" in str(exc.value) and "source_url" in str(exc.value)
    # Directly, too, and an empty string is not a weaker claim worth preserving.
    with pytest.raises(ValidationError):
        ObservedField(
            value="alice",
            original="alice",
            source="github.username",
            observed_at=_STAMP,
            source_method=SourceMethod.INPUT,
            source_url=url,
        )
    with pytest.raises(ValidationError):
        ObservedField(
            value="alice",
            original="alice",
            source="github.username",
            observed_at=_STAMP,
            source_method=SourceMethod.INPUT,
            source_url="",
        )

    # An individual INPUT item may not claim it either. The row here is exactly the
    # projection its one item produces, so nothing but this invariant can reject it.
    truthful_item = _input_row()
    truthful = {
        **_input_row(),
        "value": ["alice"],
        "original": ["alice"],
        "items": [truthful_item],
    }
    assert parse_observed({"aliases": truthful}).to_transport() == {"aliases": truthful}

    poisoned = {
        **truthful,
        "source_url": url,
        "items": [{**truthful_item, "source_url": url}],
    }
    with pytest.raises(ValidationError) as item_exc:
        parse_observed({"aliases": poisoned})
    assert [e["loc"] for e in item_exc.value.errors()] == [("aliases", "items", 0)]
    message = str(item_exc.value)
    assert "INPUT" in message and "source_url" in message
    assert "row contradicts its items" not in message
    with pytest.raises(ValidationError):
        ObservedItem(
            value="alice",
            original="alice",
            source="github.username",
            observed_at=_STAMP,
            source_method=SourceMethod.INPUT,
            source_url=url,
        )


def test_network_origins_still_carry_a_source_url() -> None:
    url = "https://example.test/alice"

    # Every real acquisition origin still records where the payload was read from.
    for method in (
        SourceMethod.JSON_API,
        SourceMethod.HTML,
        SourceMethod.AUTHENTICATED_PUBLIC,
        SourceMethod.DERIVED,
    ):
        # A derived observation must also name its origin; that coupling is its own
        # invariant, tested separately. Here it only keeps the fixture legal.
        origin = {"derived_from": "website"} if method == SourceMethod.DERIVED else {}
        field = ObservedField(
            value="alice",
            original="alice",
            source="s",
            observed_at=_STAMP,
            source_method=method,
            source_url=url,
            **origin,
        )
        assert field.to_transport()["source_url"] == url, method
        item = ObservedItem(
            value="alice", original="alice", source="s", observed_at=_STAMP,
            source_method=method, source_url=url, **origin,
        )
        assert item.to_transport()["source_url"] == url, method

    # INPUT without a URL is the valid shape, and a row that names no method at all is
    # unaffected — the invariant is about the contradiction, not about URLs.
    assert "source_url" not in ObservedField(**_input_row()).to_transport()
    assert ObservedField(
        value="alice", original="alice", source="s", observed_at=_STAMP, source_url=url
    ).to_transport()["source_url"] == url

    # And the writer already emitted it correctly: the handle is INPUT and claims no URL,
    # so everything enrich_profile() produces satisfies the invariant.
    observed = _github_observed(source_url="https://api.github.com/users/alice")
    assert observed["username"]["source_method"] == "INPUT"
    assert "source_url" not in observed["username"]
    assert observed["display_name"]["source_url"] == "https://api.github.com/users/alice"
    assert parse_observed(observed).to_transport() == observed


# Codex P2 (comment 3934699489). MIXED must prove two known acquisition methods.
def _plain_item(value: str, source: str, method: SourceMethod | None = None) -> ObservedItem:
    return ObservedItem(
        value=value, original=value, source=source, observed_at=_STAMP, source_method=method
    )


def test_mixed_needs_more_than_one_known_item_method() -> None:
    def projected(*items: ObservedItem) -> SourceMethod | None:
        method = project_items(list(items))["source_method"]
        # from_items() builds through the same projection, so the two cannot drift.
        assert ObservedField.from_items(list(items)).source_method == method
        return method

    json_api = _plain_item("a", "api.field", SourceMethod.JSON_API)
    also_json = _plain_item("b", "api.field", SourceMethod.JSON_API)
    html = _plain_item("c", "html_rel_me", SourceMethod.HTML)
    unknown = _plain_item("d", "legacy.field", None)
    other_unknown = _plain_item("e", "legacy.other", None)

    # One known method, however many items prove it.
    assert projected(json_api, also_json) == SourceMethod.JSON_API
    # Two distinct known methods: MIXED means exactly this.
    assert projected(json_api, html) == SourceMethod.MIXED
    # An unknown method is not evidence of a second origin, so the row's is unknown too.
    assert projected(json_api, unknown) is None
    assert projected(unknown, other_unknown) is None
    assert projected(json_api, html, unknown) is None

    # The row/items contract is what rejects a serialized row claiming MIXED anyway. The
    # truthful row is identical but for that key, so the failure is the false projection.
    def row(**overrides: object) -> dict:
        return {
            "value": ["a", "d"],
            "original": ["a", "d"],
            "source": MULTIPLE_SOURCES,
            "observed_at": _STAMP,
            "items": [
                {
                    "value": "a",
                    "original": "a",
                    "source": "api.field",
                    "observed_at": _STAMP,
                    "source_method": "JSON_API",
                },
                {"value": "d", "original": "d", "source": "legacy.field", "observed_at": _STAMP},
            ],
            **overrides,
        }

    truthful = row()
    assert parse_observed({"social_links": truthful}).to_transport() == {"social_links": truthful}
    assert "source_method" not in truthful

    with pytest.raises(ValidationError) as exc:
        parse_observed({"social_links": row(source_method="MIXED")})
    assert "row contradicts its items on source_method" in str(exc.value)


# Codex P2 (comment 3934699504). An observation is scalar or list-valued, not half of each.
def test_value_and_original_must_share_one_shape() -> None:
    def row(value: object, original: object) -> dict:
        return {"value": value, "original": original, "source": "s", "observed_at": _STAMP}

    # Both shapes are valid on their own, and `original` need not equal `value`.
    assert parse_observed({"bio": row("a", "a")})["bio"].value == "a"
    listed = parse_observed({"social_links": row(["a", "b"], ["raw a", "raw b"])})
    assert listed["social_links"].original == ["raw a", "raw b"]

    # Mixing them is neither shape. Both directions, through the serialized contract.
    for value, original in (("a", ["a"]), (["a"], "a")):
        with pytest.raises(ValidationError) as exc:
            parse_observed({"bio": row(value, original)})
        assert [e["loc"] for e in exc.value.errors()] == [("bio",)]
        assert "both be scalar or both be lists" in str(exc.value)
    # Directly, too.
    with pytest.raises(ValidationError):
        ObservedField(value="a", original=["a"], source="s", observed_at=_STAMP)
    with pytest.raises(ValidationError):
        ObservedField(value=["a"], original="a", source="s", observed_at=_STAMP)

    # Legacy rows of either shape are untouched.
    legacy_scalar = {"display_name": _legacy_row()}
    assert parse_observed(legacy_scalar).to_transport() == legacy_scalar
    legacy_list = {
        "social_links": {
            "value": ["https://x.com/alice", "https://github.com/alice"],
            "original": ["https://x.com/alice", "https://github.com/alice"],
            "source": "html_rel_me",
            "observed_at": _STAMP,
        }
    }
    assert parse_observed(legacy_list).to_transport() == legacy_list


# Final-gate blocker A. DERIVED and derived_from are two halves of one statement.
def test_derived_metadata_must_agree_with_the_method() -> None:
    def field(**overrides: object) -> ObservedField:
        params: dict = {
            "value": "alice.dev",
            "original": "alice.dev",
            "source": "github_api.blog",
            "observed_at": _STAMP,
        }
        params.update(overrides)
        return ObservedField(**params)

    # A derived observation naming its origin is the valid shape.
    assert field(source_method=SourceMethod.DERIVED, derived_from="website").derived_from == "website"
    # The token is not interpreted, so a future origin is not blocked by vocabulary.
    assert field(source_method=SourceMethod.DERIVED, derived_from="avatar_url").derived_from == "avatar_url"

    # A derivation with no origin, or a blank one, says nothing.
    with pytest.raises(ValidationError) as exc:
        field(source_method=SourceMethod.DERIVED)
    assert "must name the field it was derived from" in str(exc.value)
    with pytest.raises(ValidationError):
        field(source_method=SourceMethod.DERIVED, derived_from="")
    # And only a derivation may name one.
    for method in (SourceMethod.JSON_API, SourceMethod.HTML, SourceMethod.AUTHENTICATED_PUBLIC):
        with pytest.raises(ValidationError) as wrong:
            field(source_method=method, derived_from="website")
        assert "belongs to a DERIVED observation" in str(wrong.value), method
    with pytest.raises(ValidationError):
        field(derived_from="website")

    # Same invariant on an item.
    item = ObservedItem(
        value="alice.dev",
        original="alice.dev",
        source="github_api.blog",
        observed_at=_STAMP,
        source_method=SourceMethod.DERIVED,
        derived_from="website",
    )
    assert item.derived_from == "website"
    with pytest.raises(ValidationError):
        _plain_item("alice.dev", "github_api.blog", SourceMethod.DERIVED)
    with pytest.raises(ValidationError):
        ObservedItem(
            value="x",
            original="x",
            source="html_rel_me",
            observed_at=_STAMP,
            source_method=SourceMethod.HTML,
            derived_from="website",
        )

    # The writer still emits the coupled pair, and its output still validates.
    observed = _github_observed()
    assert observed["personal_domain"]["source_method"] == "DERIVED"
    assert observed["personal_domain"]["derived_from"] == "website"
    assert "derived_from" not in observed["website"]
    assert parse_observed(observed).to_transport() == observed


def test_a_derived_item_beside_a_network_item_still_projects_a_valid_row() -> None:
    """The invariant is per item and on the row's own metadata, not row-wide."""
    derived = ObservedItem(
        value="alice.dev",
        original="alice.dev",
        source="github_api.blog",
        observed_at=_STAMP,
        source_method=SourceMethod.DERIVED,
        derived_from="website",
    )
    api = _plain_item("https://x.com/alice", "github_api.twitter_username", SourceMethod.JSON_API)

    row = ObservedField.from_items([derived, api])
    assert row.source == MULTIPLE_SOURCES
    assert row.source_method == SourceMethod.MIXED
    # The items disagree on derivation, so the row claims none — and so may not carry it.
    assert row.derived_from is None
    assert row.items is not None and row.items[0].derived_from == "website"
    assert parse_observed({"f": row.to_transport()}).to_transport() == {"f": row.to_transport()}

    # When every item derives from the same field, the row does share the origin, and
    # then it must keep naming it — the invariant reads the row's own metadata.
    shared = ObservedField.from_items(
        [
            derived,
            ObservedItem(
                value="alice.example",
                original="alice.example",
                source="html_rel_me",
                observed_at=_STAMP,
                source_method=SourceMethod.DERIVED,
                derived_from="website",
            ),
        ]
    )
    assert shared.source_method == SourceMethod.DERIVED
    assert shared.derived_from == "website"
    assert shared.source == MULTIPLE_SOURCES


# Final-gate blocker B. The "multiple" marker points at items; without them, at nothing.
def test_multiple_source_marker_requires_items() -> None:
    assert MULTIPLE_SOURCES == "multiple"

    with pytest.raises(ValidationError) as exc:
        parse_observed(
            {
                "social_links": {
                    "value": ["https://x.com/alice", "https://github.com/alice"],
                    "original": ["https://x.com/alice", "https://github.com/alice"],
                    "source": MULTIPLE_SOURCES,
                    "observed_at": _STAMP,
                    "source_method": "HTML",
                }
            }
        )
    assert "the real sources are in items" in str(exc.value)
    # Including on a scalar row, which never had items to point at.
    with pytest.raises(ValidationError):
        ObservedField(
            value="a", original="a", source=MULTIPLE_SOURCES, observed_at=_STAMP
        )

    # An ordinary item-less row keeps working, legacy rows included.
    assert ObservedField(**_legacy_row()).source == "github_api.name"
    # And a heterogeneous list built through the projection still uses the marker.
    row = ObservedField.from_items(
        [
            _plain_item("https://x.com/alice", "github_api.twitter_username", SourceMethod.JSON_API),
            _plain_item("https://github.com/alice", "html_jsonld.sameAs", SourceMethod.HTML),
        ]
    )
    assert row.source == MULTIPLE_SOURCES
    assert row.items is not None
    assert parse_observed({"f": row.to_transport()}).to_transport() == {"f": row.to_transport()}
    # The marker is a row-level projection, and an item may not claim it either: that is
    # its own invariant, proved in test_the_row_marker_is_not_an_item_source below. This
    # line asserted the opposite until that rule landed.
    with pytest.raises(ValidationError):
        _plain_item("a", MULTIPLE_SOURCES, SourceMethod.HTML)


# Codex P2 (comment 3935572410). An aggregate row may defer heterogeneous derivation
# origins to its items; every other DERIVED observation still names its own.
def _derived_item(value: str, origin: str, source: str = "derived.rule") -> ObservedItem:
    return ObservedItem(
        value=value,
        original=value,
        source=source,
        observed_at=_STAMP,
        source_method=SourceMethod.DERIVED,
        derived_from=origin,
    )


def _derived_row(items: list[ObservedItem], **overrides: object) -> dict:
    """A serialized row over `items`, truthful unless an override makes it lie."""
    row: dict = {
        "value": [item.value for item in items],
        "original": [item.original for item in items],
        "source": "derived.rule",
        "observed_at": _STAMP,
        "source_method": "DERIVED",
        "items": [item.to_transport() for item in items],
    }
    row.update(overrides)
    return row


def test_derived_items_with_different_origins_still_form_a_row() -> None:
    website = _derived_item("alice.dev", "website")
    avatar = _derived_item("alice.example", "avatar_url")
    # Both items are individually valid: each knows its own origin.
    assert (website.derived_from, avatar.derived_from) == ("website", "avatar_url")

    projected = project_items([website, avatar])
    assert projected["source_method"] == SourceMethod.DERIVED
    assert projected["derived_from"] is None

    row = ObservedField.from_items([website, avatar])
    assert row.source_method == SourceMethod.DERIVED
    assert row.derived_from is None
    assert row.items is not None
    # The exact origins survive where they are true: on the items.
    assert [item.derived_from for item in row.items] == ["website", "avatar_url"]
    assert "derived_from" not in row.to_transport()
    transport = {"f": row.to_transport()}
    assert parse_observed(transport).to_transport() == transport
    # And through the serialized door, not only the constructor.
    assert parse_observed({"f": _derived_row([website, avatar])}).to_transport() == transport

    # Same-origin control: the shared origin is projected, so the row must carry it.
    shared = ObservedField.from_items([website, _derived_item("alice.test", "website")])
    assert shared.derived_from == "website"
    with pytest.raises(ValidationError) as deleted:
        parse_observed({"f": _derived_row([website, _derived_item("alice.test", "website")])})
    assert "row contradicts its items on derived_from" in str(deleted.value)
    # One item is the same case: there is a shared origin, so it may not be dropped.
    with pytest.raises(ValidationError):
        parse_observed({"f": _derived_row([website])})

    # Malicious control: an origin no item supports is not deferral, it is invention.
    with pytest.raises(ValidationError) as invented:
        parse_observed({"f": _derived_row([website, avatar], derived_from="profile")})
    assert "row contradicts its items on derived_from" in str(invented.value)

    # And the method itself may not be borrowed: items that never derived anything.
    api = _plain_item("a", "github_api.x", SourceMethod.JSON_API)
    other = _plain_item("b", "github_api.y", SourceMethod.JSON_API)
    with pytest.raises(ValidationError) as borrowed:
        parse_observed(
            {
                "f": {
                    "value": ["a", "b"],
                    "original": ["a", "b"],
                    "source": MULTIPLE_SOURCES,
                    "observed_at": _STAMP,
                    "source_method": "DERIVED",
                    "items": [api.to_transport(), other.to_transport()],
                }
            }
        )
    assert "row contradicts its items on source_method" in str(borrowed.value)

    # The relaxation is aggregate-only. A standalone derived row has nowhere to defer to.
    with pytest.raises(ValidationError) as standalone:
        ObservedField(
            value="alice.dev",
            original="alice.dev",
            source="github_api.blog",
            observed_at=_STAMP,
            source_method=SourceMethod.DERIVED,
        )
    assert "must name the field it was derived from" in str(standalone.value)
    # Nor may an item defer: it is the authoritative record of one derivation.
    with pytest.raises(ValidationError):
        _plain_item("alice.dev", "github_api.blog", SourceMethod.DERIVED)

    # Heterogeneous acquisition methods are unchanged: MIXED, and no row origin.
    mixed = ObservedField.from_items([website, api])
    assert mixed.source_method == SourceMethod.MIXED
    assert mixed.derived_from is None
    assert mixed.source == MULTIPLE_SOURCES


# Codex P2 (comment 3935572418). A derivation origin must say something.
def test_whitespace_only_derivation_origins_are_rejected() -> None:
    blank = ("", " ", "   ", "\t", "\n", " \t ")

    for origin in blank:
        with pytest.raises(ValidationError) as row:
            ObservedField(
                value="alice.dev",
                original="alice.dev",
                source="github_api.blog",
                observed_at=_STAMP,
                source_method=SourceMethod.DERIVED,
                derived_from=origin,
            )
        # Attributable to this rule, not to some unrelated one.
        assert [e["loc"] for e in row.value.errors()] == [()], origin
        assert "must name the field it was derived from" in str(row.value), origin

        with pytest.raises(ValidationError) as item:
            ObservedItem(
                value="alice.dev",
                original="alice.dev",
                source="derived.rule",
                observed_at=_STAMP,
                source_method=SourceMethod.DERIVED,
                derived_from=origin,
            )
        assert "must name the field it was derived from" in str(item.value), origin

    # Through the serialized contract, on the row and on a nested item.
    with pytest.raises(ValidationError) as serialized:
        parse_observed(
            {
                "personal_domain": {
                    "value": "alice.dev",
                    "original": "alice.dev",
                    "source": "github_api.blog",
                    "observed_at": _STAMP,
                    "source_method": "DERIVED",
                    "derived_from": "   ",
                }
            }
        )
    assert [e["loc"] for e in serialized.value.errors()] == [("personal_domain",)]
    assert "a blank origin names nothing" in str(serialized.value)

    with pytest.raises(ValidationError) as nested:
        parse_observed(
            {
                "f": {
                    "value": ["alice.dev"],
                    "original": ["alice.dev"],
                    "source": "derived.rule",
                    "observed_at": _STAMP,
                    "source_method": "DERIVED",
                    "derived_from": "website",
                    "items": [
                        {
                            "value": "alice.dev",
                            "original": "alice.dev",
                            "source": "derived.rule",
                            "observed_at": _STAMP,
                            "source_method": "DERIVED",
                            "derived_from": "  ",
                        }
                    ],
                }
            }
        )
    assert [e["loc"] for e in nested.value.errors()] == [("f", "items", 0)]
    assert "a blank origin names nothing" in str(nested.value)

    # A real token stays valid and is never rewritten: no trimming, no normalization.
    kept = _derived_item("alice.dev", "website")
    assert kept.to_transport()["derived_from"] == "website"
    padded = _derived_item("alice.dev", " website ")
    assert padded.to_transport()["derived_from"] == " website "
    # And the row-level aggregate absence stays legal — see the P2 above.
    row = ObservedField.from_items([kept, _derived_item("alice.example", "avatar_url")])
    assert row.derived_from is None


# Codex P2 (comment 3935572425). Two lists that pair up, or they pair up with nothing.
def test_list_value_and_original_must_have_equal_cardinality() -> None:
    def row(value: object, original: object) -> dict:
        return {
            "value": value,
            "original": original,
            "source": "html_rel_me",
            "observed_at": _STAMP,
        }

    # A legacy item-less list row pairs up and stays valid, `original` differing freely.
    paired = {"social_links": row(["a", "b"], ["raw-a", "raw-b"])}
    assert parse_observed(paired).to_transport() == paired
    assert parse_observed(paired)["social_links"].original == ["raw-a", "raw-b"]
    # Order is untouched, and equal values are not deduplicated by this rule.
    repeated = {"social_links": row(["a", "a"], ["raw-b", "raw-a"])}
    assert parse_observed(repeated).to_transport() == repeated

    # Unequal lists cannot be paired, in either direction, through either door.
    for value, original in ((["a", "b"], ["raw-a"]), (["a"], ["raw-a", "raw-b"])):
        with pytest.raises(ValidationError) as exc:
            parse_observed({"social_links": row(value, original)})
        assert [e["loc"] for e in exc.value.errors()] == [("social_links",)]
        assert "must pair up one to one" in str(exc.value)
        with pytest.raises(ValidationError) as direct:
            ObservedField(**row(value, original))
        assert "must pair up one to one" in str(direct.value)

    # The shape rule is unchanged and still fires first for a mismatch of kind.
    for value, original in (("a", ["a"]), (["a"], "a")):
        with pytest.raises(ValidationError) as shape:
            ObservedField(**row(value, original))
        assert "both be scalar or both be lists" in str(shape.value)
    # Scalars are unaffected, and a legacy scalar row still round-trips.
    legacy = {"display_name": _legacy_row()}
    assert parse_observed(legacy).to_transport() == legacy

    # `project_items()` builds the two lists in step, so every projected row pairs up.
    projected = ObservedField.from_items(
        [
            _plain_item("https://x.com/alice", "github_api.twitter_username", SourceMethod.JSON_API),
            _plain_item("https://x.com/alice", "html_rel_me", SourceMethod.HTML),
            _plain_item("https://github.com/alice", "html_jsonld.sameAs", SourceMethod.HTML),
        ]
    )
    assert isinstance(projected.value, list) and isinstance(projected.original, list)
    assert len(projected.value) == len(projected.original) == 2
    assert len(projected.items or []) == 3


# Independent final-gate correction. "multiple" is an aggregate row marker, not an
# extractor, so an individual item may not claim it — the `source` half of the rule
# `_reject_row_only_marker` already applies to `source_method`.
def test_the_row_marker_is_not_an_item_source() -> None:
    with pytest.raises(ValidationError) as direct:
        ObservedItem(
            value="https://x.com/alice",
            original="https://x.com/alice",
            source=MULTIPLE_SOURCES,
            observed_at=_STAMP,
            source_method=SourceMethod.HTML,
        )
    assert [e["loc"] for e in direct.value.errors()] == [("source",)]
    assert "row-level aggregation marker" in str(direct.value)

    # Serialized, inside a row that is otherwise entirely truthful: the item's method is
    # a real extraction method, it names no URL, carries no rejection metadata, and the
    # row *is* the exact projection of that item — `sources` has one member, so the row
    # legitimately reads "multiple" too. Only the item-level rule can reject this, which
    # is the impersonation: one item, one extractor, and a row claiming aggregation.
    payload = {
        "social_links": {
            "value": ["https://x.com/alice"],
            "original": ["https://x.com/alice"],
            "source": MULTIPLE_SOURCES,
            "observed_at": _STAMP,
            "source_method": "HTML",
            "items": [
                {
                    "value": "https://x.com/alice",
                    "original": "https://x.com/alice",
                    "source": MULTIPLE_SOURCES,
                    "observed_at": _STAMP,
                    "source_method": "HTML",
                }
            ],
        }
    }
    with pytest.raises(ValidationError) as nested:
        parse_observed(payload)
    assert [e["loc"] for e in nested.value.errors()] == [
        ("social_links", "items", 0, "source")
    ]
    assert "row-level aggregation marker" in str(nested.value)
    assert "row contradicts its items" not in str(nested.value)

    # Only the exact reserved string is reserved. Nothing else about `source` changes.
    for source in ("html_rel_me", "github_api.name", "multiple_source_test", "Multiple"):
        assert _plain_item("a", source, SourceMethod.HTML).source == source

    # Real heterogeneous extractors still project the marker at the row level.
    row = ObservedField.from_items(
        [
            _plain_item("https://x.com/alice", "html_jsonld.sameAs", SourceMethod.HTML),
            _plain_item("https://github.com/alice", "html_rel_me", SourceMethod.HTML),
        ]
    )
    assert row.source == MULTIPLE_SOURCES
    assert row.source_method == SourceMethod.HTML
    assert parse_observed({"f": row.to_transport()}).to_transport() == {"f": row.to_transport()}
    # And the item-less marker rule is unchanged.
    with pytest.raises(ValidationError):
        ObservedField(value="a", original="a", source=MULTIPLE_SOURCES, observed_at=_STAMP)
