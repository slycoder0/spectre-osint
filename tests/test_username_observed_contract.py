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
    LEGACY_KEYS,
    ObservedField,
    ObservedFields,
    SourceMethod,
    parse_observed,
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

    assert {m.value for m in SourceMethod} == {
        "INPUT",
        "JSON_API",
        "HTML",
        "AUTHENTICATED_PUBLIC",
        "DERIVED",
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
    assert sources["social_links"] == "html_rel_me"
    assert sources["external_links"] == "html_jsonld.sameAs"
    assert sources["avatar_url"] == "html_og.image"
    assert sources["username"] == "example_site.username"


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
