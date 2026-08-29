from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.types import AccessMode, Confidence, EntityType, UsernameCheckStatus
from spectre_osint.modules.username.catalog import (
    CatalogValidationError,
    CheckMethod,
    ConfidenceStrategy,
    SiteCatalog,
    SiteDefinition,
    clear_catalog_cache,
    load_catalog,
    slugify_name,
)
from spectre_osint.modules.username.engine import _check_site, load_sites


def _valid_site_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "Example Service",
        "category": "Development",
        "profile_url": "https://example.com/users/{username}",
        "check_method": "generic_html",
        "confidence_strategy": "multi_signal",
        "expected_status": [200],
        "not_found_status": [404],
        "enabled": True,
        "success_patterns": ["user-profile"],
        "not_found_patterns": ["page not found"],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Section 19: Permanent Catalog-wide Invariant Test
# ---------------------------------------------------------------------------


def test_every_production_site_validates_successfully() -> None:
    """Invariant: Every single site in sites.yaml must validate without error."""
    clear_catalog_cache()
    catalog = load_catalog(reload=True)
    assert catalog.total_sites() == 57
    assert len(catalog.sites) == 57

    # Validate each individual site and verify that failure output would identify the site
    for site in catalog.sites:
        assert site.slug, f"Site {site.name} missing slug"
        assert site.name, f"Site {site.slug} missing display name"
        assert site.category, f"Site {site.slug} missing category"
        assert "{username}" in site.profile_url, f"Site {site.slug} profile_url missing {{username}}"
        assert site.detection.strategy in {
            CheckMethod.GENERIC_HTML,
            CheckMethod.JSON_API,
            CheckMethod.LOGIN_WALL,
        }, f"Site {site.slug} has invalid strategy"
        assert site.detection.confidence_strategy in {
            ConfidenceStrategy.EXPLICIT_API,
            ConfidenceStrategy.MULTI_SIGNAL,
            ConfidenceStrategy.NEVER_CONFIRMED,
        }, f"Site {site.slug} has invalid confidence strategy"


# ---------------------------------------------------------------------------
# Duplicate YAML Mapping Key Tests (Hardening B2-02A.3)
# ---------------------------------------------------------------------------


def test_duplicate_yaml_mapping_keys_rejected(tmp_path: Any) -> None:
    # 1. Duplicate top-level keys
    dup_top_yaml = tmp_path / "dup_top.yaml"
    dup_top_yaml.write_text("sites:\n  - name: Site A\n    profile_url: https://a.example/{username}\nsites:\n  - name: Site B\n    profile_url: https://b.example/{username}\n")
    with pytest.raises(CatalogValidationError) as exc:
        SiteCatalog.from_yaml_file(dup_top_yaml)
    assert "Duplicate mapping key 'sites'" in str(exc.value)
    assert "line 4" in str(exc.value)

    # 2. Duplicate key inside site definition
    dup_site_yaml = tmp_path / "dup_site.yaml"
    dup_site_yaml.write_text("sites:\n  - name: Site A\n    profile_url: https://one.example/{username}\n    profile_url: https://two.example/{username}\n")
    with pytest.raises(CatalogValidationError) as exc:
        SiteCatalog.from_yaml_file(dup_site_yaml)
    assert "Duplicate mapping key 'profile_url'" in str(exc.value)

    # 3. Duplicate key inside nested mapping
    dup_nested_yaml = tmp_path / "dup_nested.yaml"
    dup_nested_yaml.write_text("sites:\n  - name: Site A\n    profile_url: https://one.example/{username}\n    detection:\n      strategy: generic_html\n      strategy: json_api\n")
    with pytest.raises(CatalogValidationError) as exc:
        SiteCatalog.from_yaml_file(dup_nested_yaml)
    assert "Duplicate mapping key 'strategy'" in str(exc.value)


# ---------------------------------------------------------------------------
# Real Format-String & URL Validation Tests (Hardening B2-02A.3)
# ---------------------------------------------------------------------------


def test_format_string_unbalanced_and_invalid_syntax_rejected() -> None:
    malformed_templates = [
        ("https://example.com/{username}{", "unbalanced opening brace"),
        ("https://example.com/{username}}", "unbalanced closing brace"),
        ("https://example.com/{username!r}", "conversion flag"),
        ("https://example.com/{username:>20}", "format specifier"),
        ("https://example.com/{username.value}", "attribute access"),
        ("https://example.com/{0}", "positional placeholder"),
        ("https://example.com/{other}", "unknown placeholder"),
    ]
    for url, desc in malformed_templates:
        with pytest.raises(Exception) as exc:
            SiteDefinition.model_validate(_valid_site_dict(profile_url=url))
        err_msg = str(exc.value).lower()
        assert "placeholder" in err_msg or "format" in err_msg or "unbalanced" in err_msg or "syntax" in err_msg, f"Failed on {desc}"


def test_url_whitespace_corruption_rejected() -> None:
    bad_urls = [
        "https://exa mple.com/{username}",
        "https://example.com/ {username}",
        "https://example.com/{username} ",
        " https://example.com/{username}",
    ]
    for bad_url in bad_urls:
        with pytest.raises(Exception) as exc:
            SiteDefinition.model_validate(_valid_site_dict(profile_url=bad_url))
        assert "whitespace" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# Pydantic Input Redaction Tests (Hardening B2-02A.3)
# ---------------------------------------------------------------------------


def test_pydantic_validation_error_redacts_credentials() -> None:
    secret_pass = "pw123"
    secret_user = "user_abc"
    bad_url = f"https://{secret_user}:{secret_pass}@example.com/{{username}}"

    with pytest.raises(ValidationError) as pydantic_exc:
        SiteDefinition.model_validate(_valid_site_dict(profile_url=bad_url))

    val_err_str = str(pydantic_exc.value)
    val_err_repr = repr(pydantic_exc.value)
    assert secret_pass not in val_err_str
    assert secret_user not in val_err_str
    assert secret_pass not in val_err_repr
    assert secret_user not in val_err_repr

    with pytest.raises(CatalogValidationError) as cat_exc:
        SiteCatalog.from_dict({"sites": [_valid_site_dict(name="SecretSite", profile_url=bad_url)]})

    cat_err_str = str(cat_exc.value)
    assert secret_pass not in cat_err_str
    assert secret_user not in cat_err_str
    assert "userinfo" in cat_err_str or "credential" in cat_err_str


# ---------------------------------------------------------------------------
# Strict Field Type Tests (Hardening B2-02A.3)
# ---------------------------------------------------------------------------


def test_strict_field_types_rejected() -> None:
    # name must be string
    with pytest.raises(Exception) as exc:
        SiteDefinition.model_validate(_valid_site_dict(name=123))
    assert "string" in str(exc.value).lower()

    # slug must be string
    with pytest.raises(Exception) as exc:
        SiteDefinition.model_validate(_valid_site_dict(slug=456))
    assert "string" in str(exc.value).lower()

    # category must be string
    with pytest.raises(Exception) as exc:
        SiteDefinition.model_validate(_valid_site_dict(category=True))
    assert "string" in str(exc.value).lower()

    # profile_url must be string
    with pytest.raises(Exception) as exc:
        SiteDefinition.model_validate(_valid_site_dict(profile_url=789))
    assert "string" in str(exc.value).lower()

    # check_url must be string
    with pytest.raises(Exception) as exc:
        SiteDefinition.model_validate(_valid_site_dict(check_url=101))
    assert "string" in str(exc.value).lower()

    # auth_platform must be string
    with pytest.raises(Exception) as exc:
        SiteDefinition.model_validate(_valid_site_dict(auth_platform=202))
    assert "string" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# Accepted Field Round-Trip Audit Test (Hardening B2-02A.3)
# ---------------------------------------------------------------------------


def test_accepted_fields_survive_legacy_round_trip() -> None:
    full_def = {
        "slug": "synthetic_platform",
        "name": "Synthetic Platform",
        "category": "Development",
        "profile_url": "https://example.com/{username}",
        "check_url": "https://api.example.com/{username}",
        "check_method": "generic_html",
        "confidence_strategy": "multi_signal",
        "http_method": "HEAD",
        "headers": {"Accept": "application/json", "User-Agent": "Spectre/1.0"},
        "rate_limit": 1.5,
        "auth_platform": "synthetic_auth",
        "requires_auth": True,
        "sensitive": True,
        "notes": "Comprehensive synthetic test platform",
        "expected_status": [200, 204],
        "not_found_status": [404, 410],
        "json_id_field": "username_field",
        "display_name_fields": ["display_name", "full_name"],
        "website_fields": ["blog", "homepage"],
        "bio_field": "biography",
        "avatar_field": "avatar_image",
        "location_field": "geo_location",
        "success_patterns": ["profile-active"],
        "profile_markers": ["marker-active"],
        "not_found_patterns": ["user not found"],
        "soft_404_patterns": ["temporarily unavailable"],
        "login_patterns": ["sign in to view"],
        "blocked_patterns": ["rate limit exceeded"],
        "challenge_patterns": ["security challenge"],
        "captcha_patterns": ["solve captcha"],
        "redirect_home": "https://example.com/",
        "redirect_search": "https://example.com/search",
        "enabled": True,
    }

    catalog = SiteCatalog.from_dict({"sites": [full_def]})
    assert len(catalog.sites) == 1
    site = catalog.sites[0]

    # Test object properties
    assert site.http_method == "HEAD"
    assert site.headers == {"Accept": "application/json", "User-Agent": "Spectre/1.0"}
    assert site.requires_auth is True
    assert site.rate_limit == 1.5
    assert site.auth_platform == "synthetic_auth"
    assert site.sensitive is True
    assert site.notes == "Comprehensive synthetic test platform"
    assert site.check_url == "https://api.example.com/{username}"

    # Test legacy to_dict conversion: every field survives
    d = site.to_dict()
    for k, v in full_def.items():
        assert d[k] == v, f"Field '{k}' did not survive round-trip (got {d[k]!r}, expected {v!r})"


# ---------------------------------------------------------------------------
# Root Catalog Strictness Tests (Hardening B2-02A.3)
# ---------------------------------------------------------------------------


def test_root_catalog_unexpected_keys_rejected() -> None:
    bad_roots = [
        {"siets": []},
        {"site": []},
        {"versionn": "1.0", "sites": []},
        {"unknown_root_field": "value", "sites": []},
    ]
    for bad_data in bad_roots:
        with pytest.raises(CatalogValidationError) as exc:
            SiteCatalog.from_dict(bad_data)
        assert "Unknown root catalog key" in str(exc.value) or "top-level 'sites'" in str(exc.value)


# ---------------------------------------------------------------------------
# Passive HTTP Method & Static Header Allowlist Tests
# ---------------------------------------------------------------------------


def test_passive_http_methods_accepted_and_rejected() -> None:
    site_get = SiteDefinition.model_validate(_valid_site_dict(http_method="GET"))
    assert site_get.request.http_method == "GET"

    site_head = SiteDefinition.model_validate(_valid_site_dict(http_method="HEAD"))
    assert site_head.request.http_method == "HEAD"

    for bad_method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE"]:
        with pytest.raises(Exception) as exc:
            SiteDefinition.model_validate(_valid_site_dict(http_method=bad_method))
        assert "passive-only" in str(exc.value).lower() or "unsupported http method" in str(exc.value).lower()


def test_static_header_allowlist_enforcement() -> None:
    allowed_headers = {
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Spectre/1.0",
        "Referer": "https://example.com/",
        "Origin": "https://example.com",
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
    }
    site = SiteDefinition.model_validate(_valid_site_dict(headers=allowed_headers))
    assert site.request.headers["Accept"] == "application/json"
    assert site.request.headers["User-Agent"] == "Spectre/1.0"

    forbidden_headers = [
        "Authorization",
        "authorization",
        "Cookie",
        "Set-Cookie",
        "X-Api-Key",
        "X-GitHub-Token",
        "X-Secret-Key",
        "Private-Token",
        "Authentication",
        "Credential",
        "X-Custom-Token",
    ]
    for bad_hdr in forbidden_headers:
        with pytest.raises(Exception) as exc:
            SiteDefinition.model_validate(_valid_site_dict(headers={bad_hdr: "secret_value"}))
        assert "allowlisted" in str(exc.value).lower() or "not permitted" in str(exc.value).lower()


def test_unsafe_header_values_rejected() -> None:
    with pytest.raises(Exception) as exc:
        SiteDefinition.model_validate(_valid_site_dict(headers={"User-Agent": "Spectre\r\nInjected: True"}))
    assert "control" in str(exc.value).lower() or "line break" in str(exc.value).lower()

    with pytest.raises(Exception) as exc:
        SiteDefinition.model_validate(_valid_site_dict(headers={"User-Agent": "Spectre—Agent"}))
    assert "ascii" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# Unknown Field & Strategy Contradiction Tests
# ---------------------------------------------------------------------------


def test_unknown_flat_typo_fields_are_rejected() -> None:
    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(_valid_site_dict(rate_limt=0.5))
    assert "rate_limt" in str(exc_info.value)

    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(_valid_site_dict(sucess_patterns=["foo"]))
    assert "sucess_patterns" in str(exc_info.value)

    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(_valid_site_dict(profile_urll="https://example.com/{username}"))
    assert "profile_urll" in str(exc_info.value)


def test_unknown_nested_fields_are_rejected() -> None:
    nested_site = {
        "slug": "custom_site",
        "name": "Custom Site",
        "category": "Development",
        "profile_url": "https://example.com/{username}",
        "detection": {
            "strategy": "generic_html",
            "unknown_detection_field": True,
        },
    }
    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(nested_site)
    assert "unknown_detection_field" in str(exc_info.value) or "extra" in str(exc_info.value).lower()


def test_overlapping_expected_and_not_found_status_rejected() -> None:
    with pytest.raises(Exception) as exc:
        SiteDefinition.model_validate(_valid_site_dict(expected_status=[200, 404], not_found_status=[404]))
    assert "conflicting" in str(exc.value).lower() or "overlapping" in str(exc.value).lower()


def test_slug_generation_and_validation() -> None:
    assert slugify_name("GitHub") == "github"
    assert slugify_name("Docker Hub") == "docker_hub"
    assert slugify_name("WordPress.org") == "wordpress_org"
    assert slugify_name("Dev.to") == "dev_to"
    assert slugify_name("Mastodon-mastodon.social") == "mastodon_mastodon_social"

    site = SiteDefinition.model_validate(_valid_site_dict(slug="custom_slug"))
    assert site.slug == "custom_slug"

    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(_valid_site_dict(slug="invalid slug with spaces!"))
    assert "slug" in str(exc_info.value).lower()


def test_duplicate_slug_rejected() -> None:
    site1 = _valid_site_dict(name="Site Alpha", slug="site_alpha")
    site2 = _valid_site_dict(name="Site Beta", slug="site_alpha")
    with pytest.raises(CatalogValidationError) as exc_info:
        SiteCatalog.from_dict({"sites": [site1, site2]})
    assert "site_alpha" in str(exc_info.value)
    assert "Duplicate slug" in str(exc_info.value)


def test_duplicate_site_name_rejected() -> None:
    site1 = _valid_site_dict(name="Example Service", slug="example_1")
    site2 = _valid_site_dict(name="example service", slug="example_2")
    with pytest.raises(CatalogValidationError) as exc_info:
        SiteCatalog.from_dict({"sites": [site1, site2]})
    assert "Duplicate site name" in str(exc_info.value)
    assert "example service" in str(exc_info.value).lower()


def test_unknown_detection_strategy_rejected() -> None:
    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(_valid_site_dict(check_method="telepathic_probe"))
    assert "strategy" in str(exc_info.value).lower() or "check_method" in str(exc_info.value).lower()


def test_unknown_confidence_strategy_rejected() -> None:
    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(_valid_site_dict(confidence_strategy="guaranteed_100_percent"))
    assert "confidence_strategy" in str(exc_info.value).lower()


def test_malformed_regex_patterns_rejected() -> None:
    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(_valid_site_dict(success_patterns=["[unclosed-bracket("]))
    assert "regex" in str(exc_info.value).lower() or "regular expression" in str(exc_info.value).lower()

    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(_valid_site_dict(not_found_patterns=["(?P<invalid"]))
    assert "regex" in str(exc_info.value).lower() or "regular expression" in str(exc_info.value).lower()


def test_category_normalization_and_validation() -> None:
    site = SiteDefinition.model_validate(_valid_site_dict(category="development"))
    assert site.category == "Development"

    site_sec = SiteDefinition.model_validate(_valid_site_dict(category="SECURITY"))
    assert site_sec.category == "Security"

    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(_valid_site_dict(category="Astronomy"))
    assert "Unknown category" in str(exc_info.value)


def test_rate_limit_validation() -> None:
    site = SiteDefinition.model_validate(_valid_site_dict(rate_limit=0.5))
    assert site.request.rate_limit == 0.5

    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(_valid_site_dict(rate_limit=-1.0))
    assert "rate limit" in str(exc_info.value).lower()


def test_json_api_strategy_requires_json_id_field() -> None:
    valid_json = _valid_site_dict(
        check_method="json_api",
        confidence_strategy="explicit_api",
        json_id_field="login",
        display_name_fields=["name"],
    )
    site = SiteDefinition.model_validate(valid_json)
    assert site.detection.strategy == CheckMethod.JSON_API
    assert site.detection.json_id_field == "login"

    invalid_json = _valid_site_dict(
        check_method="json_api",
        confidence_strategy="explicit_api",
        json_id_field=None,
    )
    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(invalid_json)
    assert "json_id_field" in str(exc_info.value)


def test_json_api_requires_get_method() -> None:
    """Invariant: json_api strategy requires HTTP method GET (HEAD is rejected)."""
    valid_json_get = _valid_site_dict(
        name="Valid API Site",
        check_method="json_api",
        confidence_strategy="explicit_api",
        json_id_field="login",
        http_method="GET",
    )
    site_get = SiteDefinition.model_validate(valid_json_get)
    assert site_get.request.http_method == "GET"

    invalid_json_head = _valid_site_dict(
        name="Invalid API Site",
        check_method="json_api",
        confidence_strategy="explicit_api",
        json_id_field="login",
        http_method="HEAD",
    )
    with pytest.raises(Exception) as exc_head:
        SiteDefinition.model_validate(invalid_json_head)
    err_head = str(exc_head.value)
    assert "json_api" in err_head
    assert "GET" in err_head

    # generic_html may use HEAD or GET
    valid_html_head = _valid_site_dict(
        name="Valid HTML HEAD Site",
        check_method="generic_html",
        http_method="HEAD",
    )
    site_html = SiteDefinition.model_validate(valid_html_head)
    assert site_html.request.http_method == "HEAD"


def test_login_wall_strategy_requires_login_patterns() -> None:
    valid_wall = _valid_site_dict(
        check_method="login_wall",
        confidence_strategy="never_confirmed",
        login_patterns=["log in", "sign up"],
        auth_platform="instagram",
    )
    site = SiteDefinition.model_validate(valid_wall)
    assert site.detection.strategy == CheckMethod.LOGIN_WALL
    assert "log in" in site.detection.login_patterns

    invalid_wall = _valid_site_dict(
        check_method="login_wall",
        confidence_strategy="never_confirmed",
        login_patterns=[],
    )
    with pytest.raises(Exception) as exc_info:
        SiteDefinition.model_validate(invalid_wall)
    assert "login_patterns" in str(exc_info.value)


def test_auth_contract_schema_rules() -> None:
    """Enforce strict auth_platform and requires_auth consistency contract."""
    # A. Public / anonymous definition: requires_auth=False, no auth_platform -> accepted
    site_pub = SiteDefinition.model_validate({
        "name": "Public Service",
        "category": "Development",
        "profile_url": "https://pub.example/{username}",
        "access": {"requires_auth": False, "auth_platform": None},
    })
    assert site_pub.access.requires_auth is False
    assert site_pub.access.auth_platform is None

    # B. Explicit authenticated definition: requires_auth=True, auth_platform present -> accepted
    site_auth = SiteDefinition.model_validate({
        "name": "Auth Service",
        "category": "Social",
        "profile_url": "https://auth.example/{username}",
        "access": {"requires_auth": True, "auth_platform": "instagram"},
    })
    assert site_auth.access.requires_auth is True
    assert site_auth.access.auth_platform == "instagram"

    # C. requires_auth=True with missing auth_platform -> rejected
    with pytest.raises(Exception) as exc_c:
        SiteDefinition.model_validate({
            "name": "Invalid Missing Platform",
            "category": "Social",
            "profile_url": "https://auth.example/{username}",
            "access": {"requires_auth": True, "auth_platform": None},
        })
    assert "missing" in str(exc_c.value).lower() or "requires_auth" in str(exc_c.value).lower()

    # D. Explicit requires_auth=False with auth_platform present -> rejected
    with pytest.raises(Exception) as exc_d:
        SiteDefinition.model_validate({
            "name": "Invalid Contradictory Auth",
            "category": "Social",
            "profile_url": "https://auth.example/{username}",
            "access": {"requires_auth": False, "auth_platform": "instagram"},
        })
    assert "false" in str(exc_d.value).lower() or "specified" in str(exc_d.value).lower()

    # E. Legacy flat auth_platform with omitted requires_auth -> normalized to requires_auth=True
    site_legacy = SiteDefinition.model_validate({
        "name": "Legacy Service",
        "category": "Social",
        "profile_url": "https://auth.example/{username}",
        "auth_platform": "instagram",
    })
    assert site_legacy.access.requires_auth is True
    assert site_legacy.access.auth_platform == "instagram"
    assert site_legacy["requires_auth"] is True
    assert site_legacy["auth_platform"] == "instagram"



def test_validation_error_identifies_affected_site() -> None:
    catalog_data = {
        "sites": [
            _valid_site_dict(name="Alpha Platform", slug="alpha"),
            _valid_site_dict(
                name="Broken Beta",
                slug="broken_beta",
                profile_url="invalid_url_without_scheme",
            ),
        ]
    }
    with pytest.raises(CatalogValidationError) as exc_info:
        SiteCatalog.from_dict(catalog_data)
    err_str = str(exc_info.value)
    assert "Broken Beta" in err_str or "broken_beta" in err_str
    assert "profile_url" in err_str


def test_catalog_introspection_api() -> None:
    clear_catalog_cache()
    catalog = load_catalog(reload=True)

    assert catalog.total_sites() == 57
    categories = catalog.categories()
    assert "Development" in categories
    assert "Social" in categories
    assert "Security" in categories
    assert "Gaming" in categories

    by_cat = catalog.count_by_category()
    assert by_cat["Development"] == 17
    assert by_cat["Social"] == 13
    assert by_cat["Gaming"] == 8
    assert by_cat["Art"] == 5
    assert by_cat["Security"] == 3

    by_strat = catalog.count_by_strategy()
    assert by_strat["generic_html"] == 41
    assert by_strat["json_api"] == 11
    assert by_strat["login_wall"] == 5

    by_conf = catalog.count_by_confidence_strategy()
    assert by_conf["multi_signal"] == 38
    assert by_conf["explicit_api"] == 11
    assert by_conf["never_confirmed"] == 8

    gh = catalog.get_by_slug("github")
    assert gh is not None
    assert gh.name == "GitHub"

    gh_by_name = catalog.get_by_name("github")
    assert gh_by_name is not None
    assert gh_by_name.slug == "github"

    dev_sites = catalog.filter(categories=["Development"])
    assert len(dev_sites) == 17
    assert all(s.category == "Development" for s in dev_sites)

    api_sites = catalog.filter(strategies=["json_api"])
    assert len(api_sites) == 11
    assert all(s.detection.strategy == CheckMethod.JSON_API for s in api_sites)

    non_social = catalog.filter(exclude_categories=["Social"])
    assert len(non_social) == 57 - 13


def test_backward_compatibility_dict_access_and_load_sites() -> None:
    sites = load_sites()
    assert len(sites) == 57
    for site in sites:
        assert isinstance(site, dict)
        assert "name" in site
        assert "slug" in site
        assert "profile_url" in site
        assert "url_template" in site
        assert "check_method" in site
        assert "category" in site
        assert "confidence_strategy" in site
        assert "expected_status" in site
        assert "not_found_status" in site

    catalog = load_catalog()
    gh = catalog.get_by_slug("github")
    assert gh is not None
    assert gh["name"] == "GitHub"
    assert gh.get("name") == "GitHub"
    assert gh.get("nonexistent_field", "default") == "default"
    assert "profile_url" in gh
    assert gh.url_template == gh.profile_url


def test_profile_existence_vs_identity_correlation_boundary() -> None:
    catalog = load_catalog()
    for site in catalog.sites:
        assert site.detection.strategy in {
            CheckMethod.GENERIC_HTML,
            CheckMethod.JSON_API,
            CheckMethod.LOGIN_WALL,
        }
        assert not hasattr(site, "identity_weight")
        assert not hasattr(site, "person_confidence")


@pytest.mark.asyncio
async def test_runtime_http_method_and_headers_mock_transport(tmp_path: Any) -> None:
    """Verify that catalog http_method (GET/HEAD) and allowlisted static headers reach transport."""
    captured_requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append({
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
        })
        return httpx.Response(200, text="<html><body>user profile marker</body></html>")

    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    sem = asyncio.Semaphore(5)
    entity = Entity.create(EntityType.USERNAME, "alice-sec", "test", Confidence.CONFIRMED)

    try:
        # 1. Test GET with allowed custom headers reaches transport
        site_get = SiteDefinition.model_validate({
            "name": "Custom Get Site",
            "category": "Development",
            "profile_url": "https://example.com/{username}",
            "request": {
                "http_method": "GET",
                "headers": {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
            },
            "detection": {
                "strategy": "generic_html",
                "success_patterns": ["marker"],
            },
        }).to_dict()

        res_get = await _check_site(entity, site_get, http, sem)
        assert res_get["finding"] is not None
        req1 = captured_requests[-1]
        assert req1["method"] == "GET"
        assert req1["headers"].get("accept") == "application/json"
        assert req1["headers"].get("x-requested-with") == "XMLHttpRequest"
        # Invariant: credential headers never present
        assert "authorization" not in req1["headers"]
        assert "cookie" not in req1["headers"]

        # 2. Test HEAD reaches transport as HEAD
        site_head = SiteDefinition.model_validate({
            "name": "Custom Head Site",
            "category": "Development",
            "profile_url": "https://example.com/{username}",
            "request": {
                "http_method": "HEAD",
                "headers": {"Accept": "*/*"},
            },
        }).to_dict()

        res_head = await _check_site(entity, site_head, http, sem)
        assert res_head["finding"] is not None
        req2 = captured_requests[-1]
        assert req2["method"] == "HEAD"
        assert req2["headers"].get("accept") == "*/*"
    finally:
        await http.close()


@dataclass
class _FakeAuthOutcome:
    status: str = "ok"
    redirected_to_login: bool = False
    status_code: int = 200
    body: str = "<html><title>Alice (@alice-sec) on Platform</title><body>Alice (@alice-sec) on Platform</body></html>"
    title: str = "Alice (@alice-sec) on Platform"
    url: str = "https://instagram.com/alice-sec"
    og_title: str = "Alice (@alice-sec)"
    og_url: str = "https://instagram.com/alice-sec"
    canonical_url: str = "https://instagram.com/alice-sec"
    detail: str = ""


class _FakeAuthService:
    def __init__(self) -> None:
        self.called_platforms: list[str] = []

    def has_active(self, platform: str) -> bool:
        return platform.lower() in {"instagram", "instagram_plat"}

    async def fetch_public_profile(self, site_name: str, username: str, profile_url: str) -> _FakeAuthOutcome:
        self.called_platforms.append(site_name)
        return _FakeAuthOutcome(
            url=f"https://instagram.com/{username}",
            og_url=f"https://instagram.com/{username}",
            canonical_url=f"https://instagram.com/{username}",
            og_title=f"Alice (@{username})",
            title=f"Alice (@{username}) on Platform",
        )


@pytest.mark.asyncio
async def test_runtime_requires_auth_isolated_behavior(tmp_path: Any) -> None:
    """Verify that requires_auth strictly gates authenticated-public session elevation."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><body>Please log in to see this profile</body></html>")

    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    sem = asyncio.Semaphore(5)
    entity = Entity.create(EntityType.USERNAME, "alice-sec", "test", Confidence.CONFIRMED)

    try:
        # 1. Public site (requires_auth=False, auth_platform=None)
        # Even with an active auth service present, authenticated-public fetch is never attempted.
        auth_service_pub = _FakeAuthService()
        site_pub = SiteDefinition.model_validate({
            "name": "Public Platform",
            "category": "Social",
            "profile_url": "https://public.example/{username}",
            "access": {
                "auth_platform": None,
                "requires_auth": False,
            },
            "detection": {
                "strategy": "login_wall",
                "login_patterns": ["Please log in"],
            },
        }).to_dict()

        res_pub = await _check_site(entity, site_pub, http, sem, auth_service=auth_service_pub)
        assert len(auth_service_pub.called_platforms) == 0
        finding_pub = res_pub["finding"]
        assert finding_pub.data["check_status"] == UsernameCheckStatus.LOGIN_REQUIRED.value
        assert finding_pub.data["access_mode"] == AccessMode.ANONYMOUS_PUBLIC.value

        # 2. Authenticated site (requires_auth=True, auth_platform="instagram")
        # When an active operator session exists, authenticated-public fetch is executed.
        auth_service_auth = _FakeAuthService()
        site_auth = SiteDefinition.model_validate({
            "name": "Instagram",
            "category": "Social",
            "profile_url": "https://instagram.com/{username}",
            "access": {
                "auth_platform": "instagram",
                "requires_auth": True,
            },
            "detection": {
                "strategy": "login_wall",
                "login_patterns": ["Please log in"],
            },
        }).to_dict()

        res_auth = await _check_site(entity, site_auth, http, sem, auth_service=auth_service_auth)
        assert len(auth_service_auth.called_platforms) == 1
        assert auth_service_auth.called_platforms[0] == "Instagram"
        finding_auth = res_auth["finding"]
        assert finding_auth.data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
        assert finding_auth.data["check_status"] in {
            UsernameCheckStatus.CONFIRMED.value,
            UsernameCheckStatus.LIKELY.value,
        }
    finally:
        await http.close()
