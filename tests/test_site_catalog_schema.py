from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import yaml
from pydantic import ValidationError

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.result_cache import ResultCache
from spectre_osint.core.types import (
    AccessMode,
    CacheState,
    Confidence,
    EntityType,
    UsernameCheckStatus,
)
from spectre_osint.modules.username.catalog import (
    CatalogSafeLoader,
    CatalogValidationError,
    CheckMethod,
    ConfidenceStrategy,
    SiteCatalog,
    SiteDefinition,
    clear_catalog_cache,
    load_catalog,
    slugify_name,
)
from spectre_osint.modules.username.engine import _check_site, classify_html, load_sites


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
        "redirect_home": "not_found",
        "redirect_search": "not_found",
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


def test_default_not_found_status_preserves_410() -> None:
    """Verify that omitting not_found_status preserves [404, 410] without corrupting explicit overrides."""
    # A. Minimal definition omitting not_found_status receives [404, 410]
    minimal = SiteDefinition.model_validate({
        "name": "Minimal Site",
        "category": "Development",
        "profile_url": "https://example.com/{username}",
    })
    assert minimal.detection.not_found_status == [404, 410]
    assert minimal.not_found_status == [404, 410]
    assert minimal.to_dict()["not_found_status"] == [404, 410]

    # B. Explicit override of not_found_status: [404] is preserved exactly
    explicit_404 = SiteDefinition.model_validate({
        "name": "Explicit 404 Site",
        "category": "Development",
        "profile_url": "https://example.com/{username}",
        "not_found_status": [404],
    })
    assert explicit_404.detection.not_found_status == [404]
    assert explicit_404.not_found_status == [404]
    assert explicit_404.to_dict()["not_found_status"] == [404]
    assert 410 not in explicit_404.to_dict()["not_found_status"]

    # C. Explicit multi-status override is preserved
    explicit_multi = SiteDefinition.model_validate({
        "name": "Explicit Multi",
        "category": "Development",
        "profile_url": "https://example.com/{username}",
        "not_found_status": [400, 404],
    })
    assert explicit_multi.to_dict()["not_found_status"] == [400, 404]


@pytest.mark.asyncio
async def test_runtime_http_410_classified_as_not_found(tmp_path: Any) -> None:
    """Verify that default not_found_status [404, 410] classifies HTTP 410 responses as NOT_FOUND."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(410, text="Gone")

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
        site = SiteDefinition.model_validate({
            "name": "Generic Site",
            "category": "Development",
            "profile_url": "https://example.com/{username}",
        }).to_dict()

        res = await _check_site(entity, site, http, sem)
        finding = res["finding"]
        assert finding.data["check_status"] == UsernameCheckStatus.NOT_FOUND.value
    finally:
        await http.close()


def test_catalog_cached_export_mutation_isolation() -> None:
    """Verify that mutating exported dictionaries from load_sites() does not corrupt cached models."""
    clear_catalog_cache()
    sites_a = load_sites()
    first_site = sites_a[0]

    # Mutate several exported mutable collections
    first_site["expected_status"].append(418)
    first_site["success_patterns"].append("synthetic-mutation-test")
    first_site["headers"]["X-Injected-Header"] = "corrupted-value"

    # Second export must be completely untouched
    sites_b = load_sites()
    assert 418 not in sites_b[0]["expected_status"]
    assert "synthetic-mutation-test" not in sites_b[0]["success_patterns"]
    assert "X-Injected-Header" not in sites_b[0]["headers"]

    # Verify cached SiteDefinition in SiteCatalog is also untouched
    cached_catalog = load_catalog()
    assert 418 not in cached_catalog.sites[0].detection.expected_status
    assert 418 not in cached_catalog.sites[0].expected_status
    assert "synthetic-mutation-test" not in cached_catalog.sites[0].detection.success_patterns
    assert "X-Injected-Header" not in cached_catalog.sites[0].request.headers

    # Verify object identity isolation
    assert sites_a[0]["expected_status"] is not sites_b[0]["expected_status"]
    assert sites_a[0]["headers"] is not sites_b[0]["headers"]


def test_url_fragment_placeholder_rules() -> None:
    """Verify that {username} must appear outside URL fragments in profile_url and check_url."""
    # A. Username in path is accepted
    site_path = SiteDefinition.model_validate(_valid_site_dict(
        profile_url="https://example.com/users/{username}"
    ))
    assert site_path.profile_url == "https://example.com/users/{username}"

    # B. Username in query is accepted
    site_query = SiteDefinition.model_validate(_valid_site_dict(
        profile_url="https://example.com/profile?user={username}"
    ))
    assert site_query.profile_url == "https://example.com/profile?user={username}"

    # C. Username in path with a fixed fragment is accepted
    site_fixed_frag = SiteDefinition.model_validate(_valid_site_dict(
        profile_url="https://example.com/users/{username}#about"
    ))
    assert site_fixed_frag.profile_url == "https://example.com/users/{username}#about"

    # D. Username only in fragment is rejected
    with pytest.raises(Exception) as exc_d:
        SiteDefinition.model_validate(_valid_site_dict(
            profile_url="https://example.com/profile#{username}"
        ))
    assert "fragment" in str(exc_d.value).lower()
    assert "outside" in str(exc_d.value).lower()

    # E. Username only in a fragment path is rejected
    with pytest.raises(Exception) as exc_e:
        SiteDefinition.model_validate(_valid_site_dict(
            profile_url="https://example.com/#/users/{username}"
        ))
    assert "fragment" in str(exc_e.value).lower()

    # F. The same rule applies to check_url
    with pytest.raises(Exception) as exc_f:
        SiteDefinition.model_validate(_valid_site_dict(
            check_url="https://api.example/users#{username}"
        ))
    assert "fragment" in str(exc_f.value).lower()

    # G. A json_api definition with fragment-only username is rejected
    with pytest.raises(Exception) as exc_g:
        SiteDefinition.model_validate(_valid_site_dict(
            check_method="json_api",
            json_id_field="id",
            profile_url="https://api.example/lookup#{username}",
        ))
    assert "fragment" in str(exc_g.value).lower()

    # H. Validation error remains sanitized and does not echo sensitive info or full secret URLs
    with pytest.raises(Exception) as exc_h:
        SiteDefinition.model_validate(_valid_site_dict(
            profile_url="https://secret-token-key:password@api.example/path#{username}"
        ))
    err_msg = str(exc_h.value)
    assert "secret-token-key" not in err_msg
    assert "password" not in err_msg


@pytest.mark.asyncio
async def test_wire_url_omits_fragment_sanity(tmp_path: Any) -> None:
    """Demonstrate that HTTP wire requests transmit path/query and isolate URL fragments."""
    captured_paths: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        # On the HTTP wire, only raw_path (path + query) is transmitted in the request line
        captured_paths.append(request.url.raw_path)
        return httpx.Response(200, text="ok")

    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    http = HttpClient(settings, transport=httpx.MockTransport(handler))

    try:
        # A URL containing a fragment sends only the base path/query across the wire
        await http.get("https://example.com/users/alice#profile-section", provider="Test")
        assert len(captured_paths) == 1
        assert captured_paths[0] == b"/users/alice"
        assert b"#" not in captured_paths[0]
        assert b"profile-section" not in captured_paths[0]
    finally:
        await http.close()


def test_typed_model_accessors_mutation_isolation() -> None:
    """Verify that public typed-model accessors return detached snapshots and preserve index consistency."""
    clear_catalog_cache()
    catalog = load_catalog()

    # A. SiteCatalog.sites property isolation
    sites_1 = catalog.sites
    sites_2 = catalog.sites
    assert sites_1[0] is not sites_2[0]
    assert sites_1[0].detection is not sites_2[0].detection
    assert sites_1[0].request is not sites_2[0].request
    assert sites_1[0].access is not sites_2[0].access

    # Mutate snapshot 1
    sites_1[0].enabled = False
    sites_1[0].slug = "mutated_slug_in_sites"
    sites_1[0].detection.expected_status.append(418)
    sites_1[0].request.headers["X-Mutated"] = "corrupted"

    # Verify snapshot 2 and internal catalog are untouched
    assert sites_2[0].enabled is True
    assert sites_2[0].slug != "mutated_slug_in_sites"
    assert 418 not in sites_2[0].detection.expected_status
    assert "X-Mutated" not in sites_2[0].request.headers

    # B. get_by_slug() index consistency and deep isolation
    original_gh = catalog.get_by_slug("github")
    assert original_gh is not None
    original_gh.slug = "mutated_github_slug"
    original_gh.name = "Mutated GitHub Name"
    original_gh.enabled = False
    original_gh.detection.expected_status.append(418)
    original_gh.extraction.display_name_fields.append("mutated_display_field")

    # Re-querying canonical slug must return uncorrupted model
    fresh_gh = catalog.get_by_slug("github")
    assert fresh_gh is not None
    assert fresh_gh.slug == "github"
    assert fresh_gh.name == "GitHub"
    assert fresh_gh.enabled is True
    assert 418 not in fresh_gh.detection.expected_status
    assert "mutated_display_field" not in fresh_gh.extraction.display_name_fields

    # Mutated slug must not exist in catalog index
    assert catalog.get_by_slug("mutated_github_slug") is None

    # C. get_by_name() deep isolation
    gh_by_name = catalog.get_by_name("GitHub")
    assert gh_by_name is not None
    assert gh_by_name.slug == "github"
    gh_by_name.name = "Corrupted Name"
    assert catalog.get_by_name("GitHub") is not None
    assert catalog.get_by_name("Corrupted Name") is None

    # D. filter() deep isolation
    dev_sites_1 = catalog.filter(categories=["Development"])
    dev_sites_2 = catalog.filter(categories=["Development"])
    assert dev_sites_1[0] is not dev_sites_2[0]
    assert dev_sites_1[0].detection is not dev_sites_2[0].detection
    dev_sites_1[0].detection.expected_status.append(418)
    assert 418 not in dev_sites_2[0].detection.expected_status

    # E. Cross-boundary check: typed mutation does not affect load_sites() output
    legacy_sites = load_sites()
    gh_dict = next(s for s in legacy_sites if s["slug"] == "github")
    assert gh_dict["name"] == "GitHub"
    assert 418 not in gh_dict["expected_status"]
    assert "mutated_display_field" not in gh_dict["display_name_fields"]


def test_url_alias_reconciliation_and_round_trip() -> None:
    """Verify profile_url and url_template alias reconciliation and to_dict() round-trip integrity."""
    # 1. profile_url only validates
    site_prof = SiteDefinition.model_validate(_valid_site_dict(
        profile_url="https://example.com/{username}"
    ))
    assert site_prof.profile_url == "https://example.com/{username}"

    # 2. url_template only validates and normalizes to profile_url
    d_tmpl = _valid_site_dict()
    d_tmpl.pop("profile_url", None)
    d_tmpl["url_template"] = "https://example.com/u/{username}"
    site_tmpl = SiteDefinition.model_validate(d_tmpl)
    assert site_tmpl.profile_url == "https://example.com/u/{username}"

    # 3. Both aliases with identical values validate
    d_both_match = _valid_site_dict(
        profile_url="https://example.com/{username}",
        url_template="https://example.com/{username}",
    )
    site_both_match = SiteDefinition.model_validate(d_both_match)
    assert site_both_match.profile_url == "https://example.com/{username}"

    # 4. Both aliases with conflicting values are rejected
    d_conflict = _valid_site_dict(
        profile_url="https://example.com/{username}",
        url_template="https://other.example/{username}",
    )
    with pytest.raises(Exception) as exc_conflict:
        SiteDefinition.model_validate(d_conflict)
    err_str = str(exc_conflict.value)
    assert "conflicting URL templates" in err_str
    # 5. Error text is sanitized and does not echo either URL
    assert "https://example.com" not in err_str
    assert "https://other.example" not in err_str

    # 6. Full round-trip validation across all 57 production sites:
    catalog = load_catalog()
    for site in catalog.sites:
        exported_dict = site.to_dict()
        reloaded_site = SiteDefinition.model_validate(exported_dict)
        assert reloaded_site.slug == site.slug
        assert reloaded_site.name == site.name
        assert reloaded_site.category == site.category
        assert reloaded_site.profile_url == site.profile_url
        assert reloaded_site.check_url == site.check_url
        assert reloaded_site.detection.strategy == site.detection.strategy
        assert reloaded_site.detection.expected_status == site.detection.expected_status
        assert reloaded_site.detection.not_found_status == site.detection.not_found_status
        assert reloaded_site.http_method == site.http_method
        assert reloaded_site.headers == site.headers
        assert reloaded_site.requires_auth == site.requires_auth
        assert reloaded_site.auth_platform == site.auth_platform


def test_site_catalog_constructor_mutation_isolation() -> None:
    """Verify that SiteCatalog takes ownership of canonical models and isolates caller inputs."""
    original = SiteDefinition.model_validate(_valid_site_dict(
        name="Original Platform",
        category="Development",
        profile_url="https://example.com/{username}",
    ))
    input_list = [original]
    catalog = SiteCatalog(input_list)

    # Mutate original caller-owned model and the input list
    original.slug = "mutated_slug"
    original.name = "Mutated Platform"
    original.enabled = False
    original.detection.expected_status.append(418)
    original.request.headers["Accept"] = "mutated/value"
    original.extraction.display_name_fields.append("mutated_field")
    input_list.clear()

    # Catalog must retain its own canonical copies and indexes
    assert catalog.total_sites() == 1
    canonical = catalog.get_by_slug("original_platform")
    assert canonical is not None
    assert canonical.slug == "original_platform"
    assert canonical.name == "Original Platform"
    assert canonical.enabled is True
    assert 418 not in canonical.detection.expected_status
    assert "Accept" not in canonical.request.headers
    assert "mutated_field" not in canonical.extraction.display_name_fields

    # Mutated slug must not exist in catalog
    assert catalog.get_by_slug("mutated_slug") is None
    assert catalog.get_by_name("Original Platform") is not None
    assert catalog.get_by_name("Mutated Platform") is None

    # Public accessors and exports must remain pristine
    assert catalog.sites[0].slug == "original_platform"
    assert catalog.filter(categories=["Development"])[0].slug == "original_platform"
    assert catalog.to_dict_list()[0]["slug"] == "original_platform"


@pytest.mark.asyncio
async def test_custom_headers_disable_response_cache(tmp_path: Any) -> None:
    """Verify that custom headers bypass response caching while headerless GETs preserve caching."""
    recorded_calls: list[tuple[str, str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded_calls.append((request.method, str(request.url), dict(request.headers)))
        accept = request.headers.get("accept", "")
        if "application/json" in accept:
            return httpx.Response(200, json={"id": "alice", "username": "alice"})
        elif "text/html" in accept:
            return httpx.Response(200, text="<html><body>Profile of alice</body></html>")
        return httpx.Response(200, text="generic profile")

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
    entity = Entity.create(EntityType.USERNAME, "alice", "test", Confidence.CONFIRMED)

    try:
        # A. Accept header variations: JSON vs HTML representation
        site_json = SiteDefinition.model_validate(_valid_site_dict(
            name="API Site",
            profile_url="https://example.com/api/{username}",
            check_method="json_api",
            confidence_strategy="explicit_api",
            json_id_field="id",
            headers={"Accept": "application/json"},
        )).to_dict()

        site_html = SiteDefinition.model_validate(_valid_site_dict(
            name="API Site",
            profile_url="https://example.com/api/{username}",
            check_method="generic_html",
            success_patterns=["Profile of"],
            headers={"Accept": "text/html"},
        )).to_dict()

        recorded_calls.clear()
        await _check_site(entity, site_json, http, sem)
        assert len(recorded_calls) == 1
        assert "application/json" in recorded_calls[0][2]["accept"]

        await _check_site(entity, site_html, http, sem)
        assert len(recorded_calls) == 2
        assert "text/html" in recorded_calls[1][2]["accept"]

        # B. Accept-Language variations
        site_en = SiteDefinition.model_validate(_valid_site_dict(
            name="Lang Site",
            profile_url="https://example.com/lang/{username}",
            headers={"Accept-Language": "en-US"},
        )).to_dict()

        site_pt = SiteDefinition.model_validate(_valid_site_dict(
            name="Lang Site",
            profile_url="https://example.com/lang/{username}",
            headers={"Accept-Language": "pt-BR"},
        )).to_dict()

        recorded_calls.clear()
        await _check_site(entity, site_en, http, sem)
        assert len(recorded_calls) == 1
        await _check_site(entity, site_pt, http, sem)
        assert len(recorded_calls) == 2

        # C. X-Requested-With variations
        site_xhr = SiteDefinition.model_validate(_valid_site_dict(
            name="XHR Site",
            profile_url="https://example.com/xhr/{username}",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )).to_dict()

        recorded_calls.clear()
        await _check_site(entity, site_xhr, http, sem)
        assert len(recorded_calls) == 1
        await _check_site(entity, site_xhr, http, sem)
        assert len(recorded_calls) == 2  # Custom headers do not cache

        # D. Headerless GET requests preserve existing response caching
        site_plain = SiteDefinition.model_validate(_valid_site_dict(
            name="Plain Site",
            profile_url="https://example.com/plain/{username}",
        )).to_dict()

        recorded_calls.clear()
        await _check_site(entity, site_plain, http, sem)
        assert len(recorded_calls) == 1

        await _check_site(entity, site_plain, http, sem)
        assert len(recorded_calls) == 1  # Served from cache without second network call
    finally:
        await http.close()


def test_yaml_merge_keys_and_anchors() -> None:
    """Verify that YAML anchors and << merge keys work while explicit duplicate keys remain rejected."""
    # A. Basic mapping anchor + << merge loads successfully and survives catalog parsing
    yaml_merge = """
defaults: &defaults
  category: Development
  enabled: true
  expected_status: [200]
  not_found_status: [404]

sites:
  - <<: *defaults
    name: Merged Example
    profile_url: https://example.com/users/{username}
    enabled: false  # B. Explicit override of merged default
"""
    raw_doc = yaml.load(yaml_merge, Loader=CatalogSafeLoader)
    site_dict = raw_doc["sites"][0]
    site = SiteDefinition.model_validate(site_dict)
    # C. Inherited and overridden values
    assert site.category == "Development"
    assert site.enabled is False  # Explicit override
    assert site.detection.expected_status == [200]
    assert site.detection.not_found_status == [404]

    # D. Multiple merge anchors in list syntax
    yaml_multi_merge = """
d1: &d1
  category: Social
d2: &d2
  expected_status: [200, 201]

site:
  <<: [*d1, *d2]
  name: Multi Merge Site
  profile_url: https://example.com/{username}
"""
    raw_multi = yaml.load(yaml_multi_merge, Loader=CatalogSafeLoader)
    site_multi = SiteDefinition.model_validate(raw_multi["site"])
    assert site_multi.category == "Social"
    assert site_multi.detection.expected_status == [200, 201]

    # E. True duplicate explicit keys in same mapping are rejected
    yaml_dup_explicit = """
site:
  name: First
  name: Second
"""
    with pytest.raises(CatalogValidationError) as exc_dup:
        yaml.load(yaml_dup_explicit, Loader=CatalogSafeLoader)
    assert "duplicate" in str(exc_dup.value).lower()
    assert "name" in str(exc_dup.value).lower()

    # F. Duplicate keys inside an anchored defaults mapping are rejected
    yaml_dup_in_anchor = """
defaults: &defaults
  category: Development
  category: Social
site:
  <<: *defaults
  name: Example
"""
    with pytest.raises(CatalogValidationError) as exc_anchor:
        yaml.load(yaml_dup_in_anchor, Loader=CatalogSafeLoader)
    assert "duplicate" in str(exc_anchor.value).lower()
    assert "category" in str(exc_anchor.value).lower()

    # G. Global yaml.SafeLoader is not mutated
    res_global = yaml.safe_load("a: 1\na: 2")
    assert res_global["a"] == 2

    # H. Production catalog continues to load 57/57
    cat = load_catalog()
    assert cat.total_sites() == 57


@pytest.mark.asyncio
async def test_result_cache_request_config_isolation(tmp_path: Any) -> None:
    """Verify that ResultCache is bypassed for custom headers and not poisoned against subsequent lookups."""
    recorded_calls: list[tuple[str, str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded_calls.append((request.method, str(request.url), dict(request.headers)))
        accept = request.headers.get("accept", "")
        if "application/json" in accept:
            return httpx.Response(200, json={"id": "alice", "username": "alice"})
        elif "text/html" in accept:
            return httpx.Response(200, text="<html><head><title>Profile of alice</title></head><body>Profile of alice</body></html>")
        return httpx.Response(200, text="<html><head><title>Generic</title></head><body>Generic profile</body></html>")

    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    rc = ResultCache(settings)
    sem = asyncio.Semaphore(5)
    entity = Entity.create(EntityType.USERNAME, "alice", "test", Confidence.CONFIRMED)

    try:
        # Site A: Custom Accept: application/json -> json_api strategy
        site_json = SiteDefinition.model_validate(_valid_site_dict(
            name="DualSite",
            profile_url="https://example.com/{username}",
            check_method="json_api",
            confidence_strategy="explicit_api",
            json_id_field="id",
            headers={"Accept": "application/json"},
        )).to_dict()

        # Site B: Custom Accept: text/html -> generic_html strategy
        site_html = SiteDefinition.model_validate(_valid_site_dict(
            name="DualSite",
            profile_url="https://example.com/{username}",
            check_method="generic_html",
            success_patterns=["Profile of"],
            headers={"Accept": "text/html"},
        )).to_dict()

        # Site C: Headerless definition
        site_plain = SiteDefinition.model_validate(_valid_site_dict(
            name="DualSite",
            profile_url="https://example.com/{username}",
            check_method="generic_html",
            success_patterns=["Generic"],
        )).to_dict()

        # 1. Run Site A with custom headers
        recorded_calls.clear()
        res_a = await _check_site(entity, site_json, http, sem, result_cache=rc)
        assert len(recorded_calls) == 1
        assert res_a["finding"].data["check_status"] == UsernameCheckStatus.CONFIRMED.value
        assert "json_id" in res_a["finding"].data["reason"] or "id=alice" in res_a["finding"].data["reason"]

        # Verify Site A did NOT write to ResultCache
        assert rc.get("username", "DualSite", "alice", AccessMode.ANONYMOUS_PUBLIC.value) is None

        # 2. Run Site B with same ResultCache instance -> must invoke transport and not receive Site A cache
        res_b = await _check_site(entity, site_html, http, sem, result_cache=rc)
        assert len(recorded_calls) == 2
        assert res_b["finding"].data["check_status"] == UsernameCheckStatus.LIKELY.value

        # Verify Site B did NOT write to ResultCache
        assert rc.get("username", "DualSite", "alice", AccessMode.ANONYMOUS_PUBLIC.value) is None

        # 3. Run headerless Site C -> must invoke transport (no poisoned cache hit) and write to ResultCache
        await _check_site(entity, site_plain, http, sem, result_cache=rc)
        assert len(recorded_calls) == 3
        # Headerless check populated ResultCache
        cached_entry = rc.get("username", "DualSite", "alice", AccessMode.ANONYMOUS_PUBLIC.value)
        assert cached_entry is not None

        # 4. Run headerless Site C a second time -> served from ResultCache (no transport call)
        res_c_2 = await _check_site(entity, site_plain, http, sem, result_cache=rc)
        assert len(recorded_calls) == 3  # No new network call
        assert res_c_2["finding"].data["cache_state"] == CacheState.CACHED.value
    finally:
        await http.close()


def test_public_yaml_defaults_and_merges(tmp_path: Any) -> None:
    """Verify that SiteCatalog.from_yaml_file supports top-level defaults and << merge anchors."""
    # A. Public from_yaml_file accepts top-level defaults and merges
    catalog_yaml = tmp_path / "catalog_with_defaults.yaml"
    catalog_yaml.write_text(
        """
defaults: &defaults
  category: Development
  enabled: true
  expected_status: [200]
  not_found_status: [404, 410]

sites:
  - <<: *defaults
    name: Example Service
    profile_url: https://example.com/users/{username}
    enabled: false  # D. Explicit override
""",
        encoding="utf-8",
    )

    catalog = SiteCatalog.from_yaml_file(catalog_yaml)

    # B. Exactly ONE site in catalog
    assert len(catalog.sites) == 1
    assert catalog.total_sites(enabled_only=False) == 1
    assert catalog.total_sites(enabled_only=True) == 0  # enabled: false override

    # C. Inherited and overridden fields
    site = catalog.sites[0]
    assert site.name == "Example Service"
    assert site.category == "Development"
    assert site.enabled is False
    assert site.detection.expected_status == [200]
    assert site.detection.not_found_status == [404, 410]

    # E. defaults itself does not appear in sites or to_dict_list
    assert len(catalog.to_dict_list(enabled_only=False)) == 1
    assert catalog.to_dict_list(enabled_only=False)[0]["name"] == "Example Service"

    # F. Non-mapping defaults block is rejected
    bad_defaults_scalar = tmp_path / "bad_defaults_scalar.yaml"
    bad_defaults_scalar.write_text(
        """
defaults: "invalid_string"
sites:
  - name: Example
    profile_url: https://example.com/{username}
""",
        encoding="utf-8",
    )
    with pytest.raises(CatalogValidationError) as exc_scalar:
        SiteCatalog.from_yaml_file(bad_defaults_scalar)
    assert "defaults" in str(exc_scalar.value)
    assert "mapping" in str(exc_scalar.value)

    bad_defaults_list = tmp_path / "bad_defaults_list.yaml"
    bad_defaults_list.write_text(
        """
defaults:
  - item1
  - item2
sites:
  - name: Example
    profile_url: https://example.com/{username}
""",
        encoding="utf-8",
    )
    with pytest.raises(CatalogValidationError) as exc_list:
        SiteCatalog.from_yaml_file(bad_defaults_list)
    assert "defaults" in str(exc_list.value)
    assert "mapping" in str(exc_list.value)

    # G. Unknown root keys other than sites and defaults remain rejected
    bad_root = tmp_path / "bad_root.yaml"
    bad_root.write_text(
        """
unexpected_root: true
sites:
  - name: Example
    profile_url: https://example.com/{username}
""",
        encoding="utf-8",
    )
    with pytest.raises(CatalogValidationError) as exc_root:
        SiteCatalog.from_yaml_file(bad_root)
    assert "unexpected_root" in str(exc_root.value)


def test_url_template_port_validation() -> None:
    """Verify that URL template ports are strictly validated during schema validation."""
    # A. No explicit port accepted
    site_no_port = SiteDefinition.model_validate(_valid_site_dict(
        profile_url="https://example.com/{username}",
    ))
    assert site_no_port.profile_url == "https://example.com/{username}"

    # B. Standard HTTPS port 443 accepted
    site_443 = SiteDefinition.model_validate(_valid_site_dict(
        profile_url="https://example.com:443/{username}",
    ))
    assert site_443.profile_url == "https://example.com:443/{username}"

    # C. Custom port 8443 accepted
    site_8443 = SiteDefinition.model_validate(_valid_site_dict(
        profile_url="https://example.com:8443/{username}",
        check_url="https://example.com:8443/api/{username}",
    ))
    assert site_8443.profile_url == "https://example.com:8443/{username}"
    assert site_8443.check_url == "https://example.com:8443/api/{username}"

    # D. Username placeholder as port rejected
    with pytest.raises(ValidationError) as exc_user_port:
        SiteDefinition.model_validate(_valid_site_dict(
            profile_url="https://example.com:{username}/profile",
        ))
    err_str = str(exc_user_port.value)
    assert "invalid port" in err_str.lower()
    assert "https://example.com" not in err_str  # Sanitized

    # E. Alphabetic static port rejected
    with pytest.raises(ValidationError) as exc_abc_port:
        SiteDefinition.model_validate(_valid_site_dict(
            profile_url="https://example.com:abc/{username}",
        ))
    assert "invalid port" in str(exc_abc_port.value).lower()

    # F. Out-of-range ports rejected (99999 and 65536)
    with pytest.raises(ValidationError) as exc_99999:
        SiteDefinition.model_validate(_valid_site_dict(
            profile_url="https://example.com:99999/{username}",
        ))
    assert "invalid port" in str(exc_99999.value).lower()

    with pytest.raises(ValidationError) as exc_65536:
        SiteDefinition.model_validate(_valid_site_dict(
            profile_url="https://example.com:65536/{username}",
        ))
    assert "invalid port" in str(exc_65536.value).lower()

    # G. Negative and zero port rejected
    with pytest.raises(ValidationError) as exc_neg:
        SiteDefinition.model_validate(_valid_site_dict(
            profile_url="https://example.com:-1/{username}",
        ))
    assert "invalid port" in str(exc_neg.value).lower()

    with pytest.raises(ValidationError) as exc_zero:
        SiteDefinition.model_validate(_valid_site_dict(
            profile_url="https://example.com:0/{username}",
        ))
    assert "invalid port" in str(exc_zero.value).lower()

    # H. Same port validation applies to check_url
    with pytest.raises(ValidationError) as exc_check_url_port:
        SiteDefinition.model_validate(_valid_site_dict(
            profile_url="https://example.com/{username}",
            check_url="https://example.com:{username}/api",
        ))
    assert "invalid port" in str(exc_check_url_port.value).lower()

    # I. Valid username in hostname and query continues to work
    site_host_user = SiteDefinition.model_validate(_valid_site_dict(
        profile_url="https://{username}.github.io",
    ))
    assert site_host_user.profile_url == "https://{username}.github.io"

    site_query_user = SiteDefinition.model_validate(_valid_site_dict(
        profile_url="https://example.com/profile?user={username}",
    ))
    assert site_query_user.profile_url == "https://example.com/profile?user={username}"


@pytest.mark.asyncio
async def test_head_and_get_result_cache_isolation(tmp_path: Any) -> None:
    """Verify that HEAD definitions bypass ResultCache and do not collide with or poison GET cached results."""
    recorded_calls: list[tuple[str, str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded_calls.append((request.method, str(request.url), dict(request.headers)))
        if request.method == "HEAD":
            return httpx.Response(200, headers={"Content-Type": "text/html"})
        return httpx.Response(200, text="<html><head><title>Profile of alice</title></head><body>Profile of alice</body></html>")

    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    rc = ResultCache(settings)
    sem = asyncio.Semaphore(5)
    entity = Entity.create(EntityType.USERNAME, "alice", "test", Confidence.CONFIRMED)

    try:
        site_get = SiteDefinition.model_validate(_valid_site_dict(
            name="MethodSite",
            profile_url="https://example.com/{username}",
            http_method="GET",
            check_method="generic_html",
            success_patterns=["Profile of"],
        )).to_dict()

        site_head = SiteDefinition.model_validate(_valid_site_dict(
            name="MethodSite",
            profile_url="https://example.com/{username}",
            http_method="HEAD",
            expected_status=[200],
        )).to_dict()

        # Part 1: GET -> HEAD isolation
        recorded_calls.clear()
        res_get = await _check_site(entity, site_get, http, sem, result_cache=rc)
        assert len(recorded_calls) == 1
        assert recorded_calls[0][0] == "GET"
        assert res_get["finding"].data["check_status"] == UsernameCheckStatus.LIKELY.value
        # GET writes to ResultCache
        assert rc.get("username", "MethodSite", "alice", AccessMode.ANONYMOUS_PUBLIC.value) is not None

        # HEAD with same ResultCache MUST reach transport (not consume cached GET classification)
        res_head = await _check_site(entity, site_head, http, sem, result_cache=rc)
        assert len(recorded_calls) == 2
        assert recorded_calls[1][0] == "HEAD"
        assert res_head["finding"].data["check_status"] == UsernameCheckStatus.INCONCLUSIVE.value

        # Second GET is served from ResultCache
        res_get_cached = await _check_site(entity, site_get, http, sem, result_cache=rc)
        assert len(recorded_calls) == 2
        assert res_get_cached["finding"].data["cache_state"] == CacheState.CACHED.value

        # Part 2: HEAD -> GET isolation on a fresh isolated ResultCache
        settings2 = Settings(
            data_dir=tmp_path / "data2",
            reports_dir=tmp_path / "reports2",
            logs_dir=tmp_path / "logs2",
            database_url=f"sqlite:///{tmp_path / 't2.db'}",
            ssrf_enabled=False,
        )
        settings2.ensure_dirs()
        http2 = HttpClient(settings2, transport=httpx.MockTransport(handler))
        rc2 = ResultCache(settings2)
        recorded_calls.clear()

        try:
            # HEAD runs first -> reaches transport, does NOT write to ResultCache
            await _check_site(entity, site_head, http2, sem, result_cache=rc2)
            assert len(recorded_calls) == 1
            assert recorded_calls[0][0] == "HEAD"
            assert rc2.get("username", "MethodSite", "alice", AccessMode.ANONYMOUS_PUBLIC.value) is None

            # GET runs next -> reaches transport, populates ResultCache
            await _check_site(entity, site_get, http2, sem, result_cache=rc2)
            assert len(recorded_calls) == 2
            assert recorded_calls[1][0] == "GET"
            assert rc2.get("username", "MethodSite", "alice", AccessMode.ANONYMOUS_PUBLIC.value) is not None

            # Refresh=True bypasses ResultCache for GET
            await _check_site(entity, site_get, http2, sem, result_cache=rc2, refresh=True)
            assert len(recorded_calls) == 3
            assert recorded_calls[2][0] == "GET"
        finally:
            await http2.close()
    finally:
        await http.close()


def test_redirect_policy_schema_validation() -> None:
    """Verify that redirect_home and redirect_search accept only None or 'not_found'."""
    # A. Omitted / None accepted
    site_none = SiteDefinition.model_validate(_valid_site_dict())
    assert site_none.detection.redirect_home is None
    assert site_none.detection.redirect_search is None

    # B. 'not_found' accepted and normalized
    site_valid = SiteDefinition.model_validate(_valid_site_dict(
        redirect_home="not_found",
        redirect_search=" NOT_FOUND ",
    ))
    assert site_valid.detection.redirect_home == "not_found"
    assert site_valid.detection.redirect_search == "not_found"

    # Exported dict contains canonical 'not_found'
    exported = site_valid.to_dict()
    assert exported["redirect_home"] == "not_found"
    assert exported["redirect_search"] == "not_found"

    # C. Invalid strings rejected
    for bad_policy in ["not_foud", "found", "ignore", "", "https://example.com/", "login_required"]:
        with pytest.raises(ValidationError) as exc_bad_home:
            SiteDefinition.model_validate(_valid_site_dict(redirect_home=bad_policy))
        assert "invalid policy" in str(exc_bad_home.value).lower()

        with pytest.raises(ValidationError) as exc_bad_search:
            SiteDefinition.model_validate(_valid_site_dict(redirect_search=bad_policy))
        assert "invalid policy" in str(exc_bad_search.value).lower()

    # D. Non-string types rejected
    for bad_type in [123, True, ["not_found"], {"policy": "not_found"}]:
        with pytest.raises(ValidationError) as exc_type_home:
            SiteDefinition.model_validate(_valid_site_dict(redirect_home=bad_type))
        assert "string" in str(exc_type_home.value).lower()

        with pytest.raises(ValidationError) as exc_type_search:
            SiteDefinition.model_validate(_valid_site_dict(redirect_search=bad_type))
        assert "string" in str(exc_type_search.value).lower()


def test_redirect_policy_runtime_classification() -> None:
    """Verify that valid redirect policies correctly classify home and search redirects at runtime."""
    site = SiteDefinition.model_validate(_valid_site_dict(
        redirect_home="not_found",
        redirect_search="not_found",
    )).to_dict()

    # Home redirect -> NOT_FOUND with reason 'redirect_home'
    status_home, reason_home, _ = classify_html(
        status_code=200,
        body="<html><head><title>Home Page</title></head><body>Welcome home</body></html>",
        title="Home Page",
        final_url="https://example.com/",
        site=site,
        username="alice",
        requested_url="https://example.com/users/alice",
        canonical_url="",
        og_title="",
    )
    assert status_home == UsernameCheckStatus.NOT_FOUND
    assert reason_home == "redirect_home"

    # Search redirect -> NOT_FOUND with reason 'redirect_search'
    status_search, reason_search, _ = classify_html(
        status_code=200,
        body="<html><head><title>Search</title></head><body>Search results</body></html>",
        title="Search",
        final_url="https://example.com/search?q=alice",
        site=site,
        username="alice",
        requested_url="https://example.com/users/alice",
        canonical_url="",
        og_title="",
    )
    assert status_search == UsernameCheckStatus.NOT_FOUND
    assert reason_search == "redirect_search"


def test_strict_boolean_fields_rejection() -> None:
    """Verify that catalog boolean fields (enabled, sensitive, requires_auth) accept only actual booleans."""
    # 1. enabled
    # Omitted defaults to True
    site_def = SiteDefinition.model_validate(_valid_site_dict())
    assert site_def.enabled is True
    assert isinstance(site_def.enabled, bool)

    # Valid bools accepted
    site_true = SiteDefinition.model_validate(_valid_site_dict(enabled=True))
    assert site_true.enabled is True
    site_false = SiteDefinition.model_validate(_valid_site_dict(enabled=False))
    assert site_false.enabled is False

    # Invalid enabled inputs rejected
    for bad in ["true", "false", "TRUE", "FALSE", "yes", "no", 1, 0, [], {}, None]:
        with pytest.raises(ValidationError) as exc_enabled:
            SiteDefinition.model_validate(_valid_site_dict(enabled=bad))
        assert "bool" in str(exc_enabled.value).lower()

    # 2. sensitive
    # Omitted defaults to False
    assert site_def.sensitive is False
    assert isinstance(site_def.sensitive, bool)

    # Valid bools accepted
    site_sens_true = SiteDefinition.model_validate(_valid_site_dict(sensitive=True))
    assert site_sens_true.sensitive is True

    # Invalid sensitive inputs rejected
    for bad in ["true", "false", 1, 0, None]:
        with pytest.raises(ValidationError) as exc_sens:
            SiteDefinition.model_validate(_valid_site_dict(sensitive=bad))
        assert "bool" in str(exc_sens.value).lower()

    # 3. requires_auth
    # Valid boolean combinations
    site_auth_true = SiteDefinition.model_validate(_valid_site_dict(
        auth_platform="twitch",
        requires_auth=True,
    ))
    assert site_auth_true.requires_auth is True

    site_auth_false = SiteDefinition.model_validate(_valid_site_dict(
        requires_auth=False,
    ))
    assert site_auth_false.requires_auth is False

    # Invalid requires_auth types rejected (flat and nested)
    for bad in ["true", "false", 1, 0, None]:
        with pytest.raises(ValidationError) as exc_auth_flat:
            SiteDefinition.model_validate(_valid_site_dict(
                auth_platform="twitch",
                requires_auth=bad,
            ))
        assert "bool" in str(exc_auth_flat.value).lower()

        with pytest.raises(ValidationError) as exc_auth_nested:
            SiteDefinition.model_validate({
                "slug": "test_auth",
                "name": "Test Auth",
                "category": "Development",
                "profile_url": "https://example.com/{username}",
                "access": {
                    "auth_platform": "twitch",
                    "requires_auth": bad,
                },
            })
        assert "bool" in str(exc_auth_nested.value).lower()


def test_public_yaml_quoted_boolean_rejection(tmp_path: Any) -> None:
    """Verify that YAML files with quoted booleans ('false', 'true') are rejected by public SiteCatalog loader."""
    # A. Quoted enabled: "false" is rejected
    quoted_yaml = tmp_path / "quoted_enabled.yaml"
    quoted_yaml.write_text(
        """
sites:
  - name: Quoted Example
    category: Social
    profile_url: https://example.com/{username}
    enabled: "false"
""",
        encoding="utf-8",
    )
    with pytest.raises(CatalogValidationError) as exc_quoted:
        SiteCatalog.from_yaml_file(quoted_yaml)
    assert "bool" in str(exc_quoted.value).lower()

    # B. Unquoted enabled: false is accepted as real boolean False
    unquoted_yaml = tmp_path / "unquoted_enabled.yaml"
    unquoted_yaml.write_text(
        """
sites:
  - name: Unquoted Example
    category: Social
    profile_url: https://example.com/{username}
    enabled: false
""",
        encoding="utf-8",
    )
    catalog = SiteCatalog.from_yaml_file(unquoted_yaml)
    assert len(catalog.sites) == 1
    assert catalog.sites[0].enabled is False
    assert isinstance(catalog.sites[0].enabled, bool)
    assert catalog.total_sites(enabled_only=True) == 0
    assert catalog.total_sites(enabled_only=False) == 1


def test_json_api_requires_explicit_api_confidence_strategy() -> None:
    """Invariant: json_api strategy requires confidence_strategy 'explicit_api'."""
    # 1. Valid explicit_api in flat and nested forms
    valid_flat = _valid_site_dict(
        check_method="json_api",
        confidence_strategy="explicit_api",
        json_id_field="login",
        http_method="GET",
    )
    site_flat = SiteDefinition.model_validate(valid_flat)
    assert site_flat.detection.strategy == CheckMethod.JSON_API
    assert site_flat.detection.confidence_strategy == ConfidenceStrategy.EXPLICIT_API

    valid_nested = {
        "slug": "nested_json",
        "name": "Nested JSON",
        "category": "Development",
        "profile_url": "https://example.com/{username}",
        "detection": {
            "strategy": "json_api",
            "confidence_strategy": "explicit_api",
            "json_id_field": "login",
        },
        "request": {
            "http_method": "GET",
        },
    }
    site_nested = SiteDefinition.model_validate(valid_nested)
    assert site_nested.detection.confidence_strategy == ConfidenceStrategy.EXPLICIT_API

    # 2. Invalid confidence_strategy for json_api (multi_signal, never_confirmed, omitted)
    for invalid_strat in ["multi_signal", "never_confirmed"]:
        with pytest.raises(ValidationError) as exc_strat:
            SiteDefinition.model_validate(_valid_site_dict(
                check_method="json_api",
                confidence_strategy=invalid_strat,
                json_id_field="login",
                http_method="GET",
            ))
        err_msg = str(exc_strat.value)
        assert "json_api" in err_msg
        assert "explicit_api" in err_msg

    # Omitted confidence_strategy with json_api (resolves to default multi_signal) must also fail
    with pytest.raises(ValidationError) as exc_omitted:
        SiteDefinition.model_validate({
            "slug": "omitted_conf",
            "name": "Omitted Conf",
            "category": "Development",
            "profile_url": "https://example.com/{username}",
            "check_method": "json_api",
            "json_id_field": "login",
            "http_method": "GET",
        })
    err_omitted = str(exc_omitted.value)
    assert "json_api" in err_omitted
    assert "explicit_api" in err_omitted


@pytest.mark.asyncio
async def test_json_api_runtime_explicit_api_confirmation(tmp_path: Any) -> None:
    """Verify that validated json_api + explicit_api site yields CONFIRMED on matching JSON identity."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"login": "alice", "id": 12345})

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
    entity = Entity.create(EntityType.USERNAME, "alice", "test", Confidence.CONFIRMED)

    try:
        # Valid JSON site executes and returns CONFIRMED
        valid_site = SiteDefinition.model_validate(_valid_site_dict(
            name="JSON Platform",
            profile_url="https://api.example.com/users/{username}",
            check_method="json_api",
            confidence_strategy="explicit_api",
            json_id_field="login",
            http_method="GET",
        )).to_dict()

        res = await _check_site(entity, valid_site, http, sem)
        finding_data = res["finding"].data
        assert finding_data["check_status"] == UsernameCheckStatus.CONFIRMED.value
        assert finding_data["confidence"] == Confidence.CONFIRMED.value

        # Invalid configuration fails at schema validation time before transport
        with pytest.raises(ValidationError):
            SiteDefinition.model_validate(_valid_site_dict(
                name="Invalid JSON Platform",
                profile_url="https://api.example.com/users/{username}",
                check_method="json_api",
                confidence_strategy="never_confirmed",
                json_id_field="login",
                http_method="GET",
            ))
    finally:
        await http.close()


def test_rate_limit_finite_positive_validation() -> None:
    """Verify that rate_limit must be None or a finite positive float."""
    # 1. Valid values
    assert SiteDefinition.model_validate(_valid_site_dict(rate_limit=None)).request.rate_limit is None
    assert SiteDefinition.model_validate(_valid_site_dict(rate_limit=0.01)).request.rate_limit == 0.01
    assert SiteDefinition.model_validate(_valid_site_dict(rate_limit=0.5)).request.rate_limit == 0.5
    assert SiteDefinition.model_validate(_valid_site_dict(rate_limit=1.0)).request.rate_limit == 1.0
    assert SiteDefinition.model_validate(_valid_site_dict(rate_limit=60.0)).request.rate_limit == 60.0

    # 2. Non-finite values rejected
    for bad_float in [float("inf"), float("-inf"), float("nan")]:
        with pytest.raises(ValidationError) as exc_nonfinite:
            SiteDefinition.model_validate(_valid_site_dict(rate_limit=bad_float))
        err_msg = str(exc_nonfinite.value).lower()
        assert "rate limit" in err_msg
        assert "finite positive" in err_msg

    # 3. Non-positive finite values rejected
    for non_positive in [0, 0.0, -0.1, -1.0, -60.0]:
        with pytest.raises(ValidationError) as exc_nonpos:
            SiteDefinition.model_validate(_valid_site_dict(rate_limit=non_positive))
        err_msg = str(exc_nonpos.value).lower()
        assert "rate limit" in err_msg
        assert "finite positive" in err_msg


def test_public_yaml_non_finite_rate_limits(tmp_path: Any) -> None:
    """Verify that YAML files with non-finite rate limits (.inf, -.inf, .nan) fail public validation."""
    for bad_scalar in [".inf", "-.inf", ".nan"]:
        yaml_file = tmp_path / f"rate_{bad_scalar.replace('.', '').replace('-', 'neg')}.yaml"
        yaml_file.write_text(
            f"""
sites:
  - name: Bad Timing Example
    category: Social
    profile_url: https://example.com/{{username}}
    rate_limit: {bad_scalar}
""",
            encoding="utf-8",
        )
        with pytest.raises(CatalogValidationError) as exc_yaml:
            SiteCatalog.from_yaml_file(yaml_file)
        assert "rate limit" in str(exc_yaml.value).lower()

    # Finite rate limit succeeds
    valid_yaml = tmp_path / "rate_valid.yaml"
    valid_yaml.write_text(
        """
sites:
  - name: Valid Timing Example
    category: Social
    profile_url: https://example.com/{username}
    rate_limit: 0.5
""",
        encoding="utf-8",
    )
    cat = SiteCatalog.from_yaml_file(valid_yaml)
    assert len(cat.sites) == 1
    assert cat.sites[0].rate_limit == 0.5


def test_static_header_casing_normalization_and_duplicate_rejection() -> None:
    """Verify that static header names are normalized to canonical casing and case-insensitive duplicates are rejected."""
    # 1. Casing normalization
    casing_inputs = {
        "user-agent": "UA-1",
        "ACCEPT-LANGUAGE": "en-US",
        "x-requested-with": "XMLHttpRequest",
        "Referer": "https://example.com/",
        "ORIGIN": "https://example.com",
        "content-type": "application/json",
        "accept": "text/html",
    }
    raw_copy = dict(casing_inputs)
    site = SiteDefinition.model_validate(_valid_site_dict(headers=casing_inputs))
    # Input dict must not be mutated
    assert casing_inputs == raw_copy

    expected_canonical = {
        "User-Agent": "UA-1",
        "Accept-Language": "en-US",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://example.com/",
        "Origin": "https://example.com",
        "Content-Type": "application/json",
        "Accept": "text/html",
    }
    assert site.request.headers == expected_canonical

    # 2. Case-insensitive duplicate rejection
    duplicate_cases = [
        {"User-Agent": "A", "user-agent": "B"},
        {"Accept": "text/html", "ACCEPT": "application/json"},
        {"x-requested-with": "A", "X-Requested-With": "B"},
        {"referer": "A", "Referer": "B"},
    ]
    for dup in duplicate_cases:
        # Flat legacy
        with pytest.raises(ValidationError) as exc_flat:
            SiteDefinition.model_validate(_valid_site_dict(headers=dup))
        assert "duplicate header" in str(exc_flat.value).lower()

        # Nested RequestDefinition
        with pytest.raises(ValidationError) as exc_nested:
            SiteDefinition.model_validate({
                "slug": "dup_site",
                "name": "Dup Site",
                "category": "Development",
                "profile_url": "https://example.com/{username}",
                "request": {
                    "headers": dup,
                },
            })
        assert "duplicate header" in str(exc_nested.value).lower()


@pytest.mark.asyncio
async def test_custom_user_agent_transport_override_and_headers(tmp_path: Any) -> None:
    """Verify that a custom User-Agent replaces the generated default on the wire and custom headers are sent."""
    recorded_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded_requests.append(request)
        return httpx.Response(200, text="<html><head><title>Profile of alice</title></head><body>Profile of alice</body></html>")

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
    entity = Entity.create(EntityType.USERNAME, "alice", "test", Confidence.CONFIRMED)

    try:
        # Site with lowercase user-agent and accept-language
        site_def = SiteDefinition.model_validate(_valid_site_dict(
            name="Custom Header Site",
            profile_url="https://example.com/{username}",
            headers={
                "user-agent": "SPECTRE-Custom-UA/1.0",
                "accept-language": "pt-BR",
            },
            success_patterns=["Profile of"],
        )).to_dict()

        await _check_site(entity, site_def, http, sem)
        assert len(recorded_requests) == 1
        req = recorded_requests[0]

        # Verify exactly one User-Agent header is sent with the custom value
        ua_list = req.headers.get_list("user-agent")
        assert len(ua_list) == 1
        assert ua_list[0] == "SPECTRE-Custom-UA/1.0"
        assert req.headers.get("user-agent") == "SPECTRE-Custom-UA/1.0"

        # Verify Accept-Language is sent with canonical name and preserved value
        assert req.headers.get("accept-language") == "pt-BR"
    finally:
        await http.close()


def test_public_yaml_duplicate_header_casing_rejection(tmp_path: Any) -> None:
    """Verify that public YAML loader rejects case-insensitive duplicate headers and normalizes single headers."""
    # A. Duplicate header names with different casing rejected
    dup_yaml = tmp_path / "dup_headers.yaml"
    dup_yaml.write_text(
        """
sites:
  - name: Dup Example
    category: Social
    profile_url: https://example.com/{username}
    headers:
      User-Agent: ValueA
      user-agent: ValueB
""",
        encoding="utf-8",
    )
    with pytest.raises(CatalogValidationError) as exc_yaml:
        SiteCatalog.from_yaml_file(dup_yaml)
    assert "duplicate header" in str(exc_yaml.value).lower()

    # B. Lowercase header in YAML is loaded and normalized canonically
    single_yaml = tmp_path / "single_header.yaml"
    single_yaml.write_text(
        """
sites:
  - name: Single Example
    category: Social
    profile_url: https://example.com/{username}
    headers:
      user-agent: Custom-UA
      accept-language: fr-FR
""",
        encoding="utf-8",
    )
    cat = SiteCatalog.from_yaml_file(single_yaml)
    assert len(cat.sites) == 1
    site = cat.sites[0]
    assert site.headers == {
        "User-Agent": "Custom-UA",
        "Accept-Language": "fr-FR",
    }

    # Round trip preserves canonical casing
    d = site.to_dict()
    assert d["headers"] == {
        "User-Agent": "Custom-UA",
        "Accept-Language": "fr-FR",
    }
    reloaded = SiteDefinition.model_validate(d)
    assert reloaded.headers == {
        "User-Agent": "Custom-UA",
        "Accept-Language": "fr-FR",
    }
