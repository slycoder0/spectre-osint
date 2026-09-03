"""Site Catalog 2.0 schema, validation, and introspection.

Provides typed Pydantic models for public username platform definitions,
ensuring strict schema validation at catalog load boundaries while preserving
existing runtime behavior and false-positive protections.

Critical Invariants:
1. HTTP 200 alone is never CONFIRMED.
2. Profile existence detection != identity correlation.
   A discovered profile only proves a handle exists on a platform;
   civil identity correlation is handled downstream by multi-signal clustering.
"""

from __future__ import annotations

import math
import re
import string
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    field_validator,
    model_validator,
)

from spectre_osint.browser.models import normalize_platform
from spectre_osint.core.config import BUNDLED_DATA_DIR


class CatalogError(Exception):
    """Base exception for site catalog errors."""


class CatalogValidationError(CatalogError):
    """Raised when a site definition fails schema or semantic validation."""

    def __init__(self, site_identifier: str, field_name: str | None, reason: str) -> None:
        self.site_identifier = site_identifier
        self.field_name = field_name
        self.reason = reason
        field_part = f" (field: {field_name})" if field_name else ""
        super().__init__(
            f"Catalog validation failed for site '{site_identifier}'{field_part}: {reason}"
        )


class CatalogSafeLoader(yaml.SafeLoader):
    """Local YAML SafeLoader that preserves merge keys (<<) while rejecting duplicate explicit keys."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, yaml.MappingNode):
            raise yaml.constructor.ConstructorError(
                None, None, f"expected a mapping node, but found {node.id}", node.start_mark
            )

        seen_keys: set[Any] = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                key = "<<"
            else:
                key = self.construct_object(key_node, deep=deep)
            if key in seen_keys:
                line = key_node.start_mark.line + 1 if key_node.start_mark else None
                col = key_node.start_mark.column + 1 if key_node.start_mark else None
                pos = f" at line {line}, column {col}" if line and col else ""
                raise CatalogValidationError(
                    site_identifier=f"YAML{pos}",
                    field_name=str(key),
                    reason=f"Duplicate mapping key '{key}' detected in catalog YAML",
                )
            seen_keys.add(key)

        return super().construct_mapping(node, deep=deep)


class CheckMethod(StrEnum):
    GENERIC_HTML = "generic_html"
    JSON_API = "json_api"
    LOGIN_WALL = "login_wall"


class ConfidenceStrategy(StrEnum):
    EXPLICIT_API = "explicit_api"
    MULTI_SIGNAL = "multi_signal"
    NEVER_CONFIRMED = "never_confirmed"


KNOWN_CATEGORIES: dict[str, str] = {
    "art": "Art",
    "creator": "Creator",
    "development": "Development",
    "forums": "Forums",
    "freelance": "Freelance",
    "gaming": "Gaming",
    "identity": "Identity",
    "music": "Music",
    "security": "Security",
    "social": "Social",
    "tech": "Tech",
    "video": "Video",
}

# Strict allowlist of safe, static request headers permitted in generic catalog definitions
_CANONICAL_HEADER_NAMES: dict[str, str] = {
    "accept": "Accept",
    "accept-language": "Accept-Language",
    "user-agent": "User-Agent",
    "referer": "Referer",
    "origin": "Origin",
    "content-type": "Content-Type",
    "x-requested-with": "X-Requested-With",
}
_ALLOWED_HEADER_NAMES: frozenset[str] = frozenset(_CANONICAL_HEADER_NAMES.keys())

# Known legacy flat keys accepted during migration from flat YAML to nested SiteDefinition
_KNOWN_LEGACY_FLAT_KEYS: frozenset[str] = frozenset(
    {
        "slug",
        "name",
        "category",
        "profile_url",
        "url_template",
        "enabled",
        "sensitive",
        "notes",
        "detection",
        "extraction",
        "request",
        "access",
        # detection flat keys
        "check_method",
        "confidence_strategy",
        "expected_status",
        "not_found_status",
        "json_id_field",
        "success_patterns",
        "profile_markers",
        "not_found_patterns",
        "soft_404_patterns",
        "login_patterns",
        "blocked_patterns",
        "challenge_patterns",
        "captcha_patterns",
        "redirect_home",
        "redirect_search",
        # extraction flat keys
        "display_name_fields",
        "website_fields",
        "bio_field",
        "avatar_field",
        "location_field",
        # request flat keys
        "check_url",
        "http_method",
        "rate_limit",
        "headers",
        # access flat keys
        "auth_platform",
        "requires_auth",
    }
)

# Allowed top-level document keys in catalog YAML
_ALLOWED_ROOT_KEYS: frozenset[str] = frozenset({"sites", "defaults"})


CANONICAL_SLUG_PATTERN = re.compile(r"^[a-z0-9_]+$")


def slugify_name(name: str) -> str:
    """Derive a deterministic, stable, lowercase ASCII slug from a display name.

    Retained only as a compatibility fallback for custom and legacy catalog
    definitions that predate explicit slugs. Production catalog definitions
    declare `slug` explicitly and are loaded with `require_explicit_slug=True`,
    so this derivation is never reached for the bundled catalog (B2-02B).
    """
    s = name.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    return s.strip("_")


def _validate_raw_production_slug(raw_site: dict[str, Any], site_identifier: str) -> None:
    """Require a raw production `slug` that is already canonical.

    Runs before `SiteDefinition` normalization, so a declaration that only becomes
    canonical after stripping and lowercasing (`" github "`, `GitHub`) is rejected
    instead of silently rewritten. Non-string values are left to the
    `SiteDefinition` type error so diagnostics stay precise.
    """
    raw_slug = raw_site.get("slug")

    if raw_slug is None:
        raise CatalogValidationError(
            site_identifier=site_identifier,
            field_name="slug",
            reason=(
                "Production catalog entries must declare an explicit non-blank 'slug'; "
                "deriving an identifier from the display name is not permitted"
            ),
        )

    if not isinstance(raw_slug, str):
        return

    if not raw_slug.strip():
        raise CatalogValidationError(
            site_identifier=site_identifier,
            field_name="slug",
            reason=(
                "Production catalog entries must declare an explicit non-blank 'slug'; "
                "a blank or whitespace-only value is not permitted"
            ),
        )

    if raw_slug != raw_slug.strip():
        raise CatalogValidationError(
            site_identifier=site_identifier,
            field_name="slug",
            reason=(
                f"Production slug '{raw_slug}' has leading or trailing whitespace; "
                "declare the canonical value, it is not normalized for you"
            ),
        )

    if raw_slug != raw_slug.lower():
        raise CatalogValidationError(
            site_identifier=site_identifier,
            field_name="slug",
            reason=(
                f"Production slug '{raw_slug}' contains uppercase characters; "
                "declare the canonical lowercase value, it is not normalized for you"
            ),
        )

    if not CANONICAL_SLUG_PATTERN.match(raw_slug):
        raise CatalogValidationError(
            site_identifier=site_identifier,
            field_name="slug",
            reason=(
                f"Production slug '{raw_slug}' is not canonical: it must already match "
                "^[a-z0-9_]+$ (lowercase ASCII letters, digits and underscores)"
            ),
        )


def _validate_regex_patterns(patterns: list[str], field_name: str) -> None:
    """Ensure all strings in a pattern list are valid, non-blank regular expressions."""
    for pattern in patterns:
        if not isinstance(pattern, str):
            raise ValueError(f"Pattern in {field_name} must be a string, got {type(pattern).__name__}")
        if not pattern.strip():
            raise ValueError(f"Pattern in {field_name} must not be empty or whitespace-only")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                f"Invalid regular expression in {field_name} '{pattern}': {exc}"
            ) from exc


def _validate_url_template(v: str, field_name: str) -> str:
    """Validate a URL template using Python format-string parsing and structured URL parsing.

    Validation errors are sanitized to never echo full URLs or sensitive values.
    """
    if not isinstance(v, str) or not v:
        raise ValueError(f"{field_name} must be a non-empty string")

    # Reject control characters and line breaks
    if any(c in "\r\n\x00\x1b" or (ord(c) < 32 and c != " ") or ord(c) == 127 for c in v):
        raise ValueError(f"{field_name} contains invalid control characters or line breaks")

    # Reject whitespace
    if any(c.isspace() for c in v):
        raise ValueError(f"{field_name} must not contain whitespace")

    # Python format-string structural validation using string.Formatter
    formatter = string.Formatter()
    try:
        parsed_fields = list(formatter.parse(v))
    except ValueError:
        raise ValueError(f"{field_name} has malformed format-string syntax with unbalanced braces") from None

    replacement_fields = [f for f in parsed_fields if f[1] is not None]
    if not replacement_fields:
        raise ValueError(f"{field_name} template must contain '{{username}}'")

    for _, fname, format_spec, conversion in replacement_fields:
        if fname != "username":
            raise ValueError(
                f"{field_name} contains unsupported placeholder '{{{fname}}}': only '{{username}}' is allowed"
            )
        if format_spec:
            raise ValueError(f"{field_name} must not contain format specifiers in placeholder")
        if conversion:
            raise ValueError(f"{field_name} must not contain conversion flags in placeholder")

    # URL fragments are not transmitted in HTTP requests; a real {username} replacement field must exist before '#'
    base_template, _, _ = v.partition("#")
    try:
        base_parsed_fields = list(formatter.parse(base_template))
    except ValueError:
        raise ValueError(
            f"{field_name} has malformed format-string syntax with unbalanced braces"
        ) from None

    base_replacement_fields = [f for f in base_parsed_fields if f[1] == "username"]
    if not base_replacement_fields:
        raise ValueError(f"{field_name} must contain '{{username}}' outside the URL fragment")

    # Structured URL parse using Python format-string semantics
    try:
        dummy_url = v.format(username="placeholder_user")
    except Exception:
        raise ValueError(f"{field_name} failed to format with placeholder value") from None

    try:
        parsed = urlparse(dummy_url)
        port = parsed.port
        if port is not None and (port < 1 or port > 65535):
            raise ValueError(f"{field_name} contains an invalid port")
    except ValueError:
        raise ValueError(f"{field_name} contains an invalid port") from None

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"{field_name} must use http:// or https:// scheme")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError(f"{field_name} is missing a valid hostname / netloc")
    if parsed.username or parsed.password:
        raise ValueError(f"{field_name} must not contain embedded userinfo or credentials")

    return v


def _validate_static_headers(headers: dict[str, str]) -> dict[str, str]:
    """Validate that catalog headers are safe, static, non-sensitive HTTP headers from the allowlist.

    Normalizes all header names to their canonical casing (e.g. 'user-agent' -> 'User-Agent')
    and rejects case-insensitive duplicate header definitions.
    """
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("Header name and value must be strings")
        name_clean = name.strip().lower()
        if not re.match(r"^[a-zA-Z0-9_-]+$", name):
            raise ValueError(f"Invalid header name '{name}': contains illegal characters")
        if name_clean not in _CANONICAL_HEADER_NAMES:
            raise ValueError(
                f"Header '{name}' is not permitted in static catalog definitions (only safe allowlisted headers allowed)"
            )
        canonical_name = _CANONICAL_HEADER_NAMES[name_clean]
        if canonical_name in normalized:
            raise ValueError(
                f"Duplicate header '{name}' (case-insensitive collision for '{canonical_name}')"
            )
        if any(ord(c) < 32 or ord(c) == 127 for c in f"{name}:{value}"):
            raise ValueError(f"Header '{name}' contains control characters or line breaks")
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(f"Header '{name}' value must contain only ASCII characters") from exc
        normalized[canonical_name] = value
    return normalized


class CatalogBaseModel(BaseModel):
    """Shared base model with strict field rejection and input redaction in errors."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class DetectionDefinition(CatalogBaseModel):
    """Detection strategy and HTTP response heuristics."""

    strategy: CheckMethod = CheckMethod.GENERIC_HTML
    confidence_strategy: ConfidenceStrategy = ConfidenceStrategy.MULTI_SIGNAL
    expected_status: list[int] = Field(default_factory=lambda: [200])
    not_found_status: list[int] = Field(default_factory=lambda: [404, 410])
    json_id_field: str | None = None
    success_patterns: list[str] = Field(default_factory=list)
    profile_markers: list[str] = Field(default_factory=list)
    not_found_patterns: list[str] = Field(default_factory=list)
    soft_404_patterns: list[str] = Field(default_factory=list)
    login_patterns: list[str] = Field(default_factory=list)
    blocked_patterns: list[str] = Field(default_factory=list)
    challenge_patterns: list[str] = Field(default_factory=list)
    captcha_patterns: list[str] = Field(default_factory=list)
    redirect_home: str | None = None
    redirect_search: str | None = None

    @field_validator("expected_status", "not_found_status")
    @classmethod
    def validate_statuses(cls, v: list[int], info: Any) -> list[int]:
        if not v:
            raise ValueError("Status code list cannot be empty")
        for code in v:
            if not isinstance(code, int) or code < 100 or code > 599:
                raise ValueError(f"Invalid HTTP status code: {code}")
        if info.field_name in {"expected_status", "not_found_status"}:
            for code in v:
                if 500 <= code <= 599 or code in {401, 403, 408, 429}:
                    raise ValueError(
                        f"{info.field_name} cannot contain reserved HTTP status code {code} (must not be 401, 403, 408, 429, or 500-599)"
                    )
        return v

    @field_validator(
        "success_patterns",
        "profile_markers",
        "not_found_patterns",
        "soft_404_patterns",
        "login_patterns",
        "blocked_patterns",
        "challenge_patterns",
        "captcha_patterns",
    )
    @classmethod
    def validate_patterns(cls, v: list[str], info: Any) -> list[str]:
        field_name = info.field_name or "pattern"
        _validate_regex_patterns(v, field_name)
        return v

    @field_validator("redirect_home", "redirect_search")
    @classmethod
    def validate_redirect_policies(cls, v: Any, info: Any) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str):
            field_name = info.field_name or "redirect_policy"
            raise ValueError(f"{field_name} must be a string, got {type(v).__name__}")
        norm = v.strip().lower()
        if norm != "not_found":
            field_name = info.field_name or "redirect_policy"
            raise ValueError(
                f"{field_name} has invalid policy '{v}'. Only 'not_found' is supported"
            )
        return "not_found"

    @field_validator("json_id_field")
    @classmethod
    def validate_json_id_field(cls, v: Any) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError(f"json_id_field must be a string, got {type(v).__name__}")
        norm = v.strip()
        if not norm:
            raise ValueError("json_id_field must not be empty or whitespace-only")
        return norm


class ExtractionDefinition(CatalogBaseModel):
    """Profile metadata extraction field mapping."""

    display_name_fields: list[str] = Field(default_factory=list)
    website_fields: list[str] = Field(default_factory=list)
    bio_field: str | None = None
    avatar_field: str | None = None
    location_field: str | None = None


class RequestDefinition(CatalogBaseModel):
    """HTTP request parameters, rate limits, and headers."""

    check_url: str | None = None
    http_method: str = "GET"
    rate_limit: float | None = None
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("rate_limit")
    @classmethod
    def validate_rate_limit(cls, v: float | None) -> float | None:
        if v is None:
            return None
        if not math.isfinite(v) or v <= 0:
            raise ValueError(f"Rate limit must be a finite positive number, got {v}")
        return v

    @field_validator("check_url")
    @classmethod
    def validate_check_url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _validate_url_template(v, "check_url")

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v: dict[str, str]) -> dict[str, str]:
        return _validate_static_headers(v)

    @field_validator("http_method")
    @classmethod
    def validate_http_method(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError(f"http_method must be a string, got {type(v).__name__}")
        method = v.strip().upper()
        if method not in {"GET", "HEAD"}:
            raise ValueError(
                f"Unsupported HTTP method '{v}': catalog checks are passive-only and restricted to GET or HEAD"
            )
        return method


class AccessDefinition(CatalogBaseModel):
    """Access mode and authentication requirements."""

    auth_platform: str | None = None
    requires_auth: StrictBool = False

    @field_validator("auth_platform")
    @classmethod
    def validate_auth_platform(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError(f"auth_platform must be a string, got {type(v).__name__}")
        v_clean = v.strip().lower()
        if not v_clean:
            raise ValueError("auth_platform cannot be an empty string")
        try:
            return normalize_platform(v_clean)
        except ValueError as exc:
            raise ValueError(f"Unsupported auth platform: {v_clean}") from exc

    @model_validator(mode="after")
    def validate_auth_contract(self) -> AccessDefinition:
        """Enforce strict consistency between requires_auth and auth_platform."""
        if self.requires_auth and not self.auth_platform:
            raise ValueError("requires_auth is true but auth_platform is missing")
        if not self.requires_auth and self.auth_platform:
            raise ValueError(
                f"auth_platform '{self.auth_platform}' is specified but requires_auth is false"
            )
        return self


class SiteDefinition(CatalogBaseModel):
    """Typed, validated public site definition for username collection."""

    slug: str
    name: str
    category: str
    profile_url: str
    enabled: StrictBool = True
    sensitive: StrictBool = False
    notes: str | None = None
    detection: DetectionDefinition = Field(default_factory=DetectionDefinition)
    extraction: ExtractionDefinition = Field(default_factory=ExtractionDefinition)
    request: RequestDefinition = Field(default_factory=RequestDefinition)
    access: AccessDefinition = Field(default_factory=AccessDefinition)

    @model_validator(mode="before")
    @classmethod
    def preprocess_flat_or_nested(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d = dict(data)

        # Strict string and boolean type checks on raw scalar inputs before any transformation
        raw_name = d.get("name")
        if raw_name is not None and not isinstance(raw_name, str):
            raise ValueError(f"Site 'name' must be a string, got {type(raw_name).__name__}")
        name = str(raw_name or "").strip()

        raw_slug = d.get("slug")
        if raw_slug is not None and not isinstance(raw_slug, str):
            raise ValueError(f"Site 'slug' must be a string, got {type(raw_slug).__name__}")
        # Display-name derivation is the custom/legacy fallback only. Production loading
        # rejects missing slugs at the catalog boundary (require_explicit_slug).
        slug = str(raw_slug or "").strip().lower() or slugify_name(name)

        raw_cat = d.get("category")
        if raw_cat is not None and not isinstance(raw_cat, str):
            raise ValueError(f"Site 'category' must be a string, got {type(raw_cat).__name__}")

        raw_prof = d.get("profile_url")
        if raw_prof is not None and not isinstance(raw_prof, str):
            raise ValueError(f"Site 'profile_url' must be a string, got {type(raw_prof).__name__}")

        raw_tmpl = d.get("url_template")
        if raw_tmpl is not None and not isinstance(raw_tmpl, str):
            raise ValueError(f"Site 'url_template' must be a string, got {type(raw_tmpl).__name__}")

        raw_check = d.get("check_url")
        if raw_check is not None and not isinstance(raw_check, str):
            raise ValueError(f"Site 'check_url' must be a string, got {type(raw_check).__name__}")

        raw_auth_plat = d.get("auth_platform")
        if raw_auth_plat is not None and not isinstance(raw_auth_plat, str):
            raise ValueError(f"Site 'auth_platform' must be a string, got {type(raw_auth_plat).__name__}")

        raw_enabled = d.get("enabled")
        if raw_enabled is not None and not isinstance(raw_enabled, bool):
            raise ValueError(f"Site 'enabled' must be a bool, got {type(raw_enabled).__name__}")

        raw_sensitive = d.get("sensitive")
        if raw_sensitive is not None and not isinstance(raw_sensitive, bool):
            raise ValueError(f"Site 'sensitive' must be a bool, got {type(raw_sensitive).__name__}")

        # Reject unknown top-level legacy keys to prevent silent typos
        for k in d:
            if k not in _KNOWN_LEGACY_FLAT_KEYS:
                site_id = name or slug or "unknown_site"
                raise ValueError(f"Unknown field '{k}' in site definition '{site_id}'")

        # Extract nested structures or build them from flat keys
        detection_data = d.pop("detection", None)
        if detection_data is None:
            detection_data = {
                "strategy": d.pop("check_method", "generic_html"),
                "confidence_strategy": d.pop("confidence_strategy", "multi_signal"),
                "expected_status": d.pop("expected_status", [200]),
                "not_found_status": d.pop("not_found_status", [404, 410]),
                "json_id_field": d.pop("json_id_field", None),
                "success_patterns": d.pop("success_patterns", []),
                "profile_markers": d.pop("profile_markers", []),
                "not_found_patterns": d.pop("not_found_patterns", []),
                "soft_404_patterns": d.pop("soft_404_patterns", []),
                "login_patterns": d.pop("login_patterns", []),
                "blocked_patterns": d.pop("blocked_patterns", []),
                "challenge_patterns": d.pop("challenge_patterns", []),
                "captcha_patterns": d.pop("captcha_patterns", []),
                "redirect_home": d.pop("redirect_home", None),
                "redirect_search": d.pop("redirect_search", None),
            }

        extraction_data = d.pop("extraction", None)
        if extraction_data is None:
            extraction_data = {
                "display_name_fields": d.pop("display_name_fields", []),
                "website_fields": d.pop("website_fields", []),
                "bio_field": d.pop("bio_field", None),
                "avatar_field": d.pop("avatar_field", None),
                "location_field": d.pop("location_field", None),
            }

        request_data = d.pop("request", None)
        if request_data is None:
            request_data = {
                "check_url": d.pop("check_url", None),
                "http_method": d.pop("http_method", "GET"),
                "rate_limit": d.pop("rate_limit", None),
                "headers": d.pop("headers", {}),
            }

        access_data = d.pop("access", None)
        if access_data is None:
            raw_auth_plat = d.pop("auth_platform", None)
            if "requires_auth" in d:
                raw_req_auth = d.pop("requires_auth")
                if not isinstance(raw_req_auth, bool):
                    raise ValueError(
                        f"Site 'requires_auth' must be a bool, got {type(raw_req_auth).__name__}"
                    )
                req_auth = raw_req_auth
            else:
                # If requires_auth is omitted and auth_platform is present -> derive True (backward compatibility)
                auth_plat_check = str(raw_auth_plat).strip().lower() if raw_auth_plat else None
                req_auth = bool(auth_plat_check is not None)

            if raw_auth_plat is not None and not isinstance(raw_auth_plat, str):
                raise ValueError(f"Site 'auth_platform' must be a string, got {type(raw_auth_plat).__name__}")

            auth_plat = str(raw_auth_plat).strip().lower() if raw_auth_plat else None

            access_data = {
                "auth_platform": auth_plat,
                "requires_auth": req_auth,
            }

        # Unconditionally consume both URL template aliases
        raw_profile_url = d.pop("profile_url", None)
        raw_url_template = d.pop("url_template", None)

        if raw_profile_url is not None and raw_url_template is not None:
            if raw_profile_url != raw_url_template:
                site_id = name or slug or "unknown_site"
                raise ValueError(
                    f"Site '{site_id}' profile_url and url_template define conflicting URL templates"
                )
            profile_url = raw_profile_url
        elif raw_profile_url is not None:
            profile_url = raw_profile_url
        elif raw_url_template is not None:
            profile_url = raw_url_template
        else:
            profile_url = ""

        out: dict[str, Any] = {
            "slug": slug,
            "name": name,
            "category": str(d.pop("category", "")).strip(),
            "profile_url": str(profile_url),
            "enabled": d.pop("enabled", True),
            "sensitive": d.pop("sensitive", False),
            "notes": d.pop("notes", None),
            "detection": detection_data,
            "extraction": extraction_data,
            "request": request_data,
            "access": access_data,
        }
        # If any unprocessed key remains in d, it will be placed in out and caught by extra="forbid"
        out.update(d)
        return out

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Site display name cannot be empty")
        return v

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or not CANONICAL_SLUG_PATTERN.match(v):
            raise ValueError(
                f"Invalid site slug '{v}': must be non-empty lowercase alphanumeric and underscores"
            )
        return v

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        v = v.strip()
        cat_lower = v.lower()
        if cat_lower not in KNOWN_CATEGORIES:
            valid_cats = ", ".join(sorted(KNOWN_CATEGORIES.values()))
            raise ValueError(f"Unknown category '{v}'. Allowed categories: {valid_cats}")
        return KNOWN_CATEGORIES[cat_lower]

    @field_validator("profile_url")
    @classmethod
    def validate_profile_url(cls, v: str) -> str:
        return _validate_url_template(v, "profile_url")

    @model_validator(mode="after")
    def validate_strategy_contracts(self) -> SiteDefinition:
        """Validate strategy-specific requirements and reject contradictory configurations."""
        # Contradiction check: Status overlap
        overlap = set(self.detection.expected_status) & set(self.detection.not_found_status)
        if overlap:
            raise ValueError(
                f"Site '{self.name}' has conflicting status codes in both expected_status and not_found_status: {sorted(overlap)}"
            )

        # Strategy-specific requirements
        if self.detection.strategy == CheckMethod.JSON_API:
            if not self.detection.json_id_field:
                raise ValueError(
                    f"Site '{self.name}' with strategy 'json_api' must specify 'json_id_field'"
                )
            if self.request.http_method.upper() != "GET":
                raise ValueError(
                    f"Site '{self.name}' with strategy 'json_api' must use HTTP method 'GET' (got '{self.request.http_method}')"
                )
            if self.detection.confidence_strategy != ConfidenceStrategy.EXPLICIT_API:
                raise ValueError(
                    f"Site '{self.name}' with strategy 'json_api' must use confidence_strategy 'explicit_api' (got '{self.detection.confidence_strategy.value}')"
                )
        elif self.detection.strategy == CheckMethod.LOGIN_WALL:
            if not self.detection.login_patterns:
                raise ValueError(
                    f"Site '{self.name}' with strategy 'login_wall' must specify 'login_patterns'"
                )
        return self

    # --- Backward compatibility properties ---
    @property
    def url_template(self) -> str:
        return self.profile_url

    @property
    def check_method(self) -> str:
        return self.detection.strategy.value

    @property
    def confidence_strategy(self) -> str:
        return self.detection.confidence_strategy.value

    @property
    def expected_status(self) -> list[int]:
        return list(self.detection.expected_status)

    @property
    def not_found_status(self) -> list[int]:
        return list(self.detection.not_found_status)

    @property
    def json_id_field(self) -> str | None:
        return self.detection.json_id_field

    @property
    def display_name_fields(self) -> list[str]:
        return list(self.extraction.display_name_fields)

    @property
    def website_fields(self) -> list[str]:
        return list(self.extraction.website_fields)

    @property
    def bio_field(self) -> str | None:
        return self.extraction.bio_field

    @property
    def avatar_field(self) -> str | None:
        return self.extraction.avatar_field

    @property
    def location_field(self) -> str | None:
        return self.extraction.location_field

    @property
    def success_patterns(self) -> list[str]:
        return list(self.detection.success_patterns)

    @property
    def profile_markers(self) -> list[str]:
        return list(self.detection.profile_markers or self.detection.success_patterns)

    @property
    def not_found_patterns(self) -> list[str]:
        return list(self.detection.not_found_patterns)

    @property
    def soft_404_patterns(self) -> list[str]:
        return list(self.detection.soft_404_patterns)

    @property
    def login_patterns(self) -> list[str]:
        return list(self.detection.login_patterns)

    @property
    def blocked_patterns(self) -> list[str]:
        return list(self.detection.blocked_patterns)

    @property
    def challenge_patterns(self) -> list[str]:
        return list(self.detection.challenge_patterns)

    @property
    def captcha_patterns(self) -> list[str]:
        return list(self.detection.captcha_patterns)

    @property
    def redirect_home(self) -> str | None:
        return self.detection.redirect_home

    @property
    def redirect_search(self) -> str | None:
        return self.detection.redirect_search

    @property
    def http_method(self) -> str:
        return self.request.http_method

    @property
    def headers(self) -> dict[str, str]:
        return dict(self.request.headers)

    @property
    def rate_limit(self) -> float | None:
        return self.request.rate_limit

    @property
    def auth_platform(self) -> str | None:
        return self.access.auth_platform

    @property
    def requires_auth(self) -> bool:
        return self.access.requires_auth

    @property
    def check_url(self) -> str:
        return self.request.check_url or self.profile_url

    def to_dict(self) -> dict[str, Any]:
        """Produce a complete dictionary matching the legacy catalog contract without dropping any field."""
        return {
            "slug": self.slug,
            "name": self.name,
            "category": self.category,
            "profile_url": self.profile_url,
            "url_template": self.profile_url,
            "check_url": self.request.check_url or self.profile_url,
            "check_method": self.detection.strategy.value,
            "confidence_strategy": self.detection.confidence_strategy.value,
            "enabled": self.enabled,
            "sensitive": self.sensitive,
            "http_method": self.request.http_method,
            "headers": dict(self.request.headers),
            "rate_limit": self.request.rate_limit,
            "notes": self.notes,
            "auth_platform": self.access.auth_platform,
            "requires_auth": self.access.requires_auth,
            "expected_status": list(self.detection.expected_status),
            "not_found_status": list(self.detection.not_found_status),
            "json_id_field": self.detection.json_id_field,
            "display_name_fields": list(self.extraction.display_name_fields),
            "website_fields": list(self.extraction.website_fields),
            "bio_field": self.extraction.bio_field,
            "avatar_field": self.extraction.avatar_field,
            "location_field": self.extraction.location_field,
            "success_patterns": list(self.detection.success_patterns),
            "profile_markers": list(self.detection.profile_markers or self.detection.success_patterns),
            "not_found_patterns": list(self.detection.not_found_patterns),
            "soft_404_patterns": list(self.detection.soft_404_patterns),
            "login_patterns": list(self.detection.login_patterns),
            "blocked_patterns": list(self.detection.blocked_patterns),
            "challenge_patterns": list(self.detection.challenge_patterns),
            "captcha_patterns": list(self.detection.captcha_patterns),
            "redirect_home": self.detection.redirect_home,
            "redirect_search": self.detection.redirect_search,
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def __contains__(self, key: str) -> bool:
        return key in self.to_dict()


class SiteCatalog:
    """Process-local cached container for validated site definitions with introspection APIs."""

    def __init__(self, sites: list[SiteDefinition]) -> None:
        self._sites = [s.model_copy(deep=True) for s in sites]
        self._by_slug: dict[str, SiteDefinition] = {}
        self._by_name: dict[str, SiteDefinition] = {}

        for site in self._sites:
            if site.slug in self._by_slug:
                existing = self._by_slug[site.slug]
                raise CatalogValidationError(
                    site_identifier=site.slug,
                    field_name="slug",
                    reason=f"Duplicate slug '{site.slug}' between '{site.name}' and '{existing.name}'",
                )
            name_lower = site.name.strip().lower()
            if name_lower in self._by_name:
                existing = self._by_name[name_lower]
                raise CatalogValidationError(
                    site_identifier=site.name,
                    field_name="name",
                    reason=f"Duplicate site name '{site.name}' (case-insensitive collision with '{existing.name}')",
                )
            self._by_slug[site.slug] = site
            self._by_name[name_lower] = site

    @property
    def sites(self) -> list[SiteDefinition]:
        """Return detached snapshot copies of all site definitions."""
        return [s.model_copy(deep=True) for s in self._sites]

    def total_sites(self, enabled_only: bool = True) -> int:
        """Total number of sites in the catalog."""
        if enabled_only:
            return sum(1 for s in self._sites if s.enabled)
        return len(self._sites)

    def categories(self, enabled_only: bool = True) -> list[str]:
        """Sorted list of unique categories in the catalog."""
        cats = {s.category for s in self._sites if not enabled_only or s.enabled}
        return sorted(cats)

    def count_by_category(self, enabled_only: bool = True) -> dict[str, int]:
        """Count of sites grouped by category."""
        counts: dict[str, int] = {}
        for s in self._sites:
            if enabled_only and not s.enabled:
                continue
            counts[s.category] = counts.get(s.category, 0) + 1
        return dict(sorted(counts.items()))

    def count_by_strategy(self, enabled_only: bool = True) -> dict[str, int]:
        """Count of sites grouped by detection strategy."""
        counts: dict[str, int] = {}
        for s in self._sites:
            if enabled_only and not s.enabled:
                continue
            strat = s.detection.strategy.value
            counts[strat] = counts.get(strat, 0) + 1
        return dict(sorted(counts.items()))

    def count_by_confidence_strategy(self, enabled_only: bool = True) -> dict[str, int]:
        """Count of sites grouped by confidence strategy."""
        counts: dict[str, int] = {}
        for s in self._sites:
            if enabled_only and not s.enabled:
                continue
            strat = s.detection.confidence_strategy.value
            counts[strat] = counts.get(strat, 0) + 1
        return dict(sorted(counts.items()))

    def get_by_slug(self, slug: str) -> SiteDefinition | None:
        """Find a site definition by its stable slug, returning a detached snapshot copy."""
        s = self._by_slug.get(slug.strip().lower())
        return s.model_copy(deep=True) if s is not None else None

    def get_by_name(self, name: str) -> SiteDefinition | None:
        """Find a site definition by its display name (case-insensitive), returning a detached snapshot copy."""
        s = self._by_name.get(name.strip().lower())
        return s.model_copy(deep=True) if s is not None else None

    def filter(
        self,
        *,
        categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        include_sensitive: bool = True,
        strategies: list[str] | None = None,
        enabled_only: bool = True,
    ) -> list[SiteDefinition]:
        """Filter site definitions based on criteria, returning detached snapshot copies."""
        cats_allowed = {c.strip().lower() for c in categories} if categories else None
        cats_excluded = {c.strip().lower() for c in exclude_categories} if exclude_categories else set()
        strats_allowed = {s.strip().lower() for s in strategies} if strategies else None

        result: list[SiteDefinition] = []
        for s in self._sites:
            if enabled_only and not s.enabled:
                continue
            if not include_sensitive and s.sensitive:
                continue
            cat_lower = s.category.lower()
            if cats_allowed is not None and cat_lower not in cats_allowed:
                continue
            if cat_lower in cats_excluded:
                continue
            strat_lower = s.detection.strategy.value.lower()
            if strats_allowed is not None and strat_lower not in strats_allowed:
                continue
            result.append(s.model_copy(deep=True))
        return result

    def to_dict_list(self, enabled_only: bool = True) -> list[dict[str, Any]]:
        """Return raw dictionaries for backward compatibility with legacy consumers."""
        return [
            s.to_dict()
            for s in self._sites
            if not enabled_only or s.enabled
        ]

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        source_label: str = "sites.yaml",
        *,
        require_explicit_slug: bool = False,
    ) -> SiteCatalog:
        """Construct and validate a SiteCatalog from a dictionary structure.

        With require_explicit_slug=True every entry must declare its own non-blank
        `slug`, already canonical before model normalization; display-name derivation
        is refused. This is the production contract enforced by load_catalog() for the
        bundled catalog.
        """
        if not isinstance(data, dict):
            raise CatalogValidationError(
                site_identifier=source_label,
                field_name=None,
                reason="Top-level catalog document must be a dictionary",
            )

        # Reject unexpected root keys
        extra_root = set(data.keys()) - _ALLOWED_ROOT_KEYS
        if extra_root:
            bad_key = sorted(extra_root)[0]
            allowed_fmt = " or ".join(sorted(f"'{k}'" for k in _ALLOWED_ROOT_KEYS))
            raise CatalogValidationError(
                site_identifier=source_label,
                field_name=bad_key,
                reason=f"Unknown root catalog key '{bad_key}'. Only {allowed_fmt} permitted",
            )

        if "defaults" in data:
            raw_defaults = data["defaults"]
            if not isinstance(raw_defaults, dict):
                raise CatalogValidationError(
                    site_identifier=source_label,
                    field_name="defaults",
                    reason=f"Top-level 'defaults' must be a mapping, got {type(raw_defaults).__name__}",
                )

        raw_sites = data.get("sites")
        if raw_sites is None or not isinstance(raw_sites, list):
            raise CatalogValidationError(
                site_identifier=source_label,
                field_name="sites",
                reason="Catalog YAML must contain a top-level 'sites' list",
            )
        validated_sites: list[SiteDefinition] = []
        for idx, item in enumerate(raw_sites):
            if not isinstance(item, dict):
                raise CatalogValidationError(
                    site_identifier=f"entry_{idx}",
                    field_name=None,
                    reason=f"Site entry at index {idx} must be a dictionary, got {type(item).__name__}",
                )
            site_name = str(item.get("name") or item.get("slug") or f"index_{idx}")
            if require_explicit_slug:
                _validate_raw_production_slug(item, site_name)
            try:
                site_def = SiteDefinition.model_validate(item)
                validated_sites.append(site_def)
            except ValidationError as exc:
                errs = exc.errors()
                field_name = None
                reason = str(exc)
                if errs:
                    loc = errs[0].get("loc", ())
                    field_name = ".".join(str(p) for p in loc)
                    reason = errs[0].get("msg", reason)
                raise CatalogValidationError(
                    site_identifier=site_name,
                    field_name=field_name,
                    reason=reason,
                ) from exc
            except ValueError as exc:
                raise CatalogValidationError(
                    site_identifier=site_name,
                    field_name=None,
                    reason=str(exc),
                ) from exc

        return cls(validated_sites)

    @classmethod
    def from_yaml_file(cls, path: Path, *, require_explicit_slug: bool = False) -> SiteCatalog:
        """Load and validate a SiteCatalog from a YAML file path."""
        if not path.exists():
            raise FileNotFoundError(f"Catalog file not found: {path}")
        raw_content = path.read_text(encoding="utf-8")
        try:
            parsed = yaml.load(raw_content, Loader=CatalogSafeLoader) or {}
        except CatalogValidationError:
            raise
        except yaml.YAMLError as exc:
            raise CatalogValidationError(
                site_identifier=path.name,
                field_name=None,
                reason=f"Malformed YAML syntax: {exc}",
            ) from exc
        if not isinstance(parsed, dict):
            raise CatalogValidationError(
                site_identifier=path.name,
                field_name=None,
                reason="Top-level YAML document must be a dictionary mapping",
            )
        return cls.from_dict(
            parsed,
            source_label=str(path),
            require_explicit_slug=require_explicit_slug,
        )


_CATALOG_CACHE: dict[tuple[Path, bool], SiteCatalog] = {}


def _bundled_catalog_path() -> Path:
    """Resolved path of the bundled production catalog."""
    return (BUNDLED_DATA_DIR / "sites.yaml").resolve()


def load_catalog(
    path: Path | None = None,
    *,
    reload: bool = False,
    require_explicit_slug: bool | None = None,
) -> SiteCatalog:
    """Load and validate the process-local cached site catalog.

    Results are cached in memory for low-overhead process-local access.
    Pass reload=True to force re-reading and re-validating the file.

    Explicit slugs are mandatory for the bundled production catalog: an entry that
    omits `slug`, or declares one that is not already canonical, is rejected instead
    of silently receiving a display-name-derived or normalized identifier.

    require_explicit_slug=None (the default) resolves that contract from the target:
    strict for the bundled production catalog, lenient for any other path, which
    keeps pre-B2-02B behavior for custom and legacy catalog files. Pass True or False
    to state the contract deliberately for either target.
    """
    bundled_path = _bundled_catalog_path()
    target_path = path.resolve() if path is not None else bundled_path
    strict = (
        target_path == bundled_path
        if require_explicit_slug is None
        else require_explicit_slug
    )
    cache_key = (target_path, strict)
    if not reload and cache_key in _CATALOG_CACHE:
        return _CATALOG_CACHE[cache_key]

    catalog = SiteCatalog.from_yaml_file(target_path, require_explicit_slug=strict)
    _CATALOG_CACHE[cache_key] = catalog
    return catalog


def clear_catalog_cache() -> None:
    """Clear in-memory process-local catalog cache."""
    _CATALOG_CACHE.clear()
