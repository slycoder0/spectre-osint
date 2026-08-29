"""Regression tests for B2-01C and B2-01D configuration hygiene and encoding safety.

Covers:
A. A copied .env.example produces no falsely configured API providers.
B. VIRUSTOTAL_API_KEY empty => configured False.
C. GITHUB_TOKEN empty => configured False.
D. Inline comments do not become credential values.
E. A credential containing a Unicode em dash cannot reach an HTTP Authorization header and cannot cause UnicodeEncodeError.
F. Legitimate synthetic ASCII test credentials still count as configured.
G. Placeholders and template syntax are treated as unconfigured.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from spectre_osint.cli.doctor import run_doctor
from spectre_osint.core.config import PROJECT_ROOT, Settings
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.registry import default_registry
from spectre_osint.core.types import ProviderKeyType
from spectre_osint.modules.mentions.providers import GitHubSearchProvider
from spectre_osint.providers.github import GitHubProvider
from spectre_osint.providers.virustotal import VirusTotalProvider


def _clean_settings(tmp_path: Path, **kwargs) -> Settings:
    s = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
        **kwargs,
    )
    s.ensure_dirs()
    return s


@pytest.mark.asyncio
async def test_copied_env_example_produces_no_falsely_configured_providers(tmp_path: Path) -> None:
    """Requirement A: .env.example copied to .env results in zero falsely configured providers."""
    env_example_path = PROJECT_ROOT / ".env.example"
    assert env_example_path.exists(), ".env.example must exist at project root"

    env_copy = tmp_path / ".env"
    env_copy.write_text(env_example_path.read_text(encoding="utf-8"), encoding="utf-8")

    settings = Settings(_env_file=env_copy)
    registry = default_registry(http_client=None)
    health_rows = await registry.health(settings, probe=False)

    for row in health_rows:
        if row.key_type == ProviderKeyType.REQUIRED_API_KEY.value:
            assert row.configured is False, f"Provider {row.name} must not be configured by default"
            assert row.status == "NOT CONFIGURED", f"Provider {row.name} status must be NOT CONFIGURED"
        elif row.key_type == ProviderKeyType.OPTIONAL_API_KEY.value:
            assert row.configured_label == "NO", f"Optional provider {row.name} must show configured NO"

    report = run_doctor(settings)
    for check in report["checks"]:
        if check["group"] == "providers":
            assert check["value"] == "NOT CONFIGURED", f"Doctor check {check['label']} was {check['value']}"
        elif check["group"] == "search" and check["label"] == "Google CSE":
            assert check["value"] == "missing"


def test_virustotal_api_key_empty_is_unconfigured(tmp_path: Path) -> None:
    """Requirement B: VIRUSTOTAL_API_KEY empty => configured False."""
    settings = _clean_settings(tmp_path, virustotal_api_key="")
    assert settings.virustotal_api_key is None
    assert settings.secret_present("virustotal_api_key") is False

    vt = VirusTotalProvider()
    assert vt.is_configured(settings) is False
    assert vt.configured_display(settings) == "NO"

    settings_ws = _clean_settings(tmp_path, virustotal_api_key="   ")
    assert settings_ws.virustotal_api_key is None
    assert settings_ws.secret_present("virustotal_api_key") is False


def test_github_token_empty_is_unconfigured(tmp_path: Path) -> None:
    """Requirement C: GITHUB_TOKEN empty => configured False."""
    settings = _clean_settings(tmp_path, github_token="")
    assert settings.github_token is None
    assert settings.secret_present("github_token") is False

    gh = GitHubProvider()
    assert gh.configured_display(settings) == "NO"

    headers = gh._headers(settings)
    assert "Authorization" not in headers


def test_inline_comments_do_not_become_credential_values(tmp_path: Path) -> None:
    """Requirement D: Inline comments never become credential values."""
    settings = _clean_settings(
        tmp_path,
        virustotal_api_key="# REQUIRED — domain/IP/URL/hash intel",
        github_token="# OPTIONAL — higher rate limit + code search",
        shodan_api_key="# comment",
        censys_api_id="# REQUIRED",
        google_cse_id="# cse id comment",
    )
    assert settings.virustotal_api_key is None
    assert settings.secret_present("virustotal_api_key") is False

    assert settings.github_token is None
    assert settings.secret_present("github_token") is False

    assert settings.shodan_api_key is None
    assert settings.secret_present("shodan_api_key") is False

    assert settings.censys_api_id is None
    assert settings.secret_present("censys_api_id") is False

    assert settings.google_cse_id is None

    vt = VirusTotalProvider()
    assert vt.is_configured(settings) is False
    assert vt.configured_display(settings) == "NO"


@pytest.mark.asyncio
async def test_unicode_em_dash_credential_cannot_reach_header_or_cause_encode_error(
    tmp_path: Path,
) -> None:
    """Requirement E: Unicode em dash / malformed values cannot reach HTTP Authorization headers."""
    malformed_token = "malformed\u2014token\u2014test"
    settings = _clean_settings(tmp_path, github_token=malformed_token)

    # Configuration boundary normalization
    assert settings.github_token is None
    assert settings.secret_present("github_token") is False

    # GitHub provider headers
    gh = GitHubProvider()
    headers = gh._headers(settings)
    assert "Authorization" not in headers

    # GitHub search provider in mentions collection
    def handler(request: httpx.Request) -> httpx.Response:
        auth_hdr = request.headers.get("authorization", "")
        assert "\u2014" not in auth_hdr
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "title": "Issue 1",
                        "html_url": "https://github.com/org/repo/issues/1",
                        "body": "test mention",
                        "user": {"login": "test"},
                    }
                ]
            },
        )

    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        provider = GitHubSearchProvider()
        mentions = await provider.search("test", http=http, settings=settings, limit=5)
        assert len(mentions) == 1
        assert mentions[0].title == "Issue 1"
    finally:
        await http.close()


def test_synthetic_legitimate_credentials_are_configured(tmp_path: Path) -> None:
    """Requirement F: Legitimate synthetic ASCII test credentials count as configured."""
    synthetic_key = "synthetic-vt-key-abcdef1234567890"
    synthetic_token = "ghp_syntheticGithubTokenValue1234567890"

    settings = _clean_settings(
        tmp_path,
        virustotal_api_key=synthetic_key,
        github_token=synthetic_token,
    )
    assert settings.virustotal_api_key is not None
    assert settings.virustotal_api_key.get_secret_value() == synthetic_key
    assert settings.secret_present("virustotal_api_key") is True

    assert settings.github_token is not None
    assert settings.github_token.get_secret_value() == synthetic_token
    assert settings.secret_present("github_token") is True

    vt = VirusTotalProvider()
    assert vt.is_configured(settings) is True
    assert vt.configured_display(settings) == "YES"

    gh = GitHubProvider()
    assert gh.configured_display(settings) == "YES"
    headers = gh._headers(settings)
    assert headers.get("Authorization") == f"Bearer {synthetic_token}"


def test_known_placeholders_treated_as_unconfigured(tmp_path: Path) -> None:
    """Requirement G: Known placeholder / template values are treated as unconfigured."""
    placeholders = [
        "your_api_key_here",
        "YOUR_API_KEY_HERE",
        "your_token_here",
        "PLACEHOLDER",
        "placeholder",
        "changeme",
        "change_me",
        "<your-api-key>",
        "<API_KEY>",
        "<token>",
        "none",
        "null",
        "xxx",
        "xxxx",
    ]
    for ph in placeholders:
        settings = _clean_settings(tmp_path, virustotal_api_key=ph, github_token=ph)
        assert settings.virustotal_api_key is None, f"Placeholder {ph} was not normalized to None"
        assert settings.github_token is None, f"Placeholder {ph} was not normalized to None"
        assert settings.secret_present("virustotal_api_key") is False
        assert settings.secret_present("github_token") is False


def test_control_characters_in_credential_treated_as_unconfigured(tmp_path: Path) -> None:
    """Requirement H: Credentials with control chars (e.g. newlines) are treated as unconfigured."""
    bad_values = [
        "token\r\nInjected-Header: evil",
        "token\ninjected",
        "token\x00nullbyte",
    ]
    for bad in bad_values:
        settings = _clean_settings(tmp_path, github_token=bad)
        assert settings.github_token is None
        assert settings.secret_present("github_token") is False
