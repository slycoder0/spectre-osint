from __future__ import annotations

import httpx
import pytest

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType
from spectre_osint.modules.username.correlate import link_public_website
from spectre_osint.modules.username.engine import analyze_username, classify_html, load_sites


def test_sites_yaml_loads() -> None:
    sites = load_sites()
    names = {s["name"] for s in sites}
    assert "GitHub" in names
    assert "PyPI" in names
    assert "Bluesky" in names
    assert "Instagram" in names
    assert "GOG" in names
    assert "WordPress.org" in names
    assert "Modrinth" in names
    assert "crates.io" in names
    for site in sites:
        template = site.get("profile_url") or site.get("url_template")
        assert template and "{username}" in template
        assert site["category"]
        assert site.get("check_method")


def test_http_200_alone_is_not_confirmed() -> None:
    status, reason, conf = classify_html(
        status_code=200,
        body="<html><title>Home</title>generic landing</html>",
        title="Home",
        final_url="https://example.com/",
        site={"check_method": "generic_html", "confidence_strategy": "multi_signal"},
        username="alice-sec",
    )
    assert status.value == "INCONCLUSIVE"
    assert "200" in reason or "proof" in reason.lower()
    assert conf is None or conf == Confidence.LOW


def test_soft_404_not_found() -> None:
    status, _reason, _conf = classify_html(
        status_code=200,
        body="Sorry, page not found for this user",
        title="Not Found",
        final_url="https://example.com/alice-sec",
        site={"not_found_patterns": ["page not found"], "check_method": "generic_html"},
        username="alice-sec",
    )
    assert status.value == "NOT_FOUND"


def test_new_provider_http_200_only_is_inconclusive() -> None:
    status, _reason, _conf = classify_html(
        status_code=200,
        body="<html><title>GOG</title>storefront</html>",
        title="GOG",
        final_url="https://www.gog.com/u/nobody",
        site={
            "name": "GOG",
            "check_method": "generic_html",
            "confidence_strategy": "multi_signal",
            "success_patterns": ["user-profile"],
            "not_found_patterns": ["page not found"],
        },
        username="nobody",
    )
    assert status.value == "INCONCLUSIVE"


def test_login_wall() -> None:
    status, _reason, _conf = classify_html(
        status_code=200,
        body="Please log in to continue",
        title="Login",
        final_url="https://instagram.com/alice-sec",
        site={"check_method": "login_wall", "login_patterns": ["log in"]},
        username="alice-sec",
    )
    assert status.value == "LOGIN_REQUIRED"


def test_blocked_and_rate_limit() -> None:
    blocked, _, _ = classify_html(
        status_code=403,
        body="restricted",
        title="",
        final_url="https://example.com/x",
        site={"blocked_patterns": ["restricted"]},
        username="x",
    )
    assert blocked.value == "BLOCKED"
    limited, _, _ = classify_html(
        status_code=429,
        body="slow down",
        title="",
        final_url="https://example.com/x",
        site={},
        username="x",
    )
    assert limited.value == "RATE_LIMITED"


def test_redirect_username_in_url_is_likely() -> None:
    status, _reason, conf = classify_html(
        status_code=200,
        body='<meta property="og:title" content="alice-sec"> success',
        title="alice-sec on Example",
        final_url="https://example.com/alice-sec",
        site={
            "success_patterns": ["og:title"],
            "check_method": "generic_html",
            "confidence_strategy": "multi_signal",
        },
        username="alice-sec",
    )
    assert status.value == "LIKELY"
    assert conf in {Confidence.HIGH, Confidence.MEDIUM}


def test_duplicate_username_normalization() -> None:
    a = Entity.create(EntityType.USERNAME, "Alice-Sec", "t", Confidence.CONFIRMED)
    b = Entity.create(EntityType.USERNAME, "alice-sec", "t", Confidence.CONFIRMED)
    assert a.id == b.id
    assert a.normalized_value == b.normalized_value == "alice-sec"


def test_website_relationship_is_evidence_backed() -> None:
    user = Entity.create(EntityType.USERNAME, "alice-sec", "github", Confidence.CONFIRMED)
    bundle = link_public_website(
        user,
        "https://alice.example/blog",
        source="GitHub",
        evidence_id="abc",
        confidence=Confidence.HIGH,
    )
    assert bundle["entities"]
    assert any(r.relation == RelationType.LINKS_TO for r in bundle["relationships"])
    assert all(r.evidence_id == "abc" for r in bundle["relationships"])
    assert all(r.metadata.get("not_identity") for r in bundle["relationships"])


def test_same_host_website_is_ignored() -> None:
    user = Entity.create(EntityType.USERNAME, "octocat", "github", Confidence.CONFIRMED)
    bundle = link_public_website(
        user, "https://github.com/octocat", source="GitHub", evidence_id="x", confidence=Confidence.HIGH
    )
    assert bundle["entities"] == []


@pytest.mark.asyncio
async def test_json_api_confirmed_and_not_found(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "/users/missing" in str(request.url):
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(
            200,
            json={"login": "octocat", "blog": "https://example.com", "name": "The Octocat"},
        )

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
        found = await analyze_username(
            Entity.create(EntityType.USERNAME, "octocat", "t", Confidence.CONFIRMED),
            http,
            categories=["Development"],
        )
        github = [f for f in found["findings"] if f.title == "GitHub"]
        assert github
        assert github[0].data["check_status"] == "CONFIRMED"
        assert github[0].status == FindingStatus.FOUND
        assert any(e.type == EntityType.DOMAIN for e in found["entities"])
        missing = await analyze_username(
            Entity.create(EntityType.USERNAME, "missing", "t", Confidence.CONFIRMED),
            http,
            categories=["Development"],
        )
        gh_miss = [f for f in missing["findings"] if f.title == "GitHub"]
        assert gh_miss[0].status == FindingStatus.NOT_FOUND
    finally:
        await http.close()
