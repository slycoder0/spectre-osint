"""AUTHENTICATED_PUBLIC evidence diagnostics. Does not loosen classification rules."""

from __future__ import annotations

import logging
from pathlib import Path

import httpx
import pytest

from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.manager import (
    _capture_authenticated_public_page,
    _has_public_profile_evidence,
    _needs_public_metadata_wait,
    _wait_for_public_profile_evidence,
)
from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.result_cache import ResultCache
from spectre_osint.core.types import AccessMode, Confidence, EntityType, UsernameCheckStatus
from spectre_osint.modules.username.engine import (
    analyze_username,
    classify_html,
    classify_instagram_authenticated_public,
    username_evidence_report,
)

_IG_SITE = {
    "name": "Instagram",
    "auth_platform": "instagram",
    "check_method": "generic_html",
    "confidence_strategy": "never_confirmed",
    "login_patterns": ["log in", "login", "signup"],
    "captcha_patterns": ["captcha"],
    "challenge_patterns": ["checkpoint"],
    "not_found_patterns": ["sorry, this page isn't available"],
    "blocked_patterns": ["restrict"],
    "expected_status": [200],
}


def _settings(tmp_path: Path) -> Settings:
    s = Settings(
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
    s.ensure_dirs()
    return s


def _ig_auth(
    *,
    username: str = "alice_osint",
    requested_url: str = "https://www.instagram.com/alice_osint/",
    final_url: str = "https://www.instagram.com/alice_osint/",
    canonical_url: str = "",
    og_url: str = "",
    og_title: str = "",
    title: str = "(7) Instagram",
    body: str = "public photos",
) -> tuple[UsernameCheckStatus, str, Confidence] | None:
    return classify_instagram_authenticated_public(
        username=username,
        requested_url=requested_url,
        final_url=final_url,
        canonical_url=canonical_url,
        og_url=og_url,
        og_title=og_title,
        title=title,
        body=body,
        site=_IG_SITE,
    )


def test_instagram_canonical_without_og_title_is_not_likely() -> None:
    assert (
        _ig_auth(
            canonical_url="https://www.instagram.com/alice_osint/",
            og_url="",
            og_title="Instagram",
        )
        is None
    )


def test_instagram_final_url_only_is_inconclusive() -> None:
    generic, reason, conf = classify_html(
        status_code=200,
        body="public photos",
        title="(7) Instagram",
        final_url="https://www.instagram.com/alice_osint/",
        site=_IG_SITE,
        username="alice_osint",
    )
    assert generic == UsernameCheckStatus.INCONCLUSIVE
    assert "HTTP 200" in reason
    assert conf is Confidence.LOW
    assert _ig_auth(canonical_url="", og_url="", og_title="Instagram") is None


def test_instagram_http_200_only_is_inconclusive() -> None:
    generic, reason, _conf = classify_html(
        status_code=200,
        body="",
        title="Instagram",
        final_url="https://www.instagram.com/",
        site=_IG_SITE,
        username="alice_osint",
    )
    assert generic == UsernameCheckStatus.INCONCLUSIVE
    assert "HTTP 200" in reason
    assert (
        _ig_auth(
            requested_url="https://www.instagram.com/",
            final_url="https://www.instagram.com/",
            canonical_url="",
            og_url="",
            og_title="",
            title="Instagram",
            body="",
        )
        is None
    )


def test_instagram_login_wall_keeps_existing_behavior() -> None:
    generic, _reason, _conf = classify_html(
        status_code=200,
        body="Please log in to continue",
        title="Instagram",
        final_url="https://www.instagram.com/accounts/login/",
        site=_IG_SITE,
        username="alice_osint",
    )
    assert generic == UsernameCheckStatus.LOGIN_REQUIRED
    assert (
        _ig_auth(
            final_url="https://www.instagram.com/alice_osint/",
            canonical_url="https://www.instagram.com/alice_osint/",
            og_url="https://www.instagram.com/alice_osint/",
            og_title="Alice Example (@alice_osint) • Instagram photos and videos",
            body="Please log in to continue",
        )
        is None
    )


def test_instagram_not_found_keeps_existing_behavior() -> None:
    generic, _reason, _conf = classify_html(
        status_code=200,
        body="Sorry, this page isn't available",
        title="Instagram",
        final_url="https://www.instagram.com/alice_osint/",
        site=_IG_SITE,
        username="alice_osint",
    )
    assert generic == UsernameCheckStatus.NOT_FOUND
    assert (
        _ig_auth(
            canonical_url="https://www.instagram.com/alice_osint/",
            og_url="https://www.instagram.com/alice_osint/",
            og_title="Alice Example (@alice_osint) • Instagram photos and videos",
            body="Sorry, this page isn't available",
        )
        is None
    )


def test_instagram_canonical_og_url_and_og_title_is_likely_high() -> None:
    generic, _reason, _conf = classify_html(
        status_code=200,
        body="public photos",
        title="(7) Instagram",
        final_url="https://www.instagram.com/alice_osint/",
        site=_IG_SITE,
        username="alice_osint",
    )
    assert generic == UsernameCheckStatus.INCONCLUSIVE
    result = _ig_auth(
        canonical_url="https://www.instagram.com/alice_osint/",
        og_url="https://www.instagram.com/alice_osint/",
        og_title="Alice Example (@alice_osint) • Instagram photos and videos",
        title="(7) Instagram",
    )
    assert result is not None
    status, reason, conf = result
    assert status == UsernameCheckStatus.LIKELY
    assert status != UsernameCheckStatus.CONFIRMED
    assert conf is Confidence.HIGH
    assert "canonical/og:url" in reason
    assert "og:title" in reason


def test_instagram_mismatched_og_title_is_not_likely() -> None:
    assert (
        _ig_auth(
            canonical_url="https://www.instagram.com/alice_osint/",
            og_url="https://www.instagram.com/alice_osint/",
            og_title="Someone Else (@otheruser) • Instagram photos and videos",
            title="(7) Instagram",
        )
        is None
    )


def test_never_confirmed_http_200_and_username_in_url_stay_inconclusive() -> None:
    status, reason, conf = classify_html(
        status_code=200,
        body="loading",
        title="TikTok",
        final_url="https://www.tiktok.com/@alice_osint",
        site={
            "check_method": "generic_html",
            "confidence_strategy": "never_confirmed",
            "expected_status": [200],
        },
        username="alice_osint",
    )
    assert status == UsernameCheckStatus.INCONCLUSIVE
    assert "HTTP 200" in reason
    assert conf is Confidence.LOW


def test_username_evidence_report_flags_without_body() -> None:
    report = username_evidence_report(
        status_code=200,
        body="<html>secret-session-body sessionid=abc</html>",
        title="TikTok",
        final_url="https://www.tiktok.com/@alice_osint",
        site={
            "check_method": "generic_html",
            "confidence_strategy": "never_confirmed",
            "login_patterns": ["log in"],
            "captcha_patterns": ["captcha"],
            "not_found_patterns": ["couldn't find this account"],
        },
        username="alice_osint",
        canonical_url="",
        og_url="",
        og_title="",
        content_length=42,
    )
    assert report["username_in_final_url"] is True
    assert report["username_in_title"] is False
    assert report["username_in_canonical"] is False
    assert report["http_status"] == 200
    assert report["content_length"] == 42
    assert "http_200_not_proof" in report["negative_rules"]
    assert "secret-session-body" not in str(report.values())
    assert "sessionid=abc" not in str(report)


def test_needs_metadata_wait_only_for_profile_urls() -> None:
    assert _needs_public_metadata_wait("https://www.tiktok.com/@alice_osint", "alice_osint") is True
    assert _needs_public_metadata_wait("https://www.tiktok.com/", "alice_osint") is False
    assert _has_public_profile_evidence({"title": "TikTok", "canonical": "", "og_url": "", "og_title": ""}, "alice_osint") is False
    assert _has_public_profile_evidence(
        {"title": "TikTok", "canonical": "https://www.tiktok.com/@alice_osint", "og_url": "", "og_title": ""},
        "alice_osint",
    ) is True


class _DeferredMetadataPage:
    url = "https://www.tiktok.com/@alice_osint"

    def __init__(self) -> None:
        self.reads = 0
        self.content_calls = 0

    async def content(self) -> str:
        self.content_calls += 1
        raise AssertionError("must not serialize full DOM")

    async def title(self) -> str:
        return "TikTok" if self.reads < 3 else "alice_osint (@alice_osint) | TikTok"

    async def evaluate(self, _script: str) -> dict[str, object]:
        self.reads += 1
        if self.reads < 3:
            return {
                "canonical": "",
                "og_url": "",
                "og_title": "",
                "title": "TikTok",
                "href": self.url,
                "text_length": 12,
                "visible": "loading",
                "has_user_page": False,
            }
        return {
            "canonical": "https://www.tiktok.com/@alice_osint",
            "og_url": "https://www.tiktok.com/@alice_osint",
            "og_title": "alice_osint",
            "title": "alice_osint (@alice_osint) | TikTok",
            "href": self.url,
            "text_length": 180,
            "visible": "alice_osint public profile",
            "has_user_page": True,
        }


@pytest.mark.asyncio
async def test_wait_follows_canonical_without_arbitrary_sleep() -> None:
    page = _DeferredMetadataPage()
    snapshot = await _wait_for_public_profile_evidence(page, "alice_osint", timeout_s=2.0)
    assert snapshot["canonical"] == "https://www.tiktok.com/@alice_osint"
    assert snapshot["og_url"] == "https://www.tiktok.com/@alice_osint"
    assert page.content_calls == 0
    assert page.reads >= 3


@pytest.mark.asyncio
async def test_capture_skips_wait_when_title_already_has_username() -> None:
    class ReadyPage:
        url = "https://www.instagram.com/alice_osint/"
        content_calls = 0

        async def content(self) -> str:
            self.content_calls += 1
            raise AssertionError("must not serialize full DOM")

        async def title(self) -> str:
            return "alice_osint"

        async def evaluate(self, _script: str) -> dict[str, object]:
            return {
                "canonical": "https://www.instagram.com/alice_osint/",
                "og_url": "https://www.instagram.com/alice_osint/",
                "og_title": "alice_osint",
                "title": "alice_osint",
                "href": self.url,
                "text_length": 80,
                "visible": "alice_osint",
                "has_user_page": True,
            }

    page = ReadyPage()
    snapshot = await _capture_authenticated_public_page(page, page.url)
    assert snapshot["metadata_waited"] is False
    assert snapshot["metadata_ready"] is True
    assert page.content_calls == 0


@pytest.mark.asyncio
async def test_authenticated_public_debug_log_omits_body_and_cookies(tmp_path: Path, caplog) -> None:
    caplog.set_level(logging.DEBUG, logger="spectre.username")
    settings = _settings(tmp_path)
    service = AuthService(settings)
    await service.login("instagram")

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, text="Please log in to continue", headers={"content-type": "text/html"})

    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    bundle = await analyze_username(
        entity, http, categories=["Social"], auth_service=service, result_cache=ResultCache(settings)
    )
    insta = next(f for f in bundle["findings"] if f.title == "Instagram")
    assert insta.data["access_mode"] == AccessMode.AUTHENTICATED_PUBLIC.value
    text = caplog.text
    assert "AUTHENTICATED_PUBLIC evidence" in text
    assert "platform=Instagram" in text
    assert "requested_url=" in text
    assert "final_url=" in text
    assert "http_status=" in text
    assert "title=" in text
    assert "canonical=" in text
    assert "og_url=" in text
    assert "username_in_final_url=" in text
    assert "username_in_canonical=" in text
    assert "username_in_og_url=" in text
    assert "username_in_title=" in text
    assert "login_wall=" in text
    assert "captcha=" in text
    assert "challenge=" in text
    assert "not_found=" in text
    assert "positive_rules=" in text
    assert "negative_rules=" in text
    assert "classification=" in text
    assert "reason=" in text
    assert "content_length=" in text
    assert "TESTCOOKIE" not in text
    assert "<html>" not in text
    assert "sessionid=" not in text.lower()
    await http.close()
