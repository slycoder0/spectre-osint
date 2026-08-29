"""Offline provider evidence rules. No network. No personal data."""

from __future__ import annotations

import logging

from spectre_osint.core.types import Confidence, UsernameCheckStatus
from spectre_osint.modules.username.engine import classify_html, load_sites

ALICE = "alice"


def _site(name: str) -> dict:
    for row in load_sites():
        if row["name"] == name:
            return row
    raise AssertionError(name)


def _classify(name: str, *, status=200, body="", title="", final="", requested="") -> tuple:
    site = _site(name)
    template = str(site.get("profile_url") or "")
    requested = requested or template.format(username=ALICE)
    final = final or requested
    return classify_html(
        status_code=status,
        body=body,
        title=title,
        final_url=final,
        site=site,
        username=ALICE,
        requested_url=requested,
    )


def test_username_in_request_url_alone_is_inconclusive() -> None:
    status, reason, conf = classify_html(
        status_code=200,
        body="<html><title>Home</title>welcome</html>",
        title="Home",
        final_url="https://pypi.org/user/alice/",
        site=_site("PyPI"),
        username=ALICE,
        requested_url="https://pypi.org/user/alice/",
    )
    assert status == UsernameCheckStatus.INCONCLUSIVE
    assert conf is Confidence.LOW
    assert "HTTP 200" in reason
    assert "final_url_only" in reason


def test_generic_og_title_tag_is_not_likely() -> None:
    status, _reason, _conf = classify_html(
        status_code=200,
        body='<html><head><meta property="og:title" content="Welcome"></head><body>home</body></html>',
        title="Welcome",
        final_url="https://www.last.fm/user/alice",
        site=_site("Last.fm"),
        username=ALICE,
        requested_url="https://www.last.fm/user/alice",
    )
    assert status == UsernameCheckStatus.INCONCLUSIVE


def test_pypi_existing_and_missing() -> None:
    ok, reason, conf = _classify(
        "PyPI",
        body='<link rel="canonical" href="https://pypi.org/user/alice/">'
        '<meta property="og:title" content="Profile of alice">'
        '<div class="author-profile">packages</div>',
        title="Profile of alice · PyPI",
    )
    assert ok == UsernameCheckStatus.LIKELY
    assert conf is Confidence.HIGH
    assert ok != UsernameCheckStatus.CONFIRMED
    missing, _r, _c = _classify(
        "PyPI",
        body="<h1>We looked everywhere</h1>not found",
        title="Not Found · PyPI",
    )
    assert missing == UsernameCheckStatus.NOT_FOUND
    home, _r, _c = _classify(
        "PyPI",
        body="<title>PyPI</title>find, install and publish",
        title="PyPI · The Python Package Index",
        final="https://pypi.org/",
    )
    assert home == UsernameCheckStatus.NOT_FOUND


def test_pypi_conflicting_title_is_not_likely() -> None:
    status, _reason, _conf = _classify(
        "PyPI",
        body='<link rel="canonical" href="https://pypi.org/user/alice/">'
        '<meta property="og:title" content="Profile of bob">',
        title="Profile of bob · PyPI",
    )
    assert status == UsernameCheckStatus.INCONCLUSIVE


def test_replit_existing_missing_and_shell() -> None:
    ok, _reason, conf = _classify(
        "Replit",
        body='<link rel="canonical" href="https://replit.com/@alice">'
        '<meta property="og:url" content="https://replit.com/@alice">'
        '<meta property="og:title" content="@alice on Replit">',
        title="@alice - Replit",
    )
    assert ok == UsernameCheckStatus.LIKELY
    assert conf is Confidence.HIGH
    shell, _r, _c = _classify(
        "Replit",
        body="<div id=root></div>",
        title="Replit",
    )
    assert shell == UsernameCheckStatus.INCONCLUSIVE
    gone, _r, _c = _classify(
        "Replit",
        body="user doesn't exist 404",
        title="Not found",
    )
    assert gone == UsernameCheckStatus.NOT_FOUND
    search, _r, _c = _classify(
        "Replit",
        body="results",
        title="Search",
        final="https://replit.com/search?q=alice",
    )
    assert search == UsernameCheckStatus.NOT_FOUND


def test_pinterest_existing_login_and_soft_miss() -> None:
    ok, _reason, conf = _classify(
        "Pinterest",
        body='<link rel="canonical" href="https://www.pinterest.com/alice/">'
        '<meta property="og:url" content="https://www.pinterest.com/alice/">'
        '<meta property="og:title" content="Alice (@alice) on Pinterest">',
        title="Alice (@alice) - Pinterest",
    )
    assert ok == UsernameCheckStatus.LIKELY
    assert ok != UsernameCheckStatus.CONFIRMED
    assert conf is Confidence.HIGH
    login, _r, _c = _classify(
        "Pinterest",
        body="Log in to see more. Sign up.",
        title="Pinterest",
        final="https://www.pinterest.com/login/",
    )
    assert login == UsernameCheckStatus.LOGIN_REQUIRED
    miss, _r, _c = _classify(
        "Pinterest",
        body="Sorry, we couldn't find that user",
        title="Pinterest",
    )
    assert miss == UsernameCheckStatus.NOT_FOUND
    generic, _r, _c = _classify(
        "Pinterest",
        body='<meta property="og:title" content="Pinterest"> pinterest app',
        title="Pinterest",
    )
    assert generic == UsernameCheckStatus.INCONCLUSIVE


def test_steam_existing_missing_and_vanity_redirect() -> None:
    ok, _reason, conf = _classify(
        "Steam",
        body='<div class="profile_header"></div>'
        '<link rel="canonical" href="https://steamcommunity.com/id/alice">'
        '<meta property="og:title" content="alice">',
        title="alice :: Steam Community",
    )
    assert ok == UsernameCheckStatus.LIKELY
    assert conf is Confidence.HIGH
    resolved, _r, _c = _classify(
        "Steam",
        body="<div class=profile_header>persona</div>",
        title="persona",
        final="https://steamcommunity.com/profiles/76561198000000000",
    )
    assert resolved == UsernameCheckStatus.LIKELY
    missing, _r, _c = _classify(
        "Steam",
        body="The specified profile could not be found.",
        title="Steam Community",
    )
    assert missing == UsernameCheckStatus.NOT_FOUND


def test_lastfm_existing_and_generic_200() -> None:
    ok, _reason, conf = _classify(
        "Last.fm",
        body='<link rel="canonical" href="https://www.last.fm/user/alice">'
        '<meta property="og:url" content="https://www.last.fm/user/alice">'
        '<meta property="og:title" content="alice">',
        title="alice’s Music Profile | Last.fm",
    )
    assert ok == UsernameCheckStatus.LIKELY
    assert conf is Confidence.HIGH
    generic, _r, _c = _classify(
        "Last.fm",
        body='<meta property="og:title" content="Last.fm">charts',
        title="Last.fm",
    )
    assert generic == UsernameCheckStatus.INCONCLUSIVE
    missing, _r, _c = _classify(
        "Last.fm",
        body="Page not found",
        title="Page not found",
    )
    assert missing == UsernameCheckStatus.NOT_FOUND


def test_telegram_photo_vs_contact_shell() -> None:
    ok, _reason, conf = _classify(
        "Telegram",
        body='<div class="tgme_page_photo"><img src="/a.jpg"></div>'
        '<div class="tgme_page_title">Alice</div>'
        '<meta property="og:title" content="Alice (@alice)">',
        title="Alice (@alice) — Telegram",
    )
    assert ok == UsernameCheckStatus.LIKELY
    assert ok != UsernameCheckStatus.CONFIRMED
    assert conf is Confidence.MEDIUM
    shell, _r, _c = _classify(
        "Telegram",
        body='<div class="tgme_page_title">alice</div>If you have Telegram, you can contact @alice',
        title="Telegram: Contact @alice",
    )
    assert shell == UsernameCheckStatus.INCONCLUSIVE


def test_debug_log_has_provider_evidence(caplog) -> None:
    caplog.set_level(logging.DEBUG, logger="spectre.username")
    _classify(
        "PyPI",
        body="<html><title>Home</title></html>",
        title="Home",
    )
    text = caplog.text
    assert "provider=PyPI" in text
    assert "status=" in text
    assert "evidence=" in text
    assert "<html>" not in text
    assert "cookie" not in text.lower()


def test_tryhackme_generic_boilerplate_page_is_inconclusive() -> None:
    ok, reason, conf = _classify(
        "TryHackMe",
        body='<link rel="canonical" href="https://tryhackme.com/p/alice">'
        '<div class="user-profile">welcome</div>',
        title="TryHackMe | Cyber Security Training",
    )
    assert ok == UsernameCheckStatus.INCONCLUSIVE
    assert ok != UsernameCheckStatus.LIKELY
    assert ok != UsernameCheckStatus.NOT_FOUND
    assert conf is Confidence.LOW
    assert "generic_platform_title" in reason


def test_tryhackme_real_profile_is_likely() -> None:
    ok, _reason, conf = _classify(
        "TryHackMe",
        body='<link rel="canonical" href="https://tryhackme.com/p/alice">'
        '<div class="user-profile">completed rooms: 10</div>',
        title="Alice Example | TryHackMe",
    )
    assert ok == UsernameCheckStatus.LIKELY
    assert ok != UsernameCheckStatus.CONFIRMED
    assert conf is Confidence.HIGH
