"""Login observation state machine.

No Playwright import. Never decides to reload the current login form.
Polling callers must apply WAIT without navigation, focus, or page.content().
"""

from __future__ import annotations

from dataclasses import dataclass

from spectre_osint.browser.models import (
    DEFAULT_OAUTH_REJECT_HINTS,
    PlatformSpec,
    cookie_names_present,
)
from spectre_osint.core.types import SessionStatus

POLL_INTERVAL_S = 2.0

GOTO_HOME = "GOTO_HOME"
GOTO_LOGIN = "GOTO_LOGIN"
WAIT = "WAIT"
SUCCESS = "SUCCESS"
STOP = "STOP"

TERMINAL_SESSION_STATUSES = frozenset(
    {
        SessionStatus.CAPTCHA_REQUIRED,
        SessionStatus.CHALLENGE_REQUIRED,
        SessionStatus.BLOCKED,
        SessionStatus.TEMPORARILY_LIMITED,
        SessionStatus.OAUTH_BROWSER_REJECTED,
        SessionStatus.CHROME_NOT_FOUND,
        SessionStatus.CDP_UNAVAILABLE,
        SessionStatus.CHROME_PROFILE_LOCKED,
        SessionStatus.WINDOWS_CDP_LAUNCH_FAILED,
    }
)

DEFAULT_LIMITED_HINTS = (
    "temporarily limited",
    "limited your login",
    "we've temporarily limited",
    "temporarily locked",
    "too many attempts",
    "attempt limit",
    "maximum number of attempts",
)


@dataclass(frozen=True)
class LoginAction:
    kind: str
    status: SessionStatus | None = None
    navigate_to: str | None = None


def is_blank_url(url: str) -> bool:
    lowered = (url or "").strip().lower()
    return lowered in {"", "about:blank", "chrome://newtab/", "chrome://new-tab-page/"}


def is_login_url(spec: PlatformSpec, url: str) -> bool:
    lowered = (url or "").lower()
    if is_blank_url(lowered):
        return False
    return any(hint.lower() in lowered for hint in spec.login_url_hints)


def cookies_as_storage(cookies: list[dict] | tuple[dict, ...] | None) -> dict:
    return {"cookies": list(cookies or []), "origins": []}


def has_session_cookies(spec: PlatformSpec, cookies: list[dict] | None) -> bool:
    return cookie_names_present(cookies_as_storage(cookies), spec.cookie_names)


def detect_temporarily_limited(spec: PlatformSpec, url: str, visible_text: str) -> bool:
    hay = f"{url} {visible_text}".lower()
    hints = spec.limited_hints or DEFAULT_LIMITED_HINTS
    return any(hint.lower() in hay for hint in hints)


def detect_oauth_browser_rejected(spec: PlatformSpec, url: str, visible_text: str) -> bool:
    hay = f"{url} {visible_text}".lower()
    hints = spec.oauth_reject_hints or DEFAULT_OAUTH_REJECT_HINTS
    return any(hint.lower() in hay for hint in hints)


def classify_visible_terminal(spec: PlatformSpec, url: str, visible_text: str) -> SessionStatus | None:
    """Terminal login states from *visible* text. Never scan page HTML/JS bundles."""
    hay = f"{url} {visible_text}".lower()
    if detect_oauth_browser_rejected(spec, url, visible_text):
        return SessionStatus.OAUTH_BROWSER_REJECTED
    if detect_temporarily_limited(spec, url, visible_text):
        return SessionStatus.TEMPORARILY_LIMITED
    if any(hint.lower() in hay for hint in spec.captcha_hints) and "captcha" in hay:
        return SessionStatus.CAPTCHA_REQUIRED
    if any(hint.lower() in hay for hint in spec.challenge_hints):
        return SessionStatus.CHALLENGE_REQUIRED
    if any(hint.lower() in hay for hint in spec.blocked_hints):
        return SessionStatus.BLOCKED
    return None


def classify_browser_state(spec: PlatformSpec, url: str, content: str) -> SessionStatus:
    """Session classification for a fetched page (visible text or short HTML snippet)."""
    terminal = classify_visible_terminal(spec, url, content)
    if terminal is not None:
        return terminal
    if is_login_url(spec, url):
        return SessionStatus.EXPIRED
    return SessionStatus.ACTIVE


def next_login_action(
    spec: PlatformSpec,
    *,
    url: str,
    cookies: list[dict] | None,
    visible_text: str,
    visited_login: bool,
    visited_home: bool,
) -> LoginAction:
    """Decide the next *non-interfering* step.

    GOTO_LOGIN / GOTO_HOME are returned at most conceptually once; the caller
    must never navigate again after the matching visited_* flag is set.
    WAIT must not navigate, reload, or snapshot the full DOM.
    """
    terminal = classify_visible_terminal(spec, url, visible_text)
    if terminal is not None:
        return LoginAction(kind=STOP, status=terminal)

    authed_cookies = has_session_cookies(spec, cookies)
    on_login = is_login_url(spec, url)
    blank = is_blank_url(url)

    if authed_cookies and not on_login and not blank:
        return LoginAction(kind=SUCCESS, status=SessionStatus.ACTIVE)

    if authed_cookies and not visited_home:
        return LoginAction(kind=GOTO_HOME, navigate_to=spec.home_url)

    if not authed_cookies and not visited_login and not on_login:
        return LoginAction(kind=GOTO_LOGIN, navigate_to=spec.login_url)

    return LoginAction(kind=WAIT)
