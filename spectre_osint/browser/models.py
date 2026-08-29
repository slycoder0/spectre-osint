"""Platform specs and auth profile metadata. No passwords. No cookie values."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, Field

from spectre_osint.core.types import AccessMode, AuthCapability, AuthPlatform, SessionStatus

OFFICIAL_API_SUGGESTION = "Use official API integration for this platform when available."
ANONYMOUS_LOOKUP_UNAFFECTED = "Anonymous public username lookup is unaffected."
NO_BROWSER_RETRY_STATUSES = frozenset(
    {
        SessionStatus.TEMPORARILY_LIMITED,
        SessionStatus.OAUTH_BROWSER_REJECTED,
    }
)
DEFAULT_OAUTH_REJECT_HINTS = (
    "this browser or app may not be secure",
    "couldn't sign you in",
    "could not sign you in",
    "browser may not be secure",
    "try using a different browser",
)

# Public login pages only. SPECTRE never submits credentials.


@dataclass(frozen=True)
class PlatformSpec:
    slug: str
    display_name: str
    login_url: str
    home_url: str
    profile_url_template: str
    cookie_names: tuple[str, ...]
    login_url_hints: tuple[str, ...]
    authenticated_url_hints: tuple[str, ...]
    challenge_hints: tuple[str, ...]
    captcha_hints: tuple[str, ...]
    site_names: tuple[str, ...] = ()
    limited_hints: tuple[str, ...] = (
        "temporarily limited",
        "limited your login",
        "we've temporarily limited",
        "temporarily locked",
        "too many attempts",
        "attempt limit",
        "maximum number of attempts",
    )
    blocked_hints: tuple[str, ...] = ("access denied", "account suspended")
    oauth_reject_hints: tuple[str, ...] = DEFAULT_OAUTH_REJECT_HINTS
    auth_capability: AuthCapability = AuthCapability.PLAYWRIGHT_SESSION
    preferred_browser: str = "playwright"
    retry_browser_after_limit: bool = True
    public_only: bool = True
    notes: str = "Authenticated public OSINT only. No DMs, no private graphs, no follow/friend automation."


def _spec(**kwargs: object) -> PlatformSpec:
    return PlatformSpec(**kwargs)  # type: ignore[arg-type]


AUTH_PLATFORMS = {
    AuthPlatform.INSTAGRAM.value: _spec(
        slug="instagram",
        display_name="Instagram",
        login_url="https://www.instagram.com/accounts/login/",
        home_url="https://www.instagram.com/",
        profile_url_template="https://www.instagram.com/{username}/",
        cookie_names=("sessionid", "ds_user_id"),
        login_url_hints=("/accounts/login", "/login"),
        authenticated_url_hints=("instagram.com/",),
        challenge_hints=("checkpoint", "challenge"),
        captcha_hints=("captcha", "recaptcha"),
        site_names=("Instagram",),
    ),
    AuthPlatform.FACEBOOK.value: _spec(
        slug="facebook",
        display_name="Facebook",
        login_url="https://www.facebook.com/login/",
        home_url="https://www.facebook.com/",
        profile_url_template="https://www.facebook.com/{username}",
        cookie_names=("c_user", "xs"),
        login_url_hints=("/login", "login.php"),
        authenticated_url_hints=("facebook.com/",),
        challenge_hints=("checkpoint", "two_step"),
        captcha_hints=("captcha", "recaptcha"),
        site_names=("Facebook",),
    ),
    AuthPlatform.THREADS.value: _spec(
        slug="threads",
        display_name="Threads",
        login_url="https://www.threads.net/login",
        home_url="https://www.threads.net/",
        profile_url_template="https://www.threads.net/@{username}",
        cookie_names=("sessionid",),
        login_url_hints=("/login",),
        authenticated_url_hints=("threads.net/",),
        challenge_hints=("checkpoint", "challenge"),
        captcha_hints=("captcha",),
        site_names=("Threads",),
    ),
    AuthPlatform.TIKTOK.value: _spec(
        slug="tiktok",
        display_name="TikTok",
        login_url="https://www.tiktok.com/login",
        home_url="https://www.tiktok.com/",
        profile_url_template="https://www.tiktok.com/@{username}",
        cookie_names=("sessionid", "sid_guard"),
        login_url_hints=("/login",),
        authenticated_url_hints=("tiktok.com/",),
        challenge_hints=("verify", "challenge"),
        captcha_hints=("captcha", "recaptcha"),
        site_names=("TikTok",),
        auth_capability=AuthCapability.CHROME_CDP_SESSION,
        preferred_browser="chrome",
        retry_browser_after_limit=False,
        notes=(
            "Authenticated Playwright Chromium is often rate-limited. "
            "Prefer a SPECTRE-owned Google Chrome CDP session on Windows/WSL. "
            + ANONYMOUS_LOOKUP_UNAFFECTED
        ),
    ),
    AuthPlatform.X.value: _spec(
        slug="x",
        display_name="X",
        login_url="https://x.com/i/flow/login",
        home_url="https://x.com/home",
        profile_url_template="https://x.com/{username}",
        cookie_names=("auth_token", "ct0"),
        login_url_hints=("/i/flow/login", "/login"),
        authenticated_url_hints=("x.com/home", "x.com/"),
        challenge_hints=("challenge", "arkose"),
        captcha_hints=("captcha", "arkose"),
        site_names=("X", "Twitter"),
        auth_capability=AuthCapability.BOTH,
        preferred_browser="chrome",
        retry_browser_after_limit=False,
        notes=(
            "Authenticated browser login is often refused by X/Google OAuth. "
            "Anonymous public username lookup is unaffected. "
            + OFFICIAL_API_SUGGESTION
        ),
    ),
    AuthPlatform.TWITCH.value: _spec(
        slug="twitch",
        display_name="Twitch",
        login_url="https://www.twitch.tv/login",
        home_url="https://www.twitch.tv/",
        profile_url_template="https://www.twitch.tv/{username}",
        cookie_names=("auth-token", "persistent"),
        login_url_hints=("/login", "passport.twitch"),
        authenticated_url_hints=("twitch.tv/",),
        challenge_hints=("challenge",),
        captcha_hints=("captcha",),
        site_names=("Twitch",),
    ),
}


class AuthProfile(BaseModel):
    platform: str
    profile_name: str = "osint-research"
    status: SessionStatus = SessionStatus.NOT_CONFIGURED
    created_at: datetime | None = None
    last_verified: datetime | None = None
    expires_at: datetime | None = None
    access_mode: AccessMode = AccessMode.AUTHENTICATED_PUBLIC
    storage: str = "file"
    keyring_available: bool = False
    notes: str = "Password is never stored. Public content only."


class LoginOutcome(BaseModel):
    status: SessionStatus
    storage_state: dict | None = Field(default=None, exclude=True)
    detail: str = ""
    display_name: str = ""


class FetchOutcome(BaseModel):
    status: str
    url: str
    status_code: int = 0
    title: str = ""
    body: str = Field(default="", exclude=True)
    detail: str = ""
    redirected_to_login: bool = False
    canonical_url: str = ""
    og_url: str = ""
    og_title: str = ""
    content_length: int = 0
    metadata_waited: bool = False
    metadata_ready: bool = False


def normalize_platform(value: str) -> str:
    raw = (value or "").strip().lower()
    aliases = {
        "twitter": "x",
        "ig": "instagram",
        "fb": "facebook",
        "tt": "tiktok",
        "www.instagram.com": "instagram",
        "instagram.com": "instagram",
    }
    raw = aliases.get(raw, raw)
    if raw not in AUTH_PLATFORMS:
        raise ValueError(f"Unsupported auth platform: {value}")
    return raw


def platform_for_site(site_name: str) -> PlatformSpec | None:
    wanted = (site_name or "").strip().lower()
    for spec in AUTH_PLATFORMS.values():
        if spec.slug == wanted or wanted in {n.lower() for n in spec.site_names}:
            return spec
    return None


def cookie_names_present(storage_state: dict | None, names: tuple[str, ...]) -> bool:
    if not storage_state or not names:
        return False
    cookies = storage_state.get("cookies")
    if not isinstance(cookies, list):
        return False
    have = {str(c.get("name", "")).lower() for c in cookies if isinstance(c, dict)}
    return any(name.lower() in have for name in names)


def cdp_session_sentinel(spec: PlatformSpec) -> dict:
    """Schema-compatible session blob. Never contains Chrome cookies or secrets."""
    return {
        "backend": AuthCapability.CHROME_CDP_SESSION.value,
        "cookies": [],
        "origins": [],
        "spectre": {"kind": "chrome_cdp", "platform": spec.slug},
    }


def is_cdp_session_state(storage_state: dict | None) -> bool:
    if not isinstance(storage_state, dict):
        return False
    if str(storage_state.get("backend") or "") == AuthCapability.CHROME_CDP_SESSION.value:
        return True
    spectre = storage_state.get("spectre")
    if isinstance(spectre, dict) and str(spectre.get("kind") or "") in {"chrome_cdp", "CHROME_CDP_SESSION"}:
        return True
    return False


def uses_chrome_cdp_session(spec: PlatformSpec, storage_state: dict | None = None) -> bool:
    """TikTok-style CHROME_CDP_SESSION, or a session persisted from Chrome CDP login."""
    if spec.auth_capability == AuthCapability.CHROME_CDP_SESSION:
        return True
    return is_cdp_session_state(storage_state)


def official_api_suggestion(spec: PlatformSpec) -> str | None:
    if spec.auth_capability in {AuthCapability.OFFICIAL_API, AuthCapability.BOTH}:
        return OFFICIAL_API_SUGGESTION
    return None


def browser_login_permitted(spec: PlatformSpec, profile: AuthProfile | None) -> bool:
    """Whether SPECTRE may launch Playwright for this platform right now."""
    if spec.auth_capability in {AuthCapability.UNSUPPORTED, AuthCapability.OFFICIAL_API}:
        return False
    if profile is None:
        return True
    if profile.status in NO_BROWSER_RETRY_STATUSES and not spec.retry_browser_after_limit:
        return False
    return True
