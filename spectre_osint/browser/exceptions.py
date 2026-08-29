"""Browser/auth exceptions. Re-exported from core so callers have one place."""

from spectre_osint.core.exceptions import (
    AuthError,
    BrowserUnavailable,
    CaptchaRequired,
    ChallengeRequired,
    OauthBrowserRejected,
    SessionExpired,
    TemporarilyLimited,
)

__all__ = [
    "AuthError",
    "BrowserUnavailable",
    "CaptchaRequired",
    "ChallengeRequired",
    "OauthBrowserRejected",
    "SessionExpired",
    "TemporarilyLimited",
]
