"""Domain exceptions. A failed provider must never abort an investigation."""

from __future__ import annotations


class SpectreError(Exception):
    """Base error for SPECTRE OSINT."""


class ValidationError(SpectreError):
    """Input did not match a supported entity type or format."""


class ProviderNotConfigured(SpectreError):
    """Optional API key is missing. Investigation continues."""


class ProviderUnavailable(SpectreError):
    """Provider could not be reached or returned a transport error."""


class UnofficialHttpStatus(ProviderUnavailable):
    """Peer/proxy returned a non-RFC HTTP status (>= 600). SPECTRE never synthesizes this."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class TlsVerificationError(ProviderUnavailable):
    """Deterministic TLS/SSL failure (e.g. certificate verify failed, hostname mismatch)."""


class AuthorizationRequired(SpectreError):
    """Active recon was requested without --authorized."""


class RateLimitExceeded(SpectreError):
    """Provider returned HTTP 429 or local quota was exhausted."""

    def __init__(self, message: str, retry_after: str | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class CacheError(SpectreError):
    """Cache backend failure. Callers should fall back to live fetch."""


class SSRFBlocked(SpectreError):
    """Request target is not a permitted public destination."""


class PathSafetyError(SpectreError):
    """Case name or artifact path escaped the allowed directory."""


class AuthError(SpectreError):
    """Authenticated-public OSINT session error."""


class SessionExpired(AuthError):
    """Saved session is no longer valid. Manual login required."""


class ChallengeRequired(AuthError):
    """Platform presented a challenge. SPECTRE will not bypass it."""


class CaptchaRequired(AuthError):
    """Platform presented a CAPTCHA. SPECTRE will not solve it."""


class TemporarilyLimited(AuthError):
    """Platform temporarily limited login. SPECTRE will not retry or bypass."""


class OauthBrowserRejected(AuthError):
    """Google/OAuth refused an automated browser. SPECTRE will not hide automation."""


class BrowserUnavailable(AuthError):
    """Playwright/Chromium is not installed or cannot start."""
