"""Authenticated public OSINT — browser automation and session store.

This package never:
- stores passwords or TOTP secrets
- accesses DMs or private content
- bypasses CAPTCHA, challenges, rate limits or login walls
- imports cookies from a personal browser without an explicit operator login
"""

from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.models import AUTH_PLATFORMS, AuthProfile, PlatformSpec

__all__ = ["AUTH_PLATFORMS", "AuthProfile", "AuthService", "PlatformSpec"]
