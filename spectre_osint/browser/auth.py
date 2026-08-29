"""Operator-driven authenticated public OSINT. Never private. Never silent."""

from __future__ import annotations

from pathlib import Path

from spectre_osint.browser.chrome import ensure_chrome_profile, wipe_chrome_profile
from spectre_osint.browser.login_flow import TERMINAL_SESSION_STATUSES
from spectre_osint.browser.manager import (
    BrowserBackend,
    ChromeCdpBackend,
    get_backend,
    map_expected_session_failure,
    resolve_browser_kind,
)
from spectre_osint.browser.models import (
    ANONYMOUS_LOOKUP_UNAFFECTED,
    AUTH_PLATFORMS,
    AuthProfile,
    FetchOutcome,
    PlatformSpec,
    browser_login_permitted,
    normalize_platform,
    official_api_suggestion,
    platform_for_site,
    uses_chrome_cdp_session,
)
from spectre_osint.browser.profiles import new_profile, save_profile
from spectre_osint.browser.sessions import SessionStore
from spectre_osint.browser.userdata import ensure_platform_profile, wipe_platform_profile
from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.logger import get_logger
from spectre_osint.core.types import AccessMode, AuthCapability, SessionStatus

logger = get_logger("spectre.auth")


class AuthService:
    def __init__(
        self,
        settings: Settings | None = None,
        store: SessionStore | None = None,
        backend: BrowserBackend | None = None,
        auth_dir: Path | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.store = store or SessionStore(self.settings, auth_dir=auth_dir)
        self.backend = backend or get_backend(self.settings.browser_backend, self.settings)

    def spec(self, platform: str) -> PlatformSpec:
        return AUTH_PLATFORMS[normalize_platform(platform)]

    def list_profiles(self) -> list[AuthProfile]:
        return self.store.list_profiles()

    def status_rows(self) -> list[dict[str, str]]:
        rows = []
        for profile in self.list_profiles():
            spec = AUTH_PLATFORMS[profile.platform]
            suggestion = official_api_suggestion(spec) or ""
            rows.append(
                {
                    "platform": spec.display_name,
                    "slug": profile.platform,
                    "session": profile.status.value,
                    "profile": profile.profile_name,
                    "last_verified": profile.last_verified.isoformat() if profile.last_verified else "",
                    "mode": AccessMode.AUTHENTICATED_PUBLIC.value
                    if profile.status == SessionStatus.ACTIVE
                    else "",
                    "storage": profile.storage,
                    "capability": spec.auth_capability.value,
                    "preferred_browser": spec.preferred_browser,
                    "suggestion": suggestion,
                    "anonymous_lookup": "available",
                    "browser_login": "available" if browser_login_permitted(spec, profile) else "unavailable",
                    "notes": profile.notes or spec.notes,
                }
            )
        return rows

    def has_active(self, platform: str | None) -> bool:
        if not platform:
            return False
        try:
            return self.store.has_active(platform)
        except ValueError:
            return False

    def allows_browser_login(self, platform: str) -> bool:
        spec = self.spec(platform)
        return browser_login_permitted(spec, self.store.load_profile(spec.slug))

    def _blocked_browser_profile(self, spec: PlatformSpec, status: SessionStatus, detail: str) -> AuthProfile:
        suggestion = official_api_suggestion(spec)
        notes = detail
        if suggestion:
            notes = f"{detail} {suggestion} {ANONYMOUS_LOOKUP_UNAFFECTED}"
        else:
            notes = f"{detail} {ANONYMOUS_LOOKUP_UNAFFECTED}"
        existing = self.store.load_profile(spec.slug)
        profile = existing or new_profile(
            spec.slug,
            status=status,
            storage="file",
            keyring_available=self.store.keyring.available,
        )
        profile.status = status
        profile.notes = notes
        save_profile(self.store.auth_dir, profile)
        return profile

    async def login(
        self,
        platform: str,
        *,
        profile_name: str = "osint-research",
        timeout_s: float = 300,
        keep_open: bool = False,
        browser: str | None = None,
        attach: bool = False,
    ) -> AuthProfile:
        spec = self.spec(platform)
        existing = self.store.load_profile(spec.slug)
        if spec.auth_capability == AuthCapability.UNSUPPORTED:
            return self._blocked_browser_profile(
                spec,
                SessionStatus.UNAVAILABLE,
                "Browser login is unsupported for this platform.",
            )
        if spec.auth_capability == AuthCapability.OFFICIAL_API:
            return self._blocked_browser_profile(
                spec,
                SessionStatus.NOT_CONFIGURED,
                "Playwright session login is not used for this platform.",
            )
        if not browser_login_permitted(spec, existing):
            status = existing.status if existing else SessionStatus.TEMPORARILY_LIMITED
            logger.info(
                "Not retrying browser login for %s (%s)",
                spec.display_name,
                status.value,
            )
            return self._blocked_browser_profile(
                spec,
                status,
                f"{status.value} — SPECTRE will not retry automated browser login.",
            )
        logger.info("Starting manual login for %s (password is never collected)", spec.display_name)
        kind = resolve_browser_kind(spec, browser, self.settings)
        backend = self._backend_for_kind(kind)
        if kind == "chrome":
            profile_dir = ensure_chrome_profile(self.settings, spec.slug)
        else:
            profile_dir = ensure_platform_profile(self.settings, spec.slug)
        outcome = await backend.interactive_login(
            spec,
            timeout_s=timeout_s,
            keep_open=keep_open,
            user_data_dir=profile_dir,
            attach=attach,
        )
        if outcome.status != SessionStatus.ACTIVE or not outcome.storage_state:
            profile = new_profile(
                spec.slug,
                profile_name,
                status=outcome.status,
                storage="file",
                keyring_available=self.store.keyring.available,
            )
            detail = outcome.detail or outcome.status.value
            extra = official_api_suggestion(spec)
            profile.notes = (
                f"{detail} {extra} {ANONYMOUS_LOOKUP_UNAFFECTED}" if extra else f"{detail} {ANONYMOUS_LOOKUP_UNAFFECTED}"
            )
            if outcome.status in TERMINAL_SESSION_STATUSES or outcome.status == SessionStatus.EXPIRED:
                self.store.delete(spec.slug)
                save_profile(self.store.auth_dir, profile)
            return profile
        return self.store.save(
            spec.slug,
            outcome.storage_state,
            profile_name=profile_name,
            status=SessionStatus.ACTIVE,
        )

    async def verify(self, platform: str) -> AuthProfile:
        spec = self.spec(platform)
        state = self.store.load_state(spec.slug)
        profile = self.store.load_profile(spec.slug)
        if state is None or profile is None:
            return AuthProfile(platform=spec.slug, status=SessionStatus.NOT_CONFIGURED)
        backend = self._backend_for_session(spec, state)
        try:
            status = await backend.verify_session(spec, state)
        except Exception as exc:  # noqa: BLE001
            mapped = map_expected_session_failure(exc)
            if mapped is None:
                raise
            logger.warning("Session verify failed for %s: %s", spec.display_name, type(exc).__name__)
            status = mapped
        updated = self.store.update_status(spec.slug, status)
        return updated or profile

    def _backend_for_kind(self, kind: str) -> BrowserBackend:
        if kind == "fake":
            return self.backend
        if kind == "chrome":
            return get_backend("chrome", self.settings)
        if self.settings.browser_backend in {"fake", "test", "mock"}:
            return self.backend
        return get_backend("playwright", self.settings)

    def _backend_for_session(self, spec: PlatformSpec, storage_state: dict | None) -> BrowserBackend:
        if uses_chrome_cdp_session(spec, storage_state):
            if isinstance(self.backend, ChromeCdpBackend):
                return self.backend
            return self._backend_for_kind("chrome")
        return self.backend

    def logout(self, platform: str) -> None:
        spec = self.spec(platform)
        try:
            self.store.delete(spec.slug)
        except (OSError, ValueError, UnicodeError):
            logger.warning("Session store delete skipped for %s", spec.display_name)
        try:
            wipe_platform_profile(self.settings, spec.slug)
        except (OSError, UnicodeError, ValueError):
            logger.warning("Playwright profile wipe failed for %s", spec.display_name)
        try:
            wipe_chrome_profile(self.settings, spec.slug)
        except (OSError, UnicodeError, ValueError):
            logger.warning("Chrome profile wipe failed for %s", spec.display_name)
        logger.info("Local session removed for %s (remote account unchanged)", spec.display_name)

    clear = logout

    async def fetch_public_profile(self, site_name: str, username: str, profile_url: str) -> FetchOutcome | None:
        spec = platform_for_site(site_name)
        if spec is None:
            return None
        if not self.store.has_active(spec.slug):
            return None
        state = self.store.load_state(spec.slug)
        if not state:
            return None
        logger.info(
            "AUTHENTICATED_PUBLIC fetch for %s (public content only)",
            spec.display_name,
        )
        backend = self._backend_for_session(spec, state)
        try:
            return await backend.fetch_public(spec, profile_url, state)
        except Exception as exc:  # noqa: BLE001
            mapped = map_expected_session_failure(exc)
            if mapped is None:
                raise
            logger.warning("Authenticated public fetch failed: %s", type(exc).__name__)
            return FetchOutcome(status=mapped.value, url=profile_url, detail=type(exc).__name__)
