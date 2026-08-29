"""Persistent authenticated-public sessions. Outside the git repo. Never in SQLite."""

from __future__ import annotations

from pathlib import Path

from spectre_osint.browser.models import AUTH_PLATFORMS, AuthProfile, normalize_platform
from spectre_osint.browser.profiles import load_profile, new_profile, save_profile
from spectre_osint.browser.storage import (
    KeyringStore,
    dump_storage_state,
    ensure_secret_dir,
    load_storage_state,
    read_secret_file,
    remove_secret_file,
    write_secret_file,
)
from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.types import SessionStatus


class SessionStore:
    def __init__(self, settings: Settings | None = None, auth_dir: Path | None = None) -> None:
        self.settings = settings or get_settings()
        self.auth_dir = ensure_secret_dir(Path(auth_dir or self.settings.resolved_auth_dir))
        self.keyring = KeyringStore(enabled=bool(self.settings.keyring_enabled))

    def platform_dir(self, platform: str) -> Path:
        return ensure_secret_dir(self.auth_dir / normalize_platform(platform))

    def storage_path(self, platform: str) -> Path:
        return self.platform_dir(platform) / "storage_state.json"

    def save(
        self,
        platform: str,
        storage_state: dict,
        *,
        profile_name: str = "osint-research",
        status: SessionStatus = SessionStatus.ACTIVE,
    ) -> AuthProfile:
        slug = normalize_platform(platform)
        blob = dump_storage_state(storage_state)
        used_keyring = self.keyring.set(slug, profile_name, blob)
        if used_keyring:
            remove_secret_file(self.storage_path(slug))
            storage = "keyring"
        else:
            write_secret_file(self.storage_path(slug), blob)
            storage = "file"
        profile = new_profile(
            slug,
            profile_name,
            status=status,
            storage=storage,
            keyring_available=self.keyring.available,
        )
        save_profile(self.auth_dir, profile)
        return profile

    def load_state(self, platform: str, profile_name: str = "osint-research") -> dict | None:
        slug = normalize_platform(platform)
        profile = load_profile(self.auth_dir, slug)
        name = profile.profile_name if profile else profile_name
        raw = self.keyring.get(slug, name)
        if not raw:
            raw = read_secret_file(self.storage_path(slug))
        return load_storage_state(raw)

    def load_profile(self, platform: str) -> AuthProfile | None:
        return load_profile(self.auth_dir, normalize_platform(platform))

    def update_status(self, platform: str, status: SessionStatus) -> AuthProfile | None:
        from datetime import UTC, datetime

        slug = normalize_platform(platform)
        profile = load_profile(self.auth_dir, slug)
        if profile is None:
            return None
        profile.status = status
        if status == SessionStatus.ACTIVE:
            profile.last_verified = datetime.now(UTC)
        save_profile(self.auth_dir, profile)
        return profile

    def delete(self, platform: str) -> bool:
        slug = normalize_platform(platform)
        profile = load_profile(self.auth_dir, slug)
        name = profile.profile_name if profile else "osint-research"
        self.keyring.delete(slug, name)
        remove_secret_file(self.storage_path(slug))
        from spectre_osint.browser.profiles import profile_path

        remove_secret_file(profile_path(self.auth_dir, slug))
        return True

    def list_profiles(self) -> list[AuthProfile]:
        rows: list[AuthProfile] = []
        for slug, spec in AUTH_PLATFORMS.items():
            profile = load_profile(self.auth_dir, slug)
            if profile is None:
                rows.append(
                    AuthProfile(
                        platform=slug,
                        profile_name=spec.display_name,
                        status=SessionStatus.NOT_CONFIGURED,
                    )
                )
            else:
                rows.append(profile)
        return rows

    def has_active(self, platform: str) -> bool:
        try:
            slug = normalize_platform(platform)
        except ValueError:
            return False
        profile = load_profile(self.auth_dir, slug)
        if profile is None or profile.status != SessionStatus.ACTIVE:
            return False
        return self.load_state(slug) is not None
