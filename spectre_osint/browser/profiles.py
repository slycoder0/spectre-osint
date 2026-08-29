"""AuthProfile persistence (metadata only — no cookies, no passwords)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from spectre_osint.browser.models import AuthProfile
from spectre_osint.browser.storage import ensure_secret_dir, read_secret_file, write_secret_file
from spectre_osint.core.types import AccessMode, SessionStatus


def profile_path(auth_dir: Path, platform: str) -> Path:
    return ensure_secret_dir(auth_dir / platform) / "profile.json"


def load_profile(auth_dir: Path, platform: str) -> AuthProfile | None:
    raw = read_secret_file(profile_path(auth_dir, platform))
    if not raw:
        return None
    try:
        return AuthProfile.model_validate_json(raw)
    except Exception:
        return None


def save_profile(auth_dir: Path, profile: AuthProfile) -> None:
    write_secret_file(
        profile_path(auth_dir, profile.platform),
        profile.model_dump_json(indent=2),
    )


def new_profile(
    platform: str,
    profile_name: str = "osint-research",
    *,
    status: SessionStatus = SessionStatus.ACTIVE,
    storage: str = "file",
    keyring_available: bool = False,
) -> AuthProfile:
    now = datetime.now(UTC)
    return AuthProfile(
        platform=platform,
        profile_name=profile_name,
        status=status,
        created_at=now,
        last_verified=now if status == SessionStatus.ACTIVE else None,
        expires_at=None,
        access_mode=AccessMode.AUTHENTICATED_PUBLIC,
        storage=storage,
        keyring_available=keyring_available,
        notes="Password is never stored. Public content only. Manual login in SPECTRE browser.",
    )
