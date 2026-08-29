"""SPECTRE-owned Chromium profile directories.

Never points at the operator's real Chrome/Edge profile. Never extracts
cookies from a personal browser. Logout wipes only the SPECTRE tree.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from spectre_osint.browser.models import AUTH_PLATFORMS, normalize_platform
from spectre_osint.browser.storage import ensure_secret_dir
from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.exceptions import PathSafetyError
from spectre_osint.core.logger import get_logger

logger = get_logger("spectre.browser.userdata")

MARKER_NAME = ".spectre-owned"
MARKER_TEXT = "SPECTRE OSINT persistent Chromium profile. Not a personal browser.\n"

_FORBIDDEN_FRAGMENTS = (
    "google/chrome",
    "google-chrome",
    "google chrome",
    "microsoft/edge",
    "microsoft edge",
    "bravesoftware",
    ".config/google-chrome",
    "application support/google/chrome",
    "application support/microsoft edge",
    "chromium/default user data",
)


def platform_profile_dir(settings: Settings | None, platform: str) -> Path:
    cfg = settings or get_settings()
    slug = normalize_platform(platform)
    return (cfg.resolved_browser_profiles_dir / slug).expanduser()


def assert_spectre_owned_profile(path: Path, root: Path) -> Path:
    resolved = path.expanduser().resolve()
    root_resolved = root.expanduser().resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise PathSafetyError(
            f"browser profile escaped SPECTRE profile root: {resolved}"
        ) from exc
    lowered = str(resolved).lower().replace("\\", "/")
    for fragment in _FORBIDDEN_FRAGMENTS:
        if fragment in lowered:
            raise PathSafetyError("Refusing to use a personal browser profile directory")
    name = resolved.name.lower()
    if name not in AUTH_PLATFORMS and resolved != root_resolved:
        # Allow the root itself; platform dirs must be known slugs.
        if resolved.parent.resolve() == root_resolved:
            raise PathSafetyError(f"Unknown SPECTRE browser profile platform dir: {resolved.name}")
    return resolved


def ensure_platform_profile(settings: Settings | None, platform: str) -> Path:
    cfg = settings or get_settings()
    root = ensure_secret_dir(cfg.resolved_browser_profiles_dir)
    target = assert_spectre_owned_profile(platform_profile_dir(cfg, platform), root)
    ensure_secret_dir(target)
    marker = target / MARKER_NAME
    if not marker.exists():
        try:
            marker.write_text(MARKER_TEXT, encoding="utf-8")
            os.chmod(marker, 0o600)
        except OSError:
            logger.warning("Could not write SPECTRE profile marker")
    try:
        os.chmod(target, 0o700)
        os.chmod(root, 0o700)
    except OSError:
        logger.warning("Could not set 0700 on SPECTRE browser profile dir")
    return target


def wipe_platform_profile(settings: Settings | None, platform: str) -> bool:
    """Delete the SPECTRE Chromium profile. Idempotent. Personal Chrome untouched."""
    try:
        cfg = settings or get_settings()
        root = cfg.resolved_browser_profiles_dir.expanduser().resolve()
        target = assert_spectre_owned_profile(platform_profile_dir(cfg, platform), root)
        if not target.exists():
            return False
        shutil.rmtree(target)
        logger.info("Removed SPECTRE browser profile for %s (personal Chrome untouched)", platform)
        return True
    except (OSError, PathSafetyError, UnicodeError, ValueError):
        logger.warning("Playwright profile wipe skipped for %s", platform)
        return False
