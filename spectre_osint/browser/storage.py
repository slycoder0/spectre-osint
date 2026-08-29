"""Secret file permissions and optional keyring wrapping.

Never prints cookie values. Never stores passwords.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from spectre_osint.core.logger import get_logger
from spectre_osint.core.redaction import redact_text

logger = get_logger("spectre.auth.storage")

SERVICE = "spectre-osint"


def ensure_secret_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        logger.warning("Could not set 0700 on %s", path)
    return path


def write_secret_file(path: Path, payload: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def read_secret_file(path: Path) -> str | None:
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def remove_secret_file(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        logger.warning("Could not remove %s", redact_text(str(path)))


class KeyringStore:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.available = False
        self.backend_warning: str | None = None
        self._impl: Any | None = None
        if not enabled:
            self.backend_warning = "System keyring disabled (SPECTRE_KEYRING=false). Sessions use 0600 files."
            return
        try:
            import keyring

            self._impl = keyring
            keyring.get_keyring()
            self.available = True
        except Exception as exc:  # noqa: BLE001
            self.backend_warning = (
                f"System keyring unavailable ({exc}). Sessions use restricted files (mode 0600)."
            )
            logger.warning("%s", self.backend_warning)

    def set(self, platform: str, profile_name: str, payload: str) -> bool:
        if not self.available or self._impl is None:
            return False
        try:
            self._impl.set_password(SERVICE, f"{platform}:{profile_name}", payload)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("keyring set failed: %s", type(exc).__name__)
            return False

    def get(self, platform: str, profile_name: str) -> str | None:
        if not self.available or self._impl is None:
            return None
        try:
            return self._impl.get_password(SERVICE, f"{platform}:{profile_name}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("keyring get failed: %s", type(exc).__name__)
            return None

    def delete(self, platform: str, profile_name: str) -> None:
        if not self.available or self._impl is None:
            return
        try:
            self._impl.delete_password(SERVICE, f"{platform}:{profile_name}")
        except Exception:
            return


def dump_storage_state(state: dict[str, Any]) -> str:
    return json.dumps(state, ensure_ascii=False)


def load_storage_state(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None
