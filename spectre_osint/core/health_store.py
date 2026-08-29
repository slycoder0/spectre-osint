"""Persist last provider health-check timestamps (no secrets)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.redaction import redact_mapping


class HealthStore:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.path = Path(self.settings.data_dir) / "provider_health.json"

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def record(self, name: str, payload: dict[str, Any]) -> None:
        data = self.load()
        row = redact_mapping(payload)
        row["checked_at"] = datetime.now(UTC).isoformat()
        data[name] = row
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def last(self, name: str) -> dict[str, Any] | None:
        row = self.load().get(name)
        return row if isinstance(row, dict) else None
