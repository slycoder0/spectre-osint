"""Redact secrets from logs, evidence payloads and reports."""

from __future__ import annotations

import json
import re
from typing import Any

_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "x-apikey",
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "password",
    "passwd",
    "pass",
    "hibp-api-key",
    "x-otx-api-key",
    "key",
    "session",
    "sessionid",
    "csrf",
    "csrftoken",
    "csrf_token",
    "auth_token",
    "bearer",
    "cookies",
    "storage_state",
    "storagestate",
}

_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|authorization|bearer)([\"'\s:=]+)([^\s\"'&,]+)"),
    re.compile(r"(?i)([?&](?:api[_-]?key|key|token|secret|password)=)([^&]+)"),
    re.compile(r"sk-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"gho_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),
    re.compile(r"SPECTRE_CANARY_SECRET_[A-Za-z0-9_\-]+"),
    re.compile(r"(?i)(sessionid|csrftoken|auth_token|access_token|refresh_token)=([^\s;&]+)"),
    re.compile(r"(?i)(cookie|set-cookie)([\"'\s:=]+)([^\s\"']+)"),
]


def mask_secret(value: str, keep: int = 2) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * max(4, len(value) - keep * 2)}{value[-keep:]}"


def _replace_secret(match: re.Match[str]) -> str:
    if match.lastindex and match.lastindex >= 3:
        return f"{match.group(1)}{match.group(2)}{mask_secret(match.group(3))}"
    if match.lastindex and match.lastindex >= 2:
        return f"{match.group(1)}{mask_secret(match.group(2))}"
    return mask_secret(match.group(0))


def redact_text(text: str) -> str:
    redacted = text
    for pattern in _PATTERNS:
        redacted = pattern.sub(_replace_secret, redacted)
    return redacted


def is_sensitive_key(key: str) -> bool:
    lowered = str(key).lower()
    if lowered in _SENSITIVE_KEYS:
        return True
    return any(token in lowered for token in ("password", "secret", "token", "cookie", "bearer", "csrf"))


def strip_auth_material(data: Any) -> Any:
    """Drop auth cookies/tokens entirely. Used by the OSINT result cache."""
    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for key, value in data.items():
            lowered = str(key).lower()
            if lowered in _SENSITIVE_KEYS or "cookie" in lowered or lowered in {
                "authorization",
                "proxy-authorization",
                "storage_state",
                "storagestate",
            }:
                continue
            out[key] = strip_auth_material(value)
        return out
    if isinstance(data, list):
        return [strip_auth_material(item) for item in data]
    if isinstance(data, str):
        return redact_text(data)
    return data


def redact_mapping(data: Any) -> Any:
    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for key, value in data.items():
            if is_sensitive_key(key):
                out[key] = mask_secret(str(value)) if value is not None else value
            else:
                out[key] = redact_mapping(value)
        return out
    if isinstance(data, list):
        return [redact_mapping(item) for item in data]
    if isinstance(data, str):
        return redact_text(data)
    return data


def safe_json(data: Any) -> str:
    return json.dumps(redact_mapping(data), default=str, ensure_ascii=False)
