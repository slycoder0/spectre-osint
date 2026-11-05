"""Redact secrets from logs, evidence payloads and reports; keep target data out of logs.

Two separate concerns live here:

- **Secrets** (API keys, cookies, tokens) are masked everywhere: logs, evidence, reports.
- **Target data** (username, e-mail, name, investigated domain / IP / URL, profile URLs,
  pivot values) belongs in reports and the database, never in a log line or warning
  (B2-07). Call sites log what is not identifying — provider slug, HTTP status, counts,
  durations, the exception class (`exc_label`) — and, when lines about one value must be
  correlated, a per-run reference (`target_ref` / `host_ref`): a truncated HMAC-SHA256
  under a random salt that exists only in this process's memory, so it cannot be
  reversed or matched across runs. As a safety net, the log formatter also replaces the
  run's known target values (`register_target_values`) wherever they still appear.
  `tests/test_logs_no_target_data.py` is the guard.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote, quote_plus, urlparse

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


# --- target data in logs (B2-07) -------------------------------------------------------------

# Random per process, never written anywhere: references cannot be reversed by guessing
# candidate values, and the same value gets a different reference in the next run.
_RUN_SALT = secrets.token_bytes(32)
_REF_HEX = 8
# Shorter values are not scrubbed: replacing every "jo" or "ab" in a log line would
# destroy it, and a one- or two-character value identifies no one on its own.
MIN_SCRUB_LENGTH = 3


def exc_label(exc: object) -> str:
    """What a log line may say about an error: the exception's class name, nothing else.

    `str(exc)` is off limits in logs: httpx errors carry the request URL (and so the
    username or investigated host), pydantic `ValidationError` carries `input_value`,
    `OSError` carries report paths named after the target.
    """
    return type(exc).__name__


def target_ref(value: object, *, kind: str = "t") -> str:
    """A short, non-reversible reference for correlating log lines within one run.

    `t:` marks a target value, `h:` a host. The same text gets the same digest under
    both prefixes, so a host can be seen to be "the target" without being named.
    """
    text = str(value or "").strip().casefold()
    if not text:
        return "-"
    digest = hmac.new(_RUN_SALT, text.encode("utf-8"), hashlib.sha256).hexdigest()[:_REF_HEX]
    return f"{kind}:{digest}"


def host_ref(url_or_host: object) -> str:
    """`target_ref` of a URL's host (or of a bare host). The host may *be* the target."""
    text = str(url_or_host or "").strip()
    if "://" in text:
        host = urlparse(text).hostname or ""
    else:
        host = text.split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
    return target_ref(host.strip().rstrip(".").lower(), kind="h")


def _scrub_forms(value: str) -> set[str]:
    """The shapes a target value takes inside a log line (matched case-insensitively)."""
    forms = {
        value,
        quote(value, safe=""),
        quote(value),
        quote_plus(value),
        value.replace(" ", ""),
        value.replace(" ", "-"),
        value.replace(" ", "_"),
        value.replace("_", "-"),
        value.replace(".", "-"),
    }
    if "@" in value:
        local, _, domain = value.rpartition("@")
        forms.update({local, domain})
        normalized = value.lower().encode("utf-8")
        forms.add(hashlib.md5(normalized).hexdigest())  # noqa: S324 — gravatar-style identifier
        forms.add(hashlib.sha256(normalized).hexdigest())
    if "://" in value:
        host = urlparse(value).hostname or ""
        if host:
            forms.add(host)
    try:
        forms.add(ipaddress.ip_address(value).reverse_pointer)
    except ValueError:
        pass
    return {form for form in forms if len(form) >= MIN_SCRUB_LENGTH}


class _TargetScrubber:
    """The process-wide set of known target values, compiled into one pattern."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._refs: dict[str, str] = {}
        self._pattern: re.Pattern[str] | None = None

    def register(self, values: Iterable[object]) -> None:
        with self._lock:
            changed = False
            for value in values:
                text = str(value or "").strip()
                if len(text) < MIN_SCRUB_LENGTH:
                    continue
                ref = target_ref(text)
                for form in _scrub_forms(text):
                    key = form.casefold()
                    if key not in self._refs:
                        self._refs[key] = ref
                        changed = True
            if changed:
                ordered = sorted(self._refs, key=len, reverse=True)
                self._pattern = re.compile("|".join(re.escape(form) for form in ordered), re.IGNORECASE)

    def clear(self) -> None:
        with self._lock:
            self._refs = {}
            self._pattern = None

    def scrub(self, text: str) -> str:
        pattern, refs = self._pattern, self._refs
        if pattern is None or not text:
            return text
        return pattern.sub(lambda match: refs.get(match.group(0).casefold(), "t:redacted"), text)


_SCRUBBER = _TargetScrubber()


def register_target_values(*values: object) -> None:
    """Add this run's target values (and their URL-encoded / slug / hashed forms) to the
    log safety net. Kept for the life of the process: more scrubbing, never less."""
    _SCRUBBER.register(values)


def clear_target_values() -> None:
    _SCRUBBER.clear()


def scrub_target_values(text: str) -> str:
    """Replace every registered target value in `text` with its `target_ref`."""
    return _SCRUBBER.scrub(text)
