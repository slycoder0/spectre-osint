"""Redact secrets from logs, evidence payloads and reports; keep target data out of logs.

Two separate concerns live here:

- **Secrets** (API keys, cookies, tokens) are masked everywhere: logs, evidence, reports.
- **Target data** (username, e-mail, name, investigated domain / IP / URL, profile URLs,
  pivot values) belongs in reports and the database, never in a log line or warning
  (B2-07). Call sites log what is not identifying — provider slug, HTTP status, counts,
  durations, the exception class (`exc_label`) — and, when lines about one value must be
  correlated, a per-investigation reference (`target_ref` / `host_ref`): a truncated
  HMAC-SHA256 under a random salt that exists only in memory and is replaced when the
  investigation ends (`target_scope`), so it cannot be reversed or matched across
  investigations. As a safety net, the log formatter also replaces the investigation's
  known target values (`register_target_values`) wherever they still stand alone in a
  line — never inside a longer word, and never a word of the log's own vocabulary
  (`core/log_vocabulary.py`). `tests/test_logs_no_target_data.py` is the guard.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any
from urllib.parse import quote, quote_plus, urlparse

logger = logging.getLogger("spectre.redaction")

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

_REF_HEX = 8
# Hard cap on the forms one investigation can register (a value has ~10 forms; a username
# run with every lead and a domain run with the pivot budget stay far below it). Past the
# cap later values are not scrubbed and one warning says so: the regex is rebuilt on every
# registration and runs on every log line, so it must stay small.
MAX_SCOPE_FORMS = 256
# The safety net only registers forms at least this long: a short value ("git", "user",
# "error") is a word of every other log line, and replacing it would destroy the log
# while the call-site rule is what actually keeps it out. The full e-mail always counts.
MIN_SCRUB_LENGTH = 6
# An e-mail's local part and domain are registered on their own only from this length:
# "info@gmail.com" must not turn "information" or "AUTHENTICATED" into references.
MIN_EMAIL_PART_LENGTH = 8
# A form is replaced only where it stands alone: not inside a longer word, identifier or
# class name (`ReadTimeout`, `username_in_final_url`). A percent-escape (`%22`, `%2F`)
# before it counts as a delimiter, so URL-encoded query strings are still covered.
_BEFORE = r"(?:(?<![A-Za-z0-9_])|(?<=%[0-9A-Fa-f]{2}))"
_AFTER = r"(?![A-Za-z0-9_])"


def exc_label(exc: object) -> str:
    """What a log line may say about an error: the exception's class name, nothing else.

    `str(exc)` is off limits in logs: httpx errors carry the request URL (and so the
    username or investigated host), pydantic `ValidationError` carries `input_value`,
    `OSError` carries report paths named after the target.
    """
    return type(exc).__name__


def target_ref(value: object, *, kind: str = "t") -> str:
    """A short, non-reversible reference for correlating log lines within one investigation.

    `t:` marks a target value, `h:` a host. The same text gets the same digest under
    both prefixes, so a host can be seen to be "the target" without being named. The
    digest is an HMAC under the current `target_scope()`'s random salt, so the same value
    gets a different reference in the next investigation, even in the same process.
    """
    text = str(value or "").strip().casefold()
    if not text:
        return "-"
    return _current_scope().ref(text, kind)


def host_ref(url_or_host: object) -> str:
    """`target_ref` of a URL's host (or of a bare host). The host may *be* the target."""
    text = str(url_or_host or "").strip()
    if "://" in text:
        host = urlparse(text).hostname or ""
    else:
        authority = text.split("/", 1)[0].rsplit("@", 1)[-1]
        host = _ip_text(authority.strip("[]")) or _ip_text(authority.split("]", 1)[0].lstrip("["))
        if not host:
            host = authority.split(":", 1)[0]  # host:port
    host = _ip_text(host) or host
    return target_ref(host.strip().rstrip(".").lower(), kind="h")


def _ip_text(text: str) -> str:
    """The canonical text of an IP address (`2001:0db8::0001` -> `2001:db8::1`), or ""."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _scrub_forms(value: str, vocabulary: frozenset[str]) -> list[str]:
    """The shapes a target value takes inside a log line (matched case-insensitively).

    Most specific first. A form shorter than the floor, or one that is a word of the
    log's own vocabulary (`core/log_vocabulary.py`), is left out; the full e-mail is not.
    """
    is_email = "@" in value
    if not is_email and len(value) < MIN_SCRUB_LENGTH:
        return []
    candidates = [
        value,
        quote(value, safe=""),
        quote(value),
        quote_plus(value),
        value.replace(" ", ""),
        value.replace(" ", "-"),
        value.replace(" ", "_"),
        value.replace("_", "-"),
        value.replace(".", "-"),
    ]
    email_parts: set[str] = set()
    if is_email:
        local, _, domain = value.rpartition("@")
        email_parts = {local, domain}
        normalized = value.lower().encode("utf-8")
        candidates.append(hashlib.md5(normalized).hexdigest())  # noqa: S324 — gravatar-style identifier
        candidates.append(hashlib.sha256(normalized).hexdigest())
        candidates.extend([local, domain])
    if "://" in value:
        host = urlparse(value).hostname or ""
        if host:
            candidates.append(host)
    try:
        candidates.append(ipaddress.ip_address(value).reverse_pointer)
    except ValueError:
        pass
    forms: list[str] = []
    for form in candidates:
        if not form or form in forms:
            continue
        if is_email and form == value:
            forms.append(form)  # the full e-mail always counts
            continue
        floor = MIN_EMAIL_PART_LENGTH if form in email_parts else MIN_SCRUB_LENGTH
        if len(form) < floor or form.casefold() in vocabulary:
            continue
        forms.append(form)
    return forms


def _compile_forms(forms: Iterable[str]) -> re.Pattern[str] | None:
    alternatives = sorted({variant for form in forms for variant in (form, form.casefold())}, key=len, reverse=True)
    if not alternatives:
        return None
    body = "|".join(re.escape(form) for form in alternatives)
    return re.compile(f"{_BEFORE}(?:{body}){_AFTER}", re.IGNORECASE)


class _TargetScope:
    """One investigation's target values, compiled into one pattern, and its salt."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.salt = secrets.token_bytes(32)
        self._refs: dict[str, str] = {}
        self._forms: list[str] = []
        self._pattern: re.Pattern[str] | None = None
        self._full = False

    @property
    def form_count(self) -> int:
        return len(self._forms)

    def ref(self, folded: str, kind: str) -> str:
        digest = hmac.new(self.salt, folded.encode("utf-8"), hashlib.sha256).hexdigest()[:_REF_HEX]
        return f"{kind}:{digest}"

    def register(self, values: Iterable[object]) -> bool:
        """Add values; True the first time the scope reaches `MAX_SCOPE_FORMS`."""
        from spectre_osint.core.log_vocabulary import log_vocabulary

        vocabulary = log_vocabulary()
        reached_limit = False
        with self._lock:
            changed = False
            for value in values:
                text = str(value or "").strip()
                if not text:
                    continue
                ref = self.ref(text.casefold(), "t")
                for form in _scrub_forms(text, vocabulary):
                    key = form.casefold()
                    if key in self._refs:
                        continue
                    if len(self._forms) >= MAX_SCOPE_FORMS:
                        reached_limit = not self._full
                        self._full = True
                        break
                    self._refs[key] = ref
                    self._forms.append(form)
                    changed = True
            if changed:
                self._pattern = _compile_forms(self._forms)
        return reached_limit

    def scrub(self, text: str) -> str:
        pattern, refs = self._pattern, self._refs
        if pattern is None or not text:
            return text
        return pattern.sub(lambda match: refs.get(match.group(0).casefold(), "t:redacted"), text)

    def close(self) -> None:
        """Forget every value, drop the pattern and replace the salt."""
        with self._lock:
            self._refs = {}
            self._forms = []
            self._pattern = None
            self._full = False
            self.salt = secrets.token_bytes(32)


# The investigation in progress in this context (asyncio tasks and `asyncio.to_thread`
# workers inherit it). Outside any `target_scope()` values go to a process-level scope,
# bounded the same way, so a code path that forgot to open one still scrubs.
_ACTIVE_SCOPE: ContextVar[_TargetScope | None] = ContextVar("spectre_target_scope", default=None)
_PROCESS_SCOPE = _TargetScope()


def _current_scope() -> _TargetScope:
    return _ACTIVE_SCOPE.get() or _PROCESS_SCOPE


@contextmanager
def target_scope() -> Iterator[None]:
    """The lifetime of one investigation's target values in the log safety net.

    `InvestigationRunner.run` (and the active recon) open one; the values registered
    inside, pivots included, are scrubbed from log lines until it closes. On exit the
    values are discarded, the pattern is emptied and the salt is replaced, so the next
    investigation in the same process (the menu runs many) neither scrubs the previous
    target nor shares its references. A scope opened inside another one is the same
    scope: only the outermost discards.
    """
    if _ACTIVE_SCOPE.get() is not None:
        yield
        return
    scope = _TargetScope()
    token = _ACTIVE_SCOPE.set(scope)
    try:
        yield
    finally:
        _ACTIVE_SCOPE.reset(token)
        scope.close()


def register_target_values(*values: object) -> None:
    """Add target values (and their URL-encoded / slug / hashed forms) to the current
    investigation's log safety net. See `target_scope()`."""
    if _current_scope().register(values):
        logger.warning(
            "log safety net full: limit=%s forms; later target values are not scrubbed",
            MAX_SCOPE_FORMS,
        )


def clear_target_values() -> None:
    """Forget every registered value (tests). Scopes do this on exit by themselves."""
    _PROCESS_SCOPE.close()
    active = _ACTIVE_SCOPE.get()
    if active is not None:
        active.close()


def registered_form_count() -> int:
    """How many forms the log safety net holds right now (current scope + process scope)."""
    active = _ACTIVE_SCOPE.get()
    return (active.form_count if active is not None else 0) + _PROCESS_SCOPE.form_count


def scrub_target_values(text: str) -> str:
    """Replace every registered target value in `text` with its `target_ref`."""
    if not text:
        return text
    active = _ACTIVE_SCOPE.get()
    if active is not None:
        text = active.scrub(text)
    return _PROCESS_SCOPE.scrub(text)
