"""Friendly, translated CLI error messages (Phase 3A).

`error_message(exc)` picks the message by the *type* of the error, never by its text.
`str(exc)` is off limits here as in logs: `SSRFBlocked` names the blocked IP and host,
httpx errors carry the request URL, `ValidationError` carries the input, `OSError`
carries report paths named after the target. When the class says something useful
(`ConnectError`, `ReadTimeout`, `PermissionError`) it is shown through `exc_label`.

Exception messages still reach findings and reports by design; only the terminal (and
the logs) are kept free of them.
"""

from __future__ import annotations

import httpx

from spectre_osint.core.exceptions import (
    AuthError,
    AuthorizationRequired,
    PathSafetyError,
    ProviderNotConfigured,
    ProviderUnavailable,
    RateLimitExceeded,
    SSRFBlocked,
    TlsVerificationError,
    ValidationError,
)
from spectre_osint.core.i18n import t
from spectre_osint.core.redaction import exc_label


def _cause_label(exc: BaseException) -> str:
    """The class of the underlying transport error when there is one (`ConnectError`
    behind a `ProviderUnavailable`), else the error's own class."""
    cause = exc.__cause__
    return exc_label(cause if isinstance(cause, BaseException) else exc)


def error_message(exc: BaseException) -> str:
    """The terminal message for an error that ends a command. Never contains `str(exc)`."""
    if isinstance(exc, SSRFBlocked):
        return t("cli.error.ssrf")
    if isinstance(exc, ValidationError):
        return t("cli.error.validation")
    if isinstance(exc, RateLimitExceeded):
        return t("cli.error.rate_limited")
    if isinstance(exc, TlsVerificationError):
        return t("cli.error.tls")
    if isinstance(exc, ProviderUnavailable):
        return t("cli.error.network", error=_cause_label(exc))
    if isinstance(exc, httpx.HTTPError):
        return t("cli.error.network", error=exc_label(exc))
    if isinstance(exc, ProviderNotConfigured):
        return t("cli.error.not_configured")
    if isinstance(exc, PathSafetyError):
        return t("cli.error.path_safety")
    if isinstance(exc, AuthorizationRequired):
        return t("cli.error.authorization")
    if isinstance(exc, AuthError):
        return t("cli.error.auth", error=exc_label(exc))
    if isinstance(exc, OSError):
        return t("cli.error.filesystem", error=exc_label(exc))
    return t("cli.error.generic", error=exc_label(exc))
