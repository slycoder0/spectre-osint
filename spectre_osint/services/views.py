"""Language-neutral view models for terminal and menu presentation (B2-06).

A view holds what is *true and countable* about a result; it never holds wording,
colors or layout. The same view feeds the compact renderer, the verbose renderer and
(Phase 3) the menu.

Honesty rules enforced here, not in the renderer:

- only catalog profiles with `CONFIRMED` / `LIKELY` status are "found". Search candidates
  (`discovered_profile`) and public mentions are other modules and are never listed;
- every checked site lands in exactly one of found / not found / unverified, so
  `checked == len(found) + not_found + unverified.total` always holds. A status the
  presentation does not know is *unverified*, never silently dropped;
- observed names are per platform and come only from the validated `observed` channel
  (`read_observed()`), only for found profiles, never from a rejected field, never from
  operator input (`SourceMethod.INPUT`) and never when the name is just the handle.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from spectre_osint.core.entities import InvestigationResult
from spectre_osint.core.presentation import check_status_of, is_username_site_finding, platform_of
from spectre_osint.modules.search.novelty import is_generic_display_name
from spectre_osint.modules.username.observed import SourceMethod, read_observed

FOUND_STATUSES: tuple[str, ...] = ("CONFIRMED", "LIKELY")
NOT_FOUND_STATUS = "NOT_FOUND"

BLOCKED_STATUSES = frozenset(
    {"BLOCKED", "CHALLENGE_REQUIRED", "CAPTCHA_REQUIRED", "OAUTH_BROWSER_REJECTED"}
)
LOGIN_STATUSES = frozenset({"LOGIN_REQUIRED", "SESSION_EXPIRED"})
RATE_LIMIT_STATUSES = frozenset({"RATE_LIMITED", "TEMPORARILY_LIMITED"})

BUCKET_BLOCKED = "blocked"
BUCKET_LOGIN = "login"
BUCKET_RATE_LIMITED = "rate_limited"
BUCKET_INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class FoundProfile:
    platform: str
    url: str
    status: str
    username: str

    @property
    def likely(self) -> bool:
        return self.status == "LIKELY"


@dataclass(frozen=True)
class ObservedName:
    """A display name one platform states for its own profile. Not a civil identity."""

    platform: str
    name: str
    source: str


@dataclass(frozen=True)
class UnverifiedCounts:
    blocked: int = 0
    login: int = 0
    rate_limited: int = 0
    inconclusive: int = 0

    @property
    def total(self) -> int:
        return self.blocked + self.login + self.rate_limited + self.inconclusive

    def buckets(self) -> list[tuple[str, int]]:
        """Non-zero buckets in a fixed display order."""
        pairs = [
            (BUCKET_BLOCKED, self.blocked),
            (BUCKET_LOGIN, self.login),
            (BUCKET_RATE_LIMITED, self.rate_limited),
            (BUCKET_INCONCLUSIVE, self.inconclusive),
        ]
        return [(name, count) for name, count in pairs if count]


@dataclass(frozen=True)
class UsernameView:
    target: str
    checked: int
    found: tuple[FoundProfile, ...]
    names: tuple[ObservedName, ...]
    not_found: int
    unverified: UnverifiedCounts
    report_path: str | None = None


def unverified_bucket(status: str) -> str:
    """Which honesty bucket a non-decisive check status belongs to."""
    if status in BLOCKED_STATUSES:
        return BUCKET_BLOCKED
    if status in LOGIN_STATUSES:
        return BUCKET_LOGIN
    if status in RATE_LIMIT_STATUSES:
        return BUCKET_RATE_LIMITED
    return BUCKET_INCONCLUSIVE


def observed_display_name(
    data: dict[str, Any] | None, *, handle: str, platform: str
) -> ObservedName | None:
    """The active, non-generic display name a profile's observed channel states."""
    field = read_observed(data).active().get("display_name")
    if field is None or field.source_method == SourceMethod.INPUT:
        return None
    value = field.value
    if not isinstance(value, str) or not value.strip():
        return None
    if is_generic_display_name(value, handle, platform=platform):
        return None
    return ObservedName(platform=platform, name=value, source=field.source)


def build_username_view(result: InvestigationResult) -> UsernameView:
    found: list[tuple[FoundProfile, ObservedName | None]] = []
    buckets: Counter[str] = Counter()
    checked = 0
    not_found = 0
    for finding in result.findings:
        if not is_username_site_finding(finding):
            continue
        checked += 1
        status = check_status_of(finding)
        if status == NOT_FOUND_STATUS:
            not_found += 1
            continue
        if status not in FOUND_STATUSES:
            buckets[unverified_bucket(status)] += 1
            continue
        data = finding.data or {}
        platform = platform_of(finding)
        handle = str(data.get("username") or result.target)
        profile = FoundProfile(
            platform=platform,
            url=str(data.get("profile_url") or data.get("final_url") or ""),
            status=status,
            username=handle,
        )
        found.append((profile, observed_display_name(data, handle=handle, platform=platform)))
    found.sort(
        key=lambda pair: (
            FOUND_STATUSES.index(pair[0].status),
            pair[0].platform.casefold(),
            pair[0].username.casefold(),
            pair[0].url,
        )
    )
    return UsernameView(
        target=result.target,
        checked=checked,
        found=tuple(profile for profile, _ in found),
        names=tuple(name for _, name in found if name is not None),
        not_found=not_found,
        unverified=UnverifiedCounts(
            blocked=buckets[BUCKET_BLOCKED],
            login=buckets[BUCKET_LOGIN],
            rate_limited=buckets[BUCKET_RATE_LIMITED],
            inconclusive=buckets[BUCKET_INCONCLUSIVE],
        ),
        report_path=result.report_path,
    )
