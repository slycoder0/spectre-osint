"""Validated contract for one observed public-profile attribute.

OBSERVED PROFILE ATTRIBUTE != VERIFIED CIVIL ATTRIBUTE.

A row here records that a public page or API *stated* something about a handle at a
point in time, and where that statement came from. It does not assert the statement
is true, and it does not identify a natural person. Correlation and reporting stay
responsible for enforcing that distinction; this module only models it.

`Finding.data["observed"]` remains the serialized transport: a plain JSON mapping of
field name -> observation. This module validates what enrichment produces before it
is written there. The dictionary key *is* the field identity, so no field name is
repeated inside the observation itself.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, RootModel, field_serializer

LEGACY_KEYS = ("value", "original", "source", "observed_at")


class SourceMethod(StrEnum):
    """How an observation reached SPECTRE. Spellings follow existing conventions.

    JSON_API matches the catalog's `json_api` detection strategy;
    AUTHENTICATED_PUBLIC matches `AccessMode.AUTHENTICATED_PUBLIC` and, like it,
    means public data read through a logged-in session — never private access.
    DERIVED matches the discovery-novelty vocabulary in `search/novelty.py`.
    """

    INPUT = "INPUT"
    JSON_API = "JSON_API"
    HTML = "HTML"
    AUTHENTICATED_PUBLIC = "AUTHENTICATED_PUBLIC"
    DERIVED = "DERIVED"


class ObservedField(BaseModel):
    """One observed attribute plus its provenance.

    The first four fields are the pre-B2-03A shape and stay required. The rest are
    additive metadata: `None` means "not known", is excluded from the serialized
    transport, and never appears as an empty string.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    value: str | list[str]
    original: str | list[str]
    source: str
    observed_at: AwareDatetime

    provider_slug: str | None = None
    source_method: SourceMethod | None = None
    source_url: str | None = None
    derived_from: str | None = None
    # Forward compatibility for B2-03B. B2-03A never emits it: rejection semantics
    # are unchanged, and a rejected value is still simply omitted.
    rejected_by: str | None = None

    @field_serializer("observed_at")
    def _serialize_observed_at(self, value: datetime) -> str:
        """Emit `datetime.isoformat()`, not Pydantic's `Z` form.

        The pre-B2-03A writer used `datetime.now(UTC).isoformat()`, so the offset is
        spelled `+00:00`. Pydantic's own JSON mode would spell it `Z` and silently
        change every timestamp already in `Finding.data["observed"]`.
        """
        return value.isoformat()

    def to_transport(self) -> dict[str, Any]:
        """Serialize to the JSON mapping stored in `Finding.data["observed"]`."""
        return self.model_dump(mode="json", exclude_none=True)


class ObservedFields(RootModel[dict[str, ObservedField]]):
    """`field name -> ObservedField`, the shape of `Finding.data["observed"]`."""

    root: dict[str, ObservedField]

    def to_transport(self) -> dict[str, dict[str, Any]]:
        return {name: field.to_transport() for name, field in self.root.items()}

    def __getitem__(self, key: str) -> ObservedField:
        return self.root[key]

    def __contains__(self, key: str) -> bool:
        return key in self.root

    def __len__(self) -> int:
        return len(self.root)


def parse_observed(raw: Any) -> ObservedFields:
    """Validate a serialized `observed` mapping, including pre-B2-03A rows.

    A legacy row carries only `value`, `original`, `source` and `observed_at`; the
    additive keys are optional, so it validates unchanged. A naive `observed_at` is
    read as UTC rather than rejected, because rows written before this contract
    existed cannot be re-stamped and must stay readable. Newly built observations go
    through `ObservedField` directly, where an aware timestamp is required.

    This parser is deliberately not wired into any read path in B2-03A: consumers
    still read the plain mapping. B2-03B makes the model authoritative.
    """
    if isinstance(raw, ObservedFields):
        return raw
    if not isinstance(raw, dict):
        raise ValueError(f"observed must be a mapping, got {type(raw).__name__}")
    coerced: dict[str, Any] = {}
    for name, item in raw.items():
        if isinstance(item, dict):
            item = dict(item)
            stamp = item.get("observed_at")
            if isinstance(stamp, str) and stamp:
                item["observed_at"] = _as_aware(stamp)
            elif isinstance(stamp, datetime) and stamp.tzinfo is None:
                item["observed_at"] = stamp.replace(tzinfo=UTC)
        coerced[str(name)] = item
    return ObservedFields.model_validate(coerced)


def _as_aware(stamp: str) -> str | datetime:
    """Attach UTC to a naive legacy timestamp; leave anything else untouched."""
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        return stamp
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return stamp
