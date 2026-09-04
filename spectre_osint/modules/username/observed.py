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

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, RootModel, field_serializer

LEGACY_KEYS = ("value", "original", "source", "observed_at")

# Row-level `source` for a list whose items do not share one source string. A single
# source path here would be a false attribution, so the marker says "read `items`".
MULTIPLE_SOURCES = "multiple"


def _iso(value: datetime) -> str:
    """Emit `datetime.isoformat()`, not Pydantic's `Z` form.

    The pre-B2-03A writer used `datetime.now(UTC).isoformat()`, so the offset is
    spelled `+00:00`. Pydantic's own JSON mode would spell it `Z` and silently
    change every timestamp already in `Finding.data["observed"]`.
    """
    return value.isoformat()


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
    # Not an extraction origin. Row-level marker meaning "this list's items reached
    # SPECTRE through more than one method"; `items` is then authoritative.
    MIXED = "MIXED"


class ObservedItem(BaseModel):
    """One member of a list-valued observation, with its own provenance.

    A list field is fed by several extractors — a JSON `twitter_username`, JSON-LD
    `sameAs`, an HTML `rel=me` link — and one row-level `source` cannot describe all
    of them truthfully. Each item records the extractor that actually observed it.

    Two items may share a `value`: the same URL observed through two extractors is
    two observations of one fact. The row's compatibility `value` list stays
    deduplicated; the evidence does not.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    value: str
    original: str
    source: str
    observed_at: AwareDatetime

    provider_slug: str | None = None
    source_method: SourceMethod | None = None
    source_url: str | None = None
    derived_from: str | None = None
    rejected_by: str | None = None

    @field_serializer("observed_at")
    def _serialize_observed_at(self, value: datetime) -> str:
        return _iso(value)

    def to_transport(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)

    @property
    def provenance_key(self) -> tuple[str, str, str | None]:
        """Identity of the observation, not of the value. Used to drop exact repeats."""
        return (self.value, self.source, self.source_method)


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

    # Exact per-member provenance for a list-valued observation. Absent on scalars,
    # and absent on a legacy list row written before this contract existed.
    items: list[ObservedItem] | None = None

    @field_serializer("observed_at")
    def _serialize_observed_at(self, value: datetime) -> str:
        return _iso(value)

    def to_transport(self) -> dict[str, Any]:
        """Serialize to the JSON mapping stored in `Finding.data["observed"]`."""
        return self.model_dump(mode="json", exclude_none=True)

    @classmethod
    def from_items(cls, items: list[ObservedItem]) -> ObservedField:
        """Build a list-valued observation whose row metadata cannot lie.

        The compatibility `value` list is the items' values in first-seen order,
        deduplicated. Row-level metadata collapses to a shared value only when every
        item agrees; otherwise `source` becomes MULTIPLE_SOURCES, `source_method`
        becomes SourceMethod.MIXED, and the remaining keys are dropped rather than
        guessed. `items` stays authoritative either way.
        """
        if not items:
            raise ValueError("a list observation needs at least one item")
        values: list[str] = []
        originals: list[str] = []
        for item in items:
            if item.value not in values:
                values.append(item.value)
                originals.append(item.original)
        sources = {item.source for item in items}
        methods = {item.source_method for item in items}
        return cls(
            value=values,
            original=originals,
            source=sources.pop() if len(sources) == 1 else MULTIPLE_SOURCES,
            # The row is "as of" its most recent observation; each item keeps its own.
            observed_at=max(item.observed_at for item in items),
            provider_slug=_shared(item.provider_slug for item in items),
            source_method=methods.pop() if len(methods) == 1 else SourceMethod.MIXED,
            source_url=_shared(item.source_url for item in items),
            derived_from=_shared(item.derived_from for item in items),
            items=items,
        )


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
            item = _coerce_stamp(item)
            members = item.get("items")
            if isinstance(members, list):
                item["items"] = [
                    _coerce_stamp(entry) if isinstance(entry, dict) else entry for entry in members
                ]
        coerced[str(name)] = item
    return ObservedFields.model_validate(coerced)


def _coerce_stamp(row: dict[str, Any]) -> dict[str, Any]:
    """Copy a row with a naive `observed_at` read as UTC. Anything else untouched."""
    out = dict(row)
    stamp = out.get("observed_at")
    if isinstance(stamp, str) and stamp:
        out["observed_at"] = _as_aware(stamp)
    elif isinstance(stamp, datetime) and stamp.tzinfo is None:
        out["observed_at"] = stamp.replace(tzinfo=UTC)
    return out


def _shared(values: Iterable[Any]) -> Any:
    """The one value every item agrees on, or None when they disagree."""
    distinct = set(values)
    return distinct.pop() if len(distinct) == 1 else None


def _as_aware(stamp: str) -> str | datetime:
    """Attach UTC to a naive legacy timestamp; leave anything else untouched."""
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        return stamp
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return stamp
