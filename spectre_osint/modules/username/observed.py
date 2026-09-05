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

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from typing import Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    RootModel,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)

LEGACY_KEYS = ("value", "original", "source", "observed_at")

# Row-level `source` for a list whose items do not share one source string. A single
# source path here would be a false attribution, so the marker says "read `items`".
# Row-level *only*: it names no extractor, so an ObservedItem may not claim it, exactly
# as SourceMethod.MIXED names no acquisition method. Reserved as this exact string; any
# other source containing the word is an ordinary extractor path.
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
    # Not an extraction origin, and therefore not valid on an ObservedItem. Row-level
    # marker meaning "this list's items reached SPECTRE through more than one method";
    # `items` is then authoritative. See EXTRACTION_METHODS.
    MIXED = "MIXED"


# The methods an individual observation can actually have been acquired through. MIXED
# is deliberately absent: an item claiming it would be an authoritative record with no
# real acquisition method, and a row claiming it would point at nothing.
EXTRACTION_METHODS = frozenset(
    {
        SourceMethod.INPUT,
        SourceMethod.JSON_API,
        SourceMethod.HTML,
        SourceMethod.AUTHENTICATED_PUBLIC,
        SourceMethod.DERIVED,
    }
)


def _check_acquisition_metadata(
    source_method: SourceMethod | None,
    source_url: str | None,
    derived_from: str | None,
    *,
    origin_deferred_to_items: bool = False,
) -> None:
    """How an observation was acquired constrains what else it may claim.

    These keys are independently typed, so nothing but a cross-field rule stops a
    serialized observation from carrying provenance it cannot have. One shared
    implementation for both models, because the contradictions are the same at either
    level. `None` still means "not known" everywhere it is allowed.

    INPUT is operator input, so there is no URL it could have been read from; any
    present `source_url` is refused, an empty string included, because a blank URL is
    not weaker provenance, it is provenance this observation cannot have.

    DERIVED and `derived_from` are two halves of one statement: a derived observation
    must name what it was derived from, and only a derived observation may name it.
    The token itself is not interpreted — no origin vocabulary is hardcoded here — but
    it must say something: a present origin that is empty or only whitespace names no
    field. Such a token is refused, never trimmed, and an accepted one is never
    rewritten — this contract validates provenance, it does not edit it.

    `origin_deferred_to_items` is the single exception, and only an item-backed
    aggregate row may claim it. When every item is DERIVED but they name different
    origins there is no shared row-level origin to state, and `items` already carries
    each one exactly. The caller must prove that from the items themselves — see
    `ObservedField._derivation_origin_is_deferred_to_items()`. A *missing* origin stays
    refused everywhere else; a *blank* one stays refused everywhere.
    """
    if source_method == SourceMethod.INPUT and source_url is not None:
        raise ValueError(
            "INPUT is operator input, not a network read, so it cannot name a source_url"
        )
    if source_method == SourceMethod.DERIVED:
        if derived_from is None:
            if not origin_deferred_to_items:
                raise ValueError(
                    "a DERIVED observation must name the field it was derived from"
                )
        elif not derived_from.strip():
            raise ValueError(
                "a DERIVED observation must name the field it was derived from; a blank "
                "origin names nothing"
            )
    elif derived_from is not None:
        named = source_method.value if source_method is not None else "an unknown method"
        raise ValueError(
            f"derived_from belongs to a DERIVED observation; {named} did not derive it"
        )


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
    # No `rejected_by`: rejection is field-level metadata on ObservedField. An item
    # carrying it would describe a state this contract does not define, and would let a
    # row present that item as accepted in the compatibility `value` list while the
    # item's own provenance said otherwise. `extra="forbid"` refuses it.

    @field_validator("source")
    @classmethod
    def _reject_row_only_source_marker(cls, value: str) -> str:
        """MULTIPLE_SOURCES is an aggregation marker, and an item aggregates nothing.

        The row-level marker means "no single source string describes all members, read
        `items`". An item *is* one of those members, so claiming it would be an
        authoritative record naming no extractor — the same contradiction
        `_reject_row_only_marker` refuses for SourceMethod.MIXED one field over. Left
        unchecked, a single item claiming it also made `project_items()` report a row
        `source` of "multiple" with no extractor heterogeneity proven at all.

        Only the exact reserved string participates: `"multiple_source_test"` and any
        other path containing the word stay valid, and no other source string is
        constrained.
        """
        if value == MULTIPLE_SOURCES:
            raise ValueError(
                f"{MULTIPLE_SOURCES!r} is a row-level aggregation marker, not an "
                "extractor; an item must name the extractor that observed it"
            )
        return value

    @field_validator("source_method")
    @classmethod
    def _reject_row_only_marker(cls, value: SourceMethod | None) -> SourceMethod | None:
        if value is not None and value not in EXTRACTION_METHODS:
            raise ValueError(
                f"{value.value} is a row-level marker, not an acquisition method; "
                "an item must name how it was actually observed"
            )
        return value

    @model_validator(mode="after")
    def _acquisition_metadata_must_agree(self) -> ObservedItem:
        """An INPUT item was read from no page, and only a DERIVED one was derived."""
        _check_acquisition_metadata(self.source_method, self.source_url, self.derived_from)
        return self

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
    # Field-level rejection metadata, and forward compatibility for B2-03B. It
    # describes the field, never an individual item, so ObservedItem has no such key.
    # B2-03A never emits it: rejection semantics are unchanged, and a rejected value is
    # still simply omitted.
    rejected_by: str | None = None

    # Exact per-member provenance for a list-valued observation. Absent on scalars,
    # and absent on a legacy list row written before this contract existed.
    items: list[ObservedItem] | None = None

    @field_serializer("observed_at")
    def _serialize_observed_at(self, value: datetime) -> str:
        return _iso(value)

    @model_validator(mode="after")
    def _value_and_original_share_one_shape(self) -> ObservedField:
        """An observation is scalar or list-valued, in both `value` and `original`.

        The two unions are validated independently, so without this a row could pair a
        scalar `value` with a one-element `original` list, or the reverse. Neither is a
        shape enrichment emits, and a consumer could not tell which original belongs to
        which normalized value. A legacy row is unaffected in either shape: the rule is
        only that the two agree.

        Agreeing on the shape is not enough for two lists. `["a", "b"]` beside
        `["raw-a"]` is the same unreadable pairing one level down — the second value has
        no original, or the first original belongs to nobody — so the two lists must
        also be the same length. `project_items()` appends to both in one step and
        already satisfies this; the rule closes the serialized door.

        Nothing here compares *contents*: `original` is the raw observed text and need
        not equal `value`, order is untouched, and no normalization or deduplication is
        added. A legacy list row stays valid whenever its own two lists pair up.
        """
        if isinstance(self.value, list) != isinstance(self.original, list):
            raise ValueError(
                "value and original must both be scalar or both be lists; got value "
                f"{type(self.value).__name__} with original {type(self.original).__name__}"
            )
        if isinstance(self.value, list) and isinstance(self.original, list):
            if len(self.value) != len(self.original):
                raise ValueError(
                    "value and original must pair up one to one; value has "
                    f"{len(self.value)} entries, original has {len(self.original)}"
                )
        return self

    def to_transport(self) -> dict[str, Any]:
        """Serialize to the JSON mapping stored in `Finding.data["observed"]`."""
        return self.model_dump(mode="json", exclude_none=True)

    @classmethod
    def from_items(cls, items: list[ObservedItem]) -> ObservedField:
        """Build a list-valued observation whose row metadata cannot lie.

        The compatibility `value` list is the items' values in first-seen order,
        deduplicated. Row-level metadata collapses to a shared value only when every
        item agrees; otherwise `source` becomes MULTIPLE_SOURCES, `source_method`
        becomes SourceMethod.MIXED when the items prove several known methods, and the
        remaining keys are dropped rather than guessed. An unknown item method leaves
        the row's method unknown too. `items` stays authoritative either way — including
        for a list whose items all derive from different fields, where the row keeps
        DERIVED and drops `derived_from` rather than naming one item's origin for all.
        """
        return cls(**project_items(items), items=items)

    @model_validator(mode="after")
    def _row_must_not_contradict_its_items(self) -> ObservedField:
        """A row carrying `items` must equal the projection those items produce.

        Without this, a serialized row could pass validation while claiming a value or
        a source its items never observed, and `flatten_observed()` / presentation
        would then read different evidence from consumers that treat `items` as
        authoritative. A legacy list row has no `items` and is unaffected;
        `rejected_by` describes the field rather than the items, so it is not part of
        the projection.

        Every key is compared literally except `observed_at`, which is compared as an
        instant — see `_agrees_with_projection()`. Two offsets naming one moment are
        the same provenance; two identical wall clocks naming two moments are not.

        A row without `items` may also not use either marker that exists to point at
        them: MIXED for acquisition-method heterogeneity, MULTIPLE_SOURCES for
        extractor heterogeneity. With no items, both point at nothing.
        """
        if self.items is None:
            if self.source_method is not None and self.source_method not in EXTRACTION_METHODS:
                raise ValueError(
                    f"{self.source_method.value} needs items to point at; a row without "
                    "them must name how it was actually observed"
                )
            if self.source == MULTIPLE_SOURCES:
                raise ValueError(
                    f"{MULTIPLE_SOURCES!r} says the real sources are in items; a row "
                    "without them must name the extractor that observed it"
                )
            return self
        expected = project_items(self.items)
        mismatched = [
            name
            for name, value in expected.items()
            if not _agrees_with_projection(name, getattr(self, name), value)
        ]
        if mismatched:
            raise ValueError(
                "row contradicts its items on " + ", ".join(sorted(mismatched))
            )
        return self

    def _derivation_origin_is_deferred_to_items(self) -> bool:
        """Do this row's own items prove DERIVED while disagreeing on the origin?

        Derived from `items` through `project_items()` — the same single source of truth
        `_row_must_not_contradict_its_items()` uses — rather than trusting that
        validator to have run first. Pydantic runs `mode="after"` validators in
        definition order, so in practice it has; the exception must still justify itself
        from the items instead of depending on that, because an ordering change would
        otherwise silently turn it into a way to omit a DERIVED origin. A row may drop
        the origin only when the projection of its own items drops it too, and
        `_row_must_not_contradict_its_items()` independently pins every other key.
        """
        if not self.items:
            return False
        projected = project_items(self.items)
        return (
            projected["source_method"] == SourceMethod.DERIVED
            and projected["derived_from"] is None
        )

    @model_validator(mode="after")
    def _acquisition_metadata_must_agree(self) -> ObservedField:
        """The same invariants at the row level, on the row's own projected metadata.

        One row-level relaxation: an aggregate whose items all derive from *different*
        fields keeps `source_method=DERIVED` — every item proves it, so the row is
        truthful — while omitting `derived_from`, because no single origin describes the
        list and `items` holds each exact one. A scalar or item-less DERIVED row has
        nowhere to defer to and must still name its origin.
        """
        _check_acquisition_metadata(
            self.source_method,
            self.source_url,
            self.derived_from,
            origin_deferred_to_items=self._derivation_origin_is_deferred_to_items(),
        )
        return self


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

    Every `observed_at` string, on the row and on each item, is read once by
    `datetime.fromisoformat()` before Pydantic sees it — see `_as_aware()`. That makes
    the parser total over the offsets this contract's own serializer can emit, without
    normalizing any of them to UTC. A string the standard library cannot read is passed
    through unchanged and still fails validation.

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
    """Copy a row with its `observed_at` read once by the standard library.

    A naive stamp — string or `datetime` — is read as UTC, the pre-B2-03A
    compatibility rule. An aware ISO string is replaced by the `datetime` it names so
    that Pydantic validates an object rather than re-parsing a spelling it may refuse;
    see `_as_aware()`. The instant and the offset are untouched either way, and a
    non-string, non-datetime value is passed through for Pydantic to reject.
    """
    out = dict(row)
    stamp = out.get("observed_at")
    if isinstance(stamp, str) and stamp:
        out["observed_at"] = _as_aware(stamp)
    elif isinstance(stamp, datetime) and stamp.tzinfo is None:
        out["observed_at"] = stamp.replace(tzinfo=UTC)
    return out


OBSERVED_KEY = "observed"

# The semantic shape each known profile field carries. `ObservedField.value` is
# deliberately generic — the B2-03A model serves scalars and lists alike — but a consumer
# knows what a display name looks like, and a field of the wrong shape is suppressed
# rather than coerced: `["Alice"]` must never reach evidence as the string "['Alice']",
# and a scalar `social_links` must not become a link just because it can be wrapped in a
# list. Names in neither set are unconstrained; forward compatibility for observed field
# names is not this milestone's business to forbid.
SCALAR_OBSERVED_FIELDS = frozenset(
    {
        "display_name",
        "username",
        "bio",
        "location",
        "organization",
        "website",
        "personal_domain",
        "public_email",
        "avatar_url",
        "public_id",
    }
)
LIST_OBSERVED_FIELDS = frozenset({"external_links", "social_links"})


def _is_active(name: str, value: Any, rejected_by: Any) -> bool:
    """Whether one observed field may act as evidence. The single rule, one place.

    `rejected_by is not None` — never truthiness. A model-valid but odd empty rejection
    token still names a rejection, and reading it as falsy would turn *rejected* into
    *accepted* by accident. A REJECTED VALUE STAYS REJECTED.
    """
    if rejected_by is not None:
        return False
    if name in SCALAR_OBSERVED_FIELDS:
        return not isinstance(value, list)
    if name in LIST_OBSERVED_FIELDS:
        return isinstance(value, list)
    return True


def field_is_active(name: str, field: ObservedField) -> bool:
    """Whether a validated field is active evidence for the attribute `name`."""
    return _is_active(name, field.value, field.rejected_by)


def transport_row_is_active(name: str, row: Mapping[str, Any]) -> bool:
    """The same rule read off canonical validated transport.

    `to_transport()` excludes `None`, so a row carrying a `rejected_by` key carries a
    real rejection and an accepted row has no such key at all — `row.get()` returning
    `None` therefore means exactly `field.rejected_by is None`.
    """
    return _is_active(name, row.get("value"), row.get("rejected_by"))


def _validation_summary(exc: Exception) -> str:
    """A short reason for a log line, carrying no observed values.

    A Pydantic error message embeds `input_value=...`, which for this transport *is*
    profile data, so the message itself is never propagated. Error locations and types
    name the shape problem using schema keys alone.
    """
    if isinstance(exc, ValidationError):
        errors = exc.errors()
        parts = [
            f"{'.'.join(str(item) for item in error['loc']) or OBSERVED_KEY}: {error['type']}"
            for error in errors[:3]
        ]
        remaining = len(errors) - len(parts)
        if remaining > 0:
            parts.append(f"and {remaining} more")
        return "; ".join(parts)[:200]
    return str(exc)[:200]


@dataclass(frozen=True)
class ObservedAuthority:
    """What a finding's `observed` channel is allowed to decide, for one consumer.

    Authority is decided by **key presence**, never by truthiness and never by type.
    `observed` absent means no observed transport was ever written, and only then may a
    consumer read the top-level compatibility attributes. `observed` present means the
    authoritative channel exists — including when it is `{}`, `None`, `[]` or malformed —
    and the top-level attributes are no longer evidence for anything it covers.

    Three states, and every consumer needs the same three:

    - absent: `present` false, `fields` None. Legacy fallback path.
    - present and valid: `fields` is the validated model, `{}` included. An empty mapping
      is authoritative emptiness, not an invitation to fall back.
    - present and invalid: `present` true, `fields` None, `error` a short reason. Fail
      closed for enrichment — but only for enrichment. PROFILE EXISTS != SAME PERSON, so
      a malformed enrichment payload does not un-check the public profile it was attached
      to, and the record itself survives with its optional attributes blank.
    """

    present: bool
    fields: ObservedFields | None = None
    error: str = ""

    @property
    def failed(self) -> bool:
        """Transport exists and does not validate. Never a reason to read top level."""
        return self.present and self.fields is None

    def active(self) -> dict[str, ObservedField]:
        """The validated fields a consumer may treat as evidence, in transport order.

        Empty when the channel is absent or invalid, so a caller that only wants active
        evidence needs no state machine of its own.
        """
        if self.fields is None:
            return {}
        return {
            name: field
            for name, field in self.fields.root.items()
            if field_is_active(name, field)
        }


def read_observed(data: Mapping[str, Any] | None) -> ObservedAuthority:
    """Decide what a finding's `observed` channel may authorize, and validate it once.

    This is the consumer-side parse boundary B2-03B1 introduces: identity correlation,
    presentation and pivot extraction all read observed profile attributes through here,
    so "is this transport trustworthy" is answered in exactly one place.

    Only validation failures are caught. `parse_observed()` raises `ValueError` for a
    non-mapping payload and Pydantic's `ValidationError` — itself a `ValueError` — for a
    malformed one; `TypeError` covers a payload whose shape breaks the walk before
    validation starts. Nothing broader is swallowed, and the original
    `Finding.data[OBSERVED_KEY]` is left exactly as persisted: this decides what may be
    *read* as evidence, never what was written.
    """
    payload = data or {}
    if OBSERVED_KEY not in payload:
        return ObservedAuthority(present=False)
    try:
        fields = parse_observed(payload[OBSERVED_KEY])
    except (ValueError, TypeError) as exc:
        return ObservedAuthority(present=True, error=_validation_summary(exc))
    return ObservedAuthority(present=True, fields=fields)


def project_items(items: list[ObservedItem]) -> dict[str, Any]:
    """Row-level fields a list of items truthfully supports.

    Single source of truth for both `ObservedField.from_items()` and the validator
    that rejects a row disagreeing with its own items.
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
    return {
        "value": values,
        "original": originals,
        "source": sources.pop() if len(sources) == 1 else MULTIPLE_SOURCES,
        # The row is "as of" its most recent observation; each item keeps its own.
        # Newest by absolute instant, and the selected item's own representation is
        # what the row carries — see _newest_observed_at().
        "observed_at": _newest_observed_at(items),
        "provider_slug": _shared(item.provider_slug for item in items),
        "source_method": _project_source_method(items),
        "source_url": _shared(item.source_url for item in items),
        "derived_from": _shared(item.derived_from for item in items),
    }


def _project_source_method(items: list[ObservedItem]) -> SourceMethod | None:
    """The method the items prove: the shared one, MIXED for several, None if any is unknown.

    MIXED asserts that the items reached SPECTRE through more than one acquisition
    method. An item whose method is unknown proves no second origin, so a list holding
    one has a row-level method that is simply not known — omitting it is the truthful
    answer, and guessing the missing method would be the false one. MIXED therefore
    means at least two distinct, non-null methods were actually observed.
    """
    methods = [item.source_method for item in items]
    if any(method is None for method in methods):
        return None
    distinct = set(methods)
    return distinct.pop() if len(distinct) == 1 else SourceMethod.MIXED


# `_instant_key()` counts whole microseconds, the finest unit `datetime` records.
_MICROSECONDS_PER_SECOND = 1_000_000
_SECONDS_PER_DAY = 86_400


def _newest_observed_at(items: list[ObservedItem]) -> datetime:
    """The timestamp of the item observed latest in absolute time.

    Ordering is by absolute instant, but the value returned is the selected item's own
    aware datetime, unchanged. Comparing by instant and storing the original keeps the
    row honest about *when* without rewriting *how the observer spelled it*: a row
    projected from an item stamped `-05:00` still serializes `-05:00`.

    Raw `max()` over the datetimes is not the same thing. CPython compares two aware
    datetimes that share one `tzinfo` object by their wall-clock fields alone, so
    across a DST fold — 01:30 `fold=0` and 01:30 `fold=1` in America/New_York, an
    hour apart in real time — it reports them equal and returns whichever came first
    in the list. The row then claimed the older observation as its "as of", and the
    result depended on item order. `_instant_key()` resolves the fold, so the
    comparison sees the two instants the observations actually name.
    """
    return max(items, key=lambda item: _instant_key(item.observed_at)).observed_at


def _instant_key(value: datetime) -> int:
    """The instant an aware timestamp names, in microseconds. For comparison only.

    Local calendar position minus UTC offset, in integer microseconds — the quantity
    `astimezone(UTC)` would have computed, kept as an unbounded `int` instead of a
    `datetime`. Ordering and equality over these keys are exactly ordering and equality
    over instants, which is how CPython already compares two aware datetimes whose
    offsets differ; the key just declines to name the result on a calendar.

    It has to decline, because `datetime` spans only years 1 through 9999 while an
    offset can push a valid timestamp's instant outside that span.
    `0001-01-01T00:00:00+01:00` names an instant in year 0 and
    `9999-12-31T23:59:59-01:00` one in year 10000. Both are accepted `AwareDatetime`
    values that serialize and reparse unchanged, and `astimezone(UTC)` raised
    `OverflowError` on both — so did shifting the datetime by its own offset, and
    `datetime.timestamp()` answers a different, epoch-bound and platform-bounded
    question. Integers have no boundary to fall off.

    Awareness is the caller's invariant, not this helper's business to repair: both
    models type `observed_at` as `AwareDatetime`, and `parse_observed()` has already
    read a legacy naive stamp as UTC, so every timestamp arriving here carries an
    offset. A naive one is refused rather than read as UTC a second time here, where
    the field that owns that rule has no say.
    """
    offset = value.utcoffset()
    if offset is None:
        raise ValueError("observed_at must be aware to name an instant")
    local_microseconds = (
        (value.toordinal() - 1) * _SECONDS_PER_DAY
        + value.hour * 3600
        + value.minute * 60
        + value.second
    ) * _MICROSECONDS_PER_SECOND + value.microsecond
    offset_microseconds = (
        offset.days * _SECONDS_PER_DAY + offset.seconds
    ) * _MICROSECONDS_PER_SECOND + offset.microseconds
    return local_microseconds - offset_microseconds


def _agrees_with_projection(name: str, actual: Any, expected: Any) -> bool:
    """Whether one row field matches what the row's items project.

    `observed_at` is compared as an instant, because two aware datetimes can spell
    one moment with different offsets — `01:30-05:00` and `06:30+00:00` are the same
    observation — while two that share a `tzinfo` object can spell two moments
    identically across a DST fold. Offset spelling is not provenance; the instant is.

    Every other key keeps exact equality: `value`, `original`, `source`,
    `provider_slug`, `source_method`, `source_url` and `derived_from` must match the
    projection literally, as before.
    """
    if name == "observed_at":
        return _instant_key(actual) == _instant_key(expected)
    return actual == expected


def _shared(values: Iterable[Any]) -> Any:
    """The one value every item agrees on, or None when they disagree."""
    distinct = set(values)
    return distinct.pop() if len(distinct) == 1 else None


# The one canonical `datetime.isoformat()` offset spelling an affected CPython reads as
# UTC: hours, minutes and whole seconds all zero while the sub-second part is not.
# `isoformat()` writes the offset fraction as exactly six digits, and `[0-9]` keeps the
# match ASCII rather than any Unicode decimal digit `\d` would also admit.
_SUBSECOND_ONLY_OFFSET = re.compile(r"([+-])00:00:00\.([0-9]{6})$")


def _stated_subsecond_offset(stamp: str) -> timedelta | None:
    """The signed pure sub-second UTC offset a transport spells, when it spells one.

    Recovered from the transport's own characters as integer microseconds — no float
    arithmetic, no epoch, no second parser — so the answer is exactly what
    `datetime.isoformat()` wrote. `None` means this stamp is not of that shape and has
    nothing to restore.

    A zero fraction returns `None` too. `+00:00:00.000000` is not a spelling this
    contract emits — a zero offset is written `+00:00` — and the standard library
    already reads it as UTC, which is the offset it states. Declining it structurally
    is what keeps this helper from ever inventing a nonzero offset for a stamp that
    named none.
    """
    match = _SUBSECOND_ONLY_OFFSET.search(stamp)
    if match is None:
        return None
    sign, fraction = match.groups()
    microseconds = int(fraction)
    if microseconds == 0:
        return None
    return timedelta(microseconds=-microseconds if sign == "-" else microseconds)


def _as_aware(stamp: str) -> str | datetime:
    """Read an ISO timestamp once, with the standard library, and hand on the result.

    A naive stamp keeps the legacy compatibility rule and is read as UTC. An aware one
    is handed on as the parsed `datetime` **object** rather than as its original string,
    because the two parsers do not accept the same offset spellings.

    `datetime.fromisoformat()` accepts an offset carrying seconds or fractional seconds
    — `+00:00:30`, `+00:00:30.123456` — and `datetime.isoformat()`, this contract's
    serializer, emits exactly those spellings back. Pydantic's *string* parser refuses
    them ("unexpected extra characters at the end of the input") while its
    `AwareDatetime` field accepts the equivalent `datetime` object. Returning the
    string therefore let a valid `ObservedField` serialize to transport its own parser
    would reject: construct -> `to_transport()` -> `parse_observed()` failed. Returning
    the object closes that hole for the whole offset domain this serializer can write.

    One spelling in that domain needs the offset restored afterwards. The C
    `fromisoformat()` accelerator shipped in Python 3.12 short-circuits to UTC on the
    whole-second part of an offset alone, so a canonical `+00:00:00.ffffff` — hours,
    minutes and seconds zero, sub-second part not — parses with its offset silently
    discarded (CPython gh-152079, fixed on 3.13 and later; 3.12 is supported here and
    stays affected). `2026-01-01T00:00:00+00:00:00.000001` came back as
    `2026-01-01T00:00:00+00:00`, a different instant one microsecond away, which is a
    provenance claim this contract never made. So when the transport states such an
    offset and the parse did not keep it, the stated offset is put back.

    Only the `tzinfo` label is replaced, never the instant. The affected parse reads the
    local wall-clock fields correctly and mislabels them UTC, so `replace()` restores
    the moment the transport named; `astimezone()` would convert the already-wrong
    instant and carry the corruption forward. On a fixed runtime the parse already
    agrees with the spelling and nothing is replaced at all.

    The instant is otherwise carried across unchanged: the parsed object keeps its own
    `tzinfo`, so nothing is converted to UTC, no `astimezone()` is involved, the offset
    value and microsecond precision survive, and a timestamp whose UTC equivalent would
    fall outside years 1..9999 stays representable — `_instant_key()` compares such rows
    without ever naming them on a calendar.

    Unparseable text is returned untouched, on purpose: Pydantic still owns the final
    validation error, and a malformed timestamp is never repaired, re-stamped as "now",
    or given a UTC offset it was not observed with. The restoration sits behind that
    door, on a stamp the standard library has already read as aware, so it can correct
    an offset but never make an invalid timestamp valid.
    """
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        return stamp
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    stated = _stated_subsecond_offset(stamp)
    if stated is not None and parsed.utcoffset() != stated:
        return parsed.replace(tzinfo=timezone(stated))
    return parsed
