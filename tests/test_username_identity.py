"""Offline identity correlation. Same username is not identity."""

from __future__ import annotations

import json
import logging

import pytest

from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.modules.username.identity import (
    BANDS,
    CLUSTER_MIN,
    CONFLICTS,
    WEIGHTS,
    compare_records,
    correlate_identities,
    identity_artifacts,
    normalize_name,
    normalize_url,
    records_from_findings,
)
from spectre_osint.reporting.html import write_html_report


def _finding(platform: str, status: str = "LIKELY", **data: object) -> Finding:
    payload = {
        "platform": platform,
        "username": "alice",
        "check_status": status,
        "profile_url": f"https://{platform.lower().replace(' ', '')}.example/alice",
        **data,
    }
    return Finding(
        module="username",
        title=platform,
        status=FindingStatus.FOUND if status in {"LIKELY", "CONFIRMED"} else FindingStatus.INCONCLUSIVE,
        summary=f"{platform}: {status}",
        data=payload,
        confidence=Confidence.HIGH if status in {"LIKELY", "CONFIRMED"} else Confidence.LOW,
    )


def _pair(*findings: Finding) -> dict:
    records = records_from_findings(list(findings))
    return compare_records(records[0], records[1])


def test_normalize_name_and_url() -> None:
    assert normalize_name("Alice Example") == normalize_name("alice example")
    assert normalize_url("HTTP://WWW.Example.com/Path/?utm_source=x") == "https://example.com/Path"


def test_same_username_alone_is_low() -> None:
    pair = _pair(_finding("GitHub"), _finding("Steam"))
    assert pair["score"] < 30
    assert pair["band"] == "LOW"
    assert pair["evidence"] == ["same_username"]


def test_username_plus_display_name_is_not_strong() -> None:
    pair = _pair(
        _finding("GitHub", display_name="Alice Example"),
        _finding("Instagram", display_name="bob example"),
    )
    assert pair["band"] != "STRONG"
    assert pair["score"] < 80


def test_personal_domain_increases_score() -> None:
    weak = _pair(_finding("GitHub"), _finding("Instagram"))
    strong = _pair(
        _finding("GitHub", website="https://alice.dev"),
        _finding("Instagram", website="http://www.alice.dev/"),
    )
    assert strong["score"] > weak["score"]
    assert "same_personal_domain" in strong["evidence"]
    assert strong["score"] >= 40


def test_cross_profile_link_increases_score() -> None:
    pair = _pair(
        _finding("Instagram", website="https://github.com/alice", public_links=["https://github.com/alice"]),
        _finding("GitHub", profile_url="https://github.com/alice"),
    )
    assert "cross_profile_link" in pair["evidence"]
    assert pair["score"] > 30


def test_same_avatar_url_increases_score() -> None:
    weak = _pair(_finding("GitHub"), _finding("Docker Hub"))
    strong = _pair(
        _finding("GitHub", avatar_url="https://cdn.example/a.png?utm_source=x"),
        _finding("Docker Hub", avatar_url="http://www.cdn.example/a.png"),
    )
    assert strong["score"] > weak["score"]
    assert "same_avatar_url" in strong["evidence"]


def test_multiple_evidence_is_strong() -> None:
    pair = _pair(
        _finding(
            "GitHub",
            display_name="Alice Example",
            website="https://alice.dev",
            public_links=["https://instagram.com/alice"],
            profile_url="https://github.com/alice",
        ),
        _finding(
            "Instagram",
            display_name="alice example",
            website="https://www.alice.dev/",
            profile_url="https://instagram.com/alice",
        ),
    )
    assert pair["band"] == "STRONG"
    assert pair["score"] >= 80
    assert pair["evidence"] == sorted(pair["evidence"])


def test_conflicting_name_and_website_stay_low() -> None:
    pair = _pair(
        _finding("GitHub", display_name="Alice Example", website="https://alice.dev"),
        _finding("Steam", display_name="Bob Other", website="https://bob.invalid"),
    )
    assert pair["strong_conflict"] is True
    assert pair["band"] == "LOW"
    assert pair["score"] <= 29


def test_three_matching_and_one_unrelated_make_two_groups() -> None:
    payload = correlate_identities(
        [
            _finding("GitHub", display_name="Alice Example", website="https://alice.dev"),
            _finding("Instagram", display_name="Alice Example", website="https://alice.dev"),
            _finding("Docker Hub", display_name="Alice Example", website="https://alice.dev"),
            _finding("Steam", display_name="Other Person", website="https://other.invalid"),
        ]
    )
    assert len(payload["clusters"]) == 1
    assert payload["clusters"][0]["platforms"] == ["Docker Hub", "GitHub", "Instagram"]
    assert "Steam" in payload["unclustered"]


def test_different_usernames_are_not_auto_clustered() -> None:
    payload = correlate_identities(
        [
            _finding("GitHub", username="alice_osint"),
            _finding("Steam", username="alice-sec"),
        ]
    )
    assert payload["clusters"] == []
    assert payload["max_score"] < 30


def test_same_platform_two_usernames_are_distinct_records() -> None:
    payload = correlate_identities(
        [
            _finding("GitHub", username="alice_osint", display_name="A"),
            _finding("GitHub", username="alice-sec", display_name="B"),
        ]
    )
    assert payload["records"] == 2


def test_missing_fields_do_not_crash() -> None:
    pair = _pair(_finding("GitHub", display_name=""), _finding("GitLab", bio=None))  # type: ignore[arg-type]
    assert 0 <= pair["score"] <= 100
    assert pair["band"] == "LOW"


def test_identity_finding_and_html_section(tmp_path) -> None:
    user = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)
    artifacts = identity_artifacts(
        [
            _finding("GitHub", display_name="Alice Example", website="https://alice.dev", profile_url="https://github.com/alice"),
            _finding(
                "Instagram",
                display_name="Alice Example",
                website="https://alice.dev",
                profile_url="https://instagram.com/alice",
            ),
        ],
        user,
    )
    assert artifacts["findings"]
    assert artifacts["findings"][0].title == "Identity correlation"
    result = InvestigationResult(
        case_id="c",
        case_name="id-demo",
        target="alice",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user, *artifacts["entities"]],
        findings=artifacts["findings"],
        relationships=artifacts["relationships"],
        identity_correlation=artifacts["identity_correlation"],
    )
    html = write_html_report(result, tmp_path).read_text(encoding="utf-8")
    assert "Identity Correlation" in html
    assert "GitHub" in html
    assert "cookie" not in html.lower() or "cookies" not in html.lower()


def test_shared_website_alone_does_not_cluster() -> None:
    """One website observation is one signal, not enough to cluster two handles."""
    left = _finding(
        "AlphaSite",
        username="alice",
        profile_url="https://alphasite.example/alice",
        website="https://acme.com/",
    )
    right = _finding(
        "BetaSite",
        username="bobmarley",
        profile_url="https://betasite.example/bobmarley",
        website="https://acme.com/",
    )
    pair = compare_records(*records_from_findings([left, right]))
    assert pair["score"] < CLUSTER_MIN
    assert pair["score"] == WEIGHTS["same_personal_domain"]
    assert "cross_profile_link" not in pair["evidence"]
    payload = correlate_identities([left, right])
    assert payload["clusters"] == []
    assert payload["max_score"] < CLUSTER_MIN


def test_shared_link_hub_url_alone_does_not_cluster() -> None:
    """A shared link hub suppresses the domain signal and must not cluster on the URL."""
    left = _finding(
        "AlphaSite",
        username="alice",
        profile_url="https://alphasite.example/alice",
        website="https://linktr.ee/acmeteam",
    )
    right = _finding(
        "BetaSite",
        username="bobmarley",
        profile_url="https://betasite.example/bobmarley",
        website="https://linktr.ee/acmeteam",
    )
    pair = compare_records(*records_from_findings([left, right]))
    assert pair["score"] < CLUSTER_MIN
    assert pair["score"] == WEIGHTS["same_personal_url"]
    assert "same_personal_domain" not in pair["evidence"]
    assert "cross_profile_link" not in pair["evidence"]
    payload = correlate_identities([left, right])
    assert payload["clusters"] == []


def test_shared_website_with_same_handle_still_does_not_cluster() -> None:
    """The common single-handle sweep must not cluster on a website alone either."""
    pair = _pair(
        _finding("AlphaSite", website="https://acme.com/"),
        _finding("BetaSite", website="https://acme.com/"),
    )
    assert pair["score"] < CLUSTER_MIN
    assert pair["score"] == WEIGHTS["same_personal_domain"] + WEIGHTS["same_username"]


def test_one_website_observation_is_reported_twice_but_scored_once() -> None:
    """Both codes stay visible to the operator; only one of them earns points."""
    pair = _pair(
        _finding("AlphaSite", website="https://acme.com/"),
        _finding("BetaSite", website="http://www.acme.com"),
    )
    assert "same_personal_domain" in pair["evidence"]
    assert "same_personal_url" in pair["evidence"]
    codes = {row["code"] for row in pair["evidence_detail"]}
    assert {"same_personal_domain", "same_personal_url"} <= codes
    inflated = (
        WEIGHTS["same_username"]
        + WEIGHTS["same_personal_domain"]
        + WEIGHTS["same_personal_url"]
    )
    assert pair["score"] < inflated
    assert pair["score"] == WEIGHTS["same_username"] + WEIGHTS["same_personal_domain"]


def test_cross_profile_link_requires_a_profile_target() -> None:
    """A link to the other record's website restates the website; only a profile link counts."""
    website_only = _pair(
        _finding(
            "AlphaSite",
            username="alice",
            profile_url="https://alphasite.example/alice",
            public_links=["https://acme.com/"],
        ),
        _finding(
            "BetaSite",
            username="alice",
            profile_url="https://betasite.example/alice",
            website="https://acme.com/",
        ),
    )
    assert "cross_profile_link" not in website_only["evidence"]

    profile_link = _pair(
        _finding(
            "AlphaSite",
            username="alice",
            profile_url="https://alphasite.example/alice",
            public_links=["https://betasite.example/alice"],
        ),
        _finding(
            "BetaSite",
            username="alice",
            profile_url="https://betasite.example/alice",
        ),
    )
    assert "cross_profile_link" in profile_link["evidence"]


def test_independent_signals_still_stack_to_strong() -> None:
    """Name + website + a real profile cross-link are three observations, not one."""
    pair = _pair(
        _finding(
            "GitHub",
            display_name="Alice Example",
            website="https://alice.dev",
            public_links=["https://instagram.com/alice"],
            profile_url="https://github.com/alice",
        ),
        _finding(
            "Instagram",
            display_name="alice example",
            website="https://www.alice.dev/",
            profile_url="https://instagram.com/alice",
        ),
    )
    assert set(pair["evidence"]) >= {
        "same_display_name",
        "same_personal_domain",
        "cross_profile_link",
    }
    assert pair["score"] >= 80
    assert pair["band"] == "STRONG"


def test_weights_conflicts_and_bands_are_unchanged_by_the_hotfix() -> None:
    """The hotfix changes how signals are counted, never what they are worth."""
    assert WEIGHTS == {
        "same_username": 6,
        "same_display_name": 16,
        "similar_bio": 10,
        "same_organization": 10,
        "same_location": 8,
        "same_personal_domain": 42,
        "same_personal_url": 40,
        "cross_profile_link": 38,
        "same_public_id": 32,
        "same_public_email": 35,
        "same_avatar_url": 18,
    }
    assert CONFLICTS == {
        "distinct_display_name": -28,
        "distinct_personal_domain": -32,
        "distinct_organization": -18,
        "distinct_location": -12,
        "distinct_public_id": -40,
        "distinct_public_email": -35,
    }
    assert BANDS == ((80, "STRONG"), (60, "LIKELY"), (30, "POSSIBLE"), (0, "LOW"))
    assert CLUSTER_MIN == 60


def test_strong_conflicts_still_cap_and_block_clustering() -> None:
    """Conflict handling is untouched: capped at 24, never clustered."""
    left = _finding("GitHub", display_name="Alice Example", website="https://alice.dev")
    right = _finding("Steam", display_name="Bob Other", website="https://bob.invalid")
    pair = compare_records(*records_from_findings([left, right]))
    assert pair["strong_conflict"] is True
    assert "distinct_display_name" in pair["conflicts"]
    assert "distinct_personal_domain" in pair["conflicts"]
    assert pair["score"] <= 24
    assert pair["band"] == "LOW"
    assert correlate_identities([left, right])["clusters"] == []


def test_distinct_public_id_alone_still_caps_the_score() -> None:
    """A single strong conflict keeps capping even when a website matches."""
    left = _finding("GitHub", website="https://acme.com/", public_id="1")
    right = _finding("GitLab", website="https://acme.com/", public_id="2")
    pair = compare_records(*records_from_findings([left, right]))
    assert pair["strong_conflict"] is True
    assert pair["score"] <= 24
    assert correlate_identities([left, right])["clusters"] == []


def test_website_that_only_restates_its_own_profile_url_is_not_an_observation() -> None:
    """Providers leaking canonical/og:url into `website` must not add a second signal."""
    linking = _finding(
        "GitHub",
        username="alice",
        profile_url="https://github.com/alice",
        website="https://tryhackme.com/p/bob",
    )
    self_referential = _finding(
        "TryHackMe",
        username="bob",
        profile_url="https://tryhackme.com/p/bob",
        website="https://tryhackme.com/p/bob",
    )
    pair = compare_records(*records_from_findings([linking, self_referential]))
    assert pair["evidence"] == ["cross_profile_link"]
    assert pair["score"] == WEIGHTS["cross_profile_link"]
    assert pair["score"] < CLUSTER_MIN
    assert correlate_identities([linking, self_referential])["clusters"] == []
    honest = compare_records(
        *records_from_findings(
            [
                linking,
                _finding("TryHackMe", username="bob", profile_url="https://tryhackme.com/p/bob"),
            ]
        )
    )
    assert (pair["score"], pair["evidence"]) == (honest["score"], honest["evidence"])


def test_self_referential_websites_on_one_platform_do_not_match() -> None:
    """Two users on a leaking provider share only the platform, which is not identity."""
    left = _finding(
        "TryHackMe",
        username="alice",
        profile_url="https://tryhackme.com/p/alice",
        website="https://tryhackme.com/p/alice",
    )
    right = _finding(
        "TryHackMe",
        username="bobmarley",
        profile_url="https://tryhackme.com/p/bobmarley",
        website="https://tryhackme.com/p/bobmarley",
    )
    pair = compare_records(*records_from_findings([left, right]))
    assert "same_personal_domain" not in pair["evidence"]
    assert "same_personal_url" not in pair["evidence"]
    assert "distinct_personal_domain" not in pair["conflicts"]
    assert pair["score"] < CLUSTER_MIN
    assert correlate_identities([left, right])["clusters"] == []


def test_website_n_drops_only_the_self_reference() -> None:
    """A genuine website survives; any normalization of the own profile URL does not."""
    genuine = records_from_findings(
        [_finding("GitHub", profile_url="https://github.com/alice", website="https://alice.dev")]
    )[0]
    assert genuine.website_n == "https://alice.dev/"
    assert genuine.url_n == "https://alice.dev/"
    assert genuine.domain == "alice.dev"
    for variant in (
        "https://tryhackme.com/p/alice",
        "http://www.tryhackme.com/p/alice/",
        "tryhackme.com/p/alice?utm_source=x",
    ):
        leaked = records_from_findings(
            [_finding("TryHackMe", profile_url="https://tryhackme.com/p/alice", website=variant)]
        )[0]
        assert leaked.website_n == "", variant
        assert leaked.url_n == "", variant
        assert leaked.domain == "", variant


def test_cross_profile_link_rejects_a_username_substring() -> None:
    """alicebob is a different account; alice being a prefix of it is not a link."""
    pair = _pair(
        _finding(
            "AlphaSite",
            username="alice",
            profile_url="https://alphasite.example/alice",
            public_links=["https://wordpress.org/support/users/alicebob"],
        ),
        _finding(
            "WordPress",
            username="alice",
            profile_url="https://wordpress.org/support/users/alice",
        ),
    )
    assert "cross_profile_link" not in pair["evidence"]
    assert pair["score"] == WEIGHTS["same_username"]


def test_cross_profile_link_rejects_a_username_suffix_and_infix() -> None:
    """malice contains alice; so does an unrelated article slug. Neither is a profile."""
    for decoy in (
        "https://wordpress.org/support/users/malice",
        "https://wordpress.org/support/users/notalicehere",
        "https://wordpress.org/news/alice-in-wonderland-review",
    ):
        pair = _pair(
            _finding(
                "AlphaSite",
                username="alice",
                profile_url="https://alphasite.example/alice",
                public_links=[decoy],
            ),
            _finding(
                "WordPress",
                username="alice",
                profile_url="https://wordpress.org/support/users/alice",
            ),
        )
        assert "cross_profile_link" not in pair["evidence"], decoy


def test_cross_profile_link_accepts_an_exact_path_segment() -> None:
    """A different path on the same host still counts when a segment *is* the username."""
    pair = _pair(
        _finding(
            "AlphaSite",
            username="alice",
            profile_url="https://alphasite.example/alice",
            public_links=["https://wordpress.org/users/alice"],
        ),
        _finding(
            "WordPress",
            username="alice",
            profile_url="https://wordpress.org/support/users/alice",
        ),
    )
    assert "cross_profile_link" in pair["evidence"]
    assert pair["score"] == WEIGHTS["same_username"] + WEIGHTS["cross_profile_link"]


def test_cross_profile_link_accepts_at_prefixed_and_trailing_slash_segments() -> None:
    """/p/alice/ and /@alice are the same identity claim as /alice."""
    for link in (
        "https://wordpress.org/p/alice/",
        "https://wordpress.org/@alice",
        "https://WordPress.ORG/P/Alice",
    ):
        pair = _pair(
            _finding(
                "AlphaSite",
                username="alice",
                profile_url="https://alphasite.example/alice",
                public_links=[link],
            ),
            _finding(
                "WordPress",
                username="alice",
                profile_url="https://wordpress.org/support/users/alice",
            ),
        )
        assert "cross_profile_link" in pair["evidence"], link


def test_cross_profile_link_reads_an_exact_query_value() -> None:
    """?user=alice is an explicit identity claim; ?user=alicebob and ?q=alice are not."""
    pair = _pair(
        _finding(
            "AlphaSite",
            username="alice",
            profile_url="https://alphasite.example/alice",
            public_links=["https://wordpress.org/profile.php?user=alice"],
        ),
        _finding(
            "WordPress",
            username="alice",
            profile_url="https://wordpress.org/support/users/alice",
        ),
    )
    assert "cross_profile_link" in pair["evidence"]
    for decoy in (
        "https://wordpress.org/profile.php?user=alicebob",
        "https://wordpress.org/search.php?q=alice+example",
    ):
        miss = _pair(
            _finding(
                "AlphaSite",
                username="alice",
                profile_url="https://alphasite.example/alice",
                public_links=[decoy],
            ),
            _finding(
                "WordPress",
                username="alice",
                profile_url="https://wordpress.org/support/users/alice",
            ),
        )
        assert "cross_profile_link" not in miss["evidence"], decoy


def test_repeated_cross_profile_link_scores_once() -> None:
    """The same target listed several ways is one observation."""
    pair = _pair(
        _finding(
            "AlphaSite",
            username="alice",
            profile_url="https://alphasite.example/alice",
            public_links=[
                "https://wordpress.org/users/alice",
                "https://wordpress.org/users/alice/",
                "http://www.wordpress.org/users/alice?utm_source=x",
                "https://wordpress.org/support/users/alice",
            ],
        ),
        _finding(
            "WordPress",
            username="alice",
            profile_url="https://wordpress.org/support/users/alice",
        ),
    )
    assert pair["evidence"].count("cross_profile_link") == 1
    assert pair["score"] == WEIGHTS["same_username"] + WEIGHTS["cross_profile_link"]


# ---------------------------------------------------------------------------
# B2-03B1: validated `observed` is authoritative for observed profile attributes.
#
# Authority is decided by KEY PRESENCE. A finding with no `observed` key at all is a
# true pre-B2-03A row and keeps the top-level compatibility fallback; a finding that
# carries the key — valid, empty, `None`, `[]` or malformed — has an authoritative
# channel, and the top-level attributes stop being evidence for anything it covers.
# ---------------------------------------------------------------------------

_OBSERVED_STAMP = "2026-01-01T12:00:00+00:00"

# Top-level compatibility values no record with an `observed` key may ever surface. Every
# spelling the legacy reader accepts is poisoned, including both alternates per attribute,
# so a fallback anywhere is visible rather than merely possible.
_POISON = {
    "display_name": "Mallory Poison",
    "bio": "Poisoned biography long enough to be a comparable public field",
    "avatar_url": "https://poison.example/avatar.png",
    "website": "https://poison.example/",
    "public_location": "Poisonville",
    "location": "Poisonville",
    "organization": "Poison Corp",
    "company": "Poison Corp",
    "public_email": "poison@poison.example",
    "email": "poison@poison.example",
    "public_id": "poison-999",
    "id": "poison-999",
    "public_links": ["https://poison.example/link"],
}


def _row(value: object, **extra: object) -> dict:
    """One observed field as real transport: all four required keys, like the producer."""
    original = list(value) if isinstance(value, list) else value
    return {
        "value": value,
        "original": original,
        "source": "github_api.field",
        "observed_at": _OBSERVED_STAMP,
        **extra,
    }


def _observed_record(observed: object, **top_level: object) -> object:
    """The single record built from one CONFIRMED finding carrying `observed`."""
    records = records_from_findings(
        [_finding("GitHub", status="CONFIRMED", observed=observed, **top_level)]
    )
    assert len(records) == 1
    return records[0]


# A. no observed key at all -> true legacy, fallback intact
def test_a_finding_without_observed_keeps_the_legacy_top_level_mapping() -> None:
    """The compatibility sentinel. Rows written before the contract cannot be re-enriched."""
    finding = _finding(
        "GitHub",
        status="CONFIRMED",
        display_name="Alice Legacy",
        bio="Legacy biography long enough to compare",
        avatar_url="https://legacy.example/a.png",
        website="https://legacy.example/",
        public_location="Lisbon",
        organization="Legacy Labs",
        public_email="alice@legacy.example",
        public_id="42",
        public_links=["https://x.com/alice"],
        created_at="2020-01-01",
    )
    assert "observed" not in finding.data
    record = records_from_findings([finding])[0]
    assert record.display_name == "Alice Legacy"
    assert record.bio == "Legacy biography long enough to compare"
    assert record.avatar_url == "https://legacy.example/a.png"
    assert record.website == "https://legacy.example/"
    assert record.location == "Lisbon"
    assert record.organization == "Legacy Labs"
    assert record.public_email == "alice@legacy.example"
    assert record.public_id == "42"
    # Legacy links keep the compatibility website append.
    assert record.links == ["https://x.com/alice", "https://legacy.example/"]
    assert record.created == "2020-01-01"
    # No provenance is fabricated for a top-level attribute.
    assert record.provenance == {}


# B. observed present and empty -> authoritative emptiness, never a fallback
def test_an_empty_observed_mapping_is_authoritative_emptiness() -> None:
    """`{}` says "enrichment ran and found nothing", not "look somewhere else"."""
    record = _observed_record({}, **_POISON)
    assert record.display_name == ""
    assert record.bio == ""
    assert record.avatar_url == ""
    assert record.website == ""
    assert record.location == ""
    assert record.organization == ""
    assert record.public_email == ""
    assert record.public_id == ""
    assert record.links == []
    assert record.provenance == {}
    # The checked profile itself is untouched by an empty enrichment payload.
    assert record.platform == "GitHub"
    assert record.username == "alice"
    assert record.profile_url == "https://github.example/alice"
    assert record.check_status == "CONFIRMED"
    assert record.entity_id


# C + D + §16. Every attribute, both channels, one parametrized proof.
#
# `_row()` supplies only the four contract-required keys, so the "legacy four-key" and
# "modern" transports are the same shape here — additive B2-03A metadata is optional and
# its absence must not cost a row its authority. The `observed_*` variants below add it.
@pytest.mark.parametrize(
    ("field", "observed_value", "attribute", "expected"),
    (
        ("display_name", "Alice Observed", "display_name", "Alice Observed"),
        ("bio", "Observed biography long enough to compare", "bio", "Observed biography long enough to compare"),
        ("avatar_url", "https://observed.example/a.png", "avatar_url", "https://observed.example/a.png"),
        ("website", "https://observed.example/", "website", "https://observed.example/"),
        ("location", "Porto", "location", "Porto"),
        ("organization", "Observed Labs", "organization", "Observed Labs"),
        ("public_email", "alice@observed.example", "public_email", "alice@observed.example"),
        ("public_id", "observed-1", "public_id", "observed-1"),
    ),
)
def test_top_level_compatibility_cannot_override_observed(
    field: str, observed_value: str, attribute: str, expected: str
) -> None:
    """One observed field wins its attribute, and poisons none of the others.

    Poisoning every top-level spelling at once means the assertion is not just "the
    observed value arrived" but "no attribute was filled from the compatibility channel":
    the eight attributes this record could have are the observed one plus seven blanks.
    """
    record = _observed_record({field: _row(observed_value)}, **_POISON)
    assert getattr(record, attribute) == expected
    blanks = {
        "display_name",
        "bio",
        "avatar_url",
        "website",
        "location",
        "organization",
        "public_email",
        "public_id",
    } - {attribute}
    assert {name: getattr(record, name) for name in sorted(blanks)} == dict.fromkeys(sorted(blanks), "")
    # Top-level public_links never leaks in either.
    assert record.links == []
    assert record.provenance == {field: _row(observed_value)}


def test_top_level_public_links_cannot_override_observed_link_fields() -> None:
    """The list channel gets the same treatment as the scalars."""
    observed = {
        "external_links": _row(["https://alice.dev/"]),
        "social_links": _row(["https://x.com/alice"]),
    }
    record = _observed_record(observed, **_POISON)
    # Deterministic order: external_links before social_links, matching the producer.
    assert record.links == ["https://alice.dev/", "https://x.com/alice"]
    assert "https://poison.example/link" not in record.links
    assert record.website == ""


# E. present but invalid -> fail closed for enrichment, keep the checked profile
@pytest.mark.parametrize(
    ("label", "payload"),
    (
        ("row missing observed_at", {"website": {"value": "https://o.example/", "original": "x", "source": "s"}}),
        ("row missing original", {"website": {"value": "https://o.example/", "source": "s", "observed_at": _OBSERVED_STAMP}}),
        ("observed is None", None),
        ("observed is a list", []),
        ("observed is a non-empty list", [{"value": "x"}]),
        ("observed is a string", "malformed"),
        ("forbidden extra key", {"website": {**_row("https://o.example/"), "bogus": "x"}}),
        ("naive-hostile timestamp", {"website": {**_row("https://o.example/"), "observed_at": "not-a-date"}}),
        ("row is not a mapping", {"website": "https://o.example/"}),
        ("item claims the row-only marker", {"social_links": {**_row(["https://x.com/a"]), "source_method": "MIXED"}}),
    ),
)
def test_invalid_observed_fails_closed_without_a_top_level_fallback(
    label: str, payload: object
) -> None:
    """Malformed modern enrichment blanks the enrichment, not the profile.

    PROFILE EXISTS != SAME PERSON. A broken enrichment payload says nothing about whether
    the public profile was found, so the record stays in the inventory with its platform,
    handle, URL, check status and entity id intact — and with every optional observed
    attribute empty, because the only channel authorized to fill them did not validate.
    """
    record = _observed_record(payload, **_POISON)
    assert record.platform == "GitHub"
    assert record.username == "alice"
    assert record.profile_url == "https://github.example/alice"
    assert record.check_status == "CONFIRMED"
    assert record.entity_id
    assert record.display_name == ""
    assert record.bio == ""
    assert record.avatar_url == ""
    assert record.website == ""
    assert record.location == ""
    assert record.organization == ""
    assert record.public_email == ""
    assert record.public_id == ""
    assert record.links == []
    # Malformed transport is never stored as active provenance; the raw payload still
    # survives untouched in Finding.data, which is the persisted audit source.
    assert record.provenance == {}


def test_an_invalid_payload_never_reaches_the_legacy_branch() -> None:
    """A parse failure is not the same state as an absent key, and must not become one."""
    poisoned = _observed_record({"website": {"value": "https://o.example/"}}, **_POISON)
    legacy = records_from_findings([_finding("GitHub", status="CONFIRMED", **_POISON)])[0]
    # The legacy record does read the compatibility channel — that is the contrast.
    assert legacy.website == "https://poison.example/"
    assert legacy.display_name == "Mallory Poison"
    assert poisoned.website == ""
    assert poisoned.display_name == ""


def test_a_malformed_payload_leaves_the_original_finding_untouched() -> None:
    """Authority is a read-time decision; nothing repairs or rewrites the transport."""
    payload = {"website": {"value": "https://o.example/", "source": "s"}}
    finding = _finding("GitHub", status="CONFIRMED", observed=payload)
    snapshot = json.loads(json.dumps(finding.data))
    records_from_findings([finding])
    assert finding.data == snapshot


# F. rejected_by is authoritative downstream
def test_a_rejected_scalar_is_not_an_active_attribute() -> None:
    """A rejected value is absent from evidence, not a value that happens to score zero."""
    observed = {
        "display_name": _row("Rejected Name", rejected_by="test_rule"),
        "organization": _row("Observed Labs"),
    }
    record = _observed_record(observed, **_POISON)
    assert record.display_name == ""
    assert record.organization == "Observed Labs"
    # Rejection stays visible in the audit view: it was observed, and then rejected.
    assert record.provenance["display_name"]["rejected_by"] == "test_rule"
    assert record.provenance["display_name"]["value"] == "Rejected Name"


def test_a_rejected_list_field_contributes_no_links() -> None:
    observed = {
        "external_links": _row(["https://rejected.example/"], rejected_by="test_rule"),
        "social_links": _row(["https://x.com/alice"]),
    }
    record = _observed_record(observed, **_POISON)
    assert record.links == ["https://x.com/alice"]
    assert record.provenance["external_links"]["rejected_by"] == "test_rule"


def test_an_empty_rejection_token_still_rejects() -> None:
    """`is not None`, never truthiness: a blank token names a rejection all the same."""
    record = _observed_record({"display_name": _row("Rejected Name", rejected_by="")}, **_POISON)
    assert record.display_name == ""
    assert record.provenance["display_name"]["rejected_by"] == ""


def test_rejection_removes_positive_evidence() -> None:
    """Two profiles agreeing on an organization stop agreeing when one side is rejected."""
    def profile(platform: str, *, rejected: bool) -> Finding:
        row = _row("Observed Labs", rejected_by="test_rule") if rejected else _row("Observed Labs")
        return _finding(platform, status="CONFIRMED", observed={"organization": row})

    agreeing = _pair(profile("GitHub", rejected=False), profile("Instagram", rejected=False))
    assert "same_organization" in agreeing["evidence"]

    rejected = _pair(profile("GitHub", rejected=True), profile("Instagram", rejected=False))
    assert "same_organization" not in rejected["evidence"]
    assert rejected["score"] == agreeing["score"] - WEIGHTS["same_organization"]


def test_rejection_removes_negative_conflict() -> None:
    """A rejected value cannot contradict anything either. It is not in the comparison."""
    def profile(platform: str, name: str, *, rejected: bool) -> Finding:
        row = _row(name, rejected_by="test_rule") if rejected else _row(name)
        return _finding(platform, status="CONFIRMED", observed={"display_name": row})

    conflicting = _pair(
        profile("GitHub", "Alice Observed", rejected=False),
        profile("Instagram", "Bob Different", rejected=False),
    )
    assert "distinct_display_name" in conflicting["conflicts"]

    rejected = _pair(
        profile("GitHub", "Alice Observed", rejected=True),
        profile("Instagram", "Bob Different", rejected=False),
    )
    assert "distinct_display_name" not in rejected["conflicts"]
    assert rejected["score"] > conflicting["score"]


def test_a_rejected_value_never_appears_in_a_pair_explanation() -> None:
    """The explanation boundary too: no rejected text reaches evidence_detail.

    Both sides carry the *same* rejected website on purpose. Were rejection ignored, that
    agreement would be the strongest pair of signals this engine has — 42 + 40 — and the
    rejected URL would be quoted back in the evidence detail of both sides. Rejecting it
    on one side only would prove much less: a one-sided value cannot agree with anything.
    """
    def profile(platform: str) -> Finding:
        return _finding(
            platform,
            status="CONFIRMED",
            observed={
                "display_name": _row("Alice Observed"),
                "website": _row("https://rejected-secret.example/", rejected_by="test_rule"),
            },
        )

    pair = _pair(profile("GitHub"), profile("Instagram"))
    assert "same_display_name" in pair["evidence"]
    assert "same_personal_domain" not in pair["evidence"]
    assert "same_personal_url" not in pair["evidence"]
    assert pair["score"] == WEIGHTS["same_username"] + WEIGHTS["same_display_name"]
    # Neither the value nor its host is quoted anywhere in the explanation.
    assert "rejected-secret" not in json.dumps(pair)


# G + H. list authority, with and without items
def test_item_backed_link_values_are_authoritative_and_items_survive() -> None:
    """The row value is the contract's truthful projection of its items, so it is safe.

    B2-03B1 uses that projection for link membership and keeps the items in provenance for
    B2-03B3 to explain. It deliberately does not claim the row-level `source` describes
    every member — `"multiple"` names no extractor, and inventing per-link provenance here
    would be a false attribution.
    """
    items = [
        {
            "value": "https://alice.dev/",
            "original": "https://alice.dev/",
            "source": "github_api.blog",
            "observed_at": _OBSERVED_STAMP,
            "source_method": "JSON_API",
        },
        {
            "value": "https://x.com/alice",
            "original": "https://x.com/alice",
            "source": "html_rel_me",
            "observed_at": _OBSERVED_STAMP,
            "source_method": "HTML",
        },
    ]
    observed = {
        "social_links": {
            "value": ["https://alice.dev/", "https://x.com/alice"],
            "original": ["https://alice.dev/", "https://x.com/alice"],
            "source": "multiple",
            "observed_at": _OBSERVED_STAMP,
            "source_method": "MIXED",
            "items": items,
        }
    }
    record = _observed_record(observed, **_POISON)
    assert record.links == ["https://alice.dev/", "https://x.com/alice"]
    assert "https://poison.example/link" not in record.links
    stored = record.provenance["social_links"]["items"]
    assert [item["source"] for item in stored] == ["github_api.blog", "html_rel_me"]
    # Row-level aggregation marker preserved as itself, never copied onto a member.
    assert record.provenance["social_links"]["source"] == "multiple"


def test_a_legacy_list_row_without_items_is_still_authoritative() -> None:
    """Items are not retroactively required of a row written before they existed."""
    observed = {
        "external_links": {
            "value": ["https://alice.dev/", "https://alice.dev/blog"],
            "original": ["https://alice.dev/", "https://alice.dev/blog"],
            "source": "html_rel_me",
            "observed_at": _OBSERVED_STAMP,
        }
    }
    record = _observed_record(observed, **_POISON)
    assert record.links == ["https://alice.dev/", "https://alice.dev/blog"]
    assert "items" not in record.provenance["external_links"]


def test_duplicate_link_values_are_deduplicated_without_respelling() -> None:
    observed = {
        "external_links": _row(["https://alice.dev/", "https://ALICE.dev/"]),
        "social_links": _row(["https://alice.dev/", "https://x.com/alice"]),
    }
    record = _observed_record(observed)
    # Exact repeats collapse; two different spellings of one host stay two entries,
    # because normalizing a URL here would rewrite what the observer actually published.
    assert record.links == ["https://alice.dev/", "https://ALICE.dev/", "https://x.com/alice"]


# §9. consumer-incompatible shapes are suppressed, one field at a time
def test_a_scalar_field_carrying_a_list_is_suppressed_not_stringified() -> None:
    observed = {
        "display_name": _row(["Alice Observed"]),
        "organization": _row("Observed Labs"),
    }
    record = _observed_record(observed, **_POISON)
    assert record.display_name == ""
    assert "['Alice Observed']" not in record.display_name
    # The valid neighbour survives: one incompatible field is not a whole-mapping failure.
    assert record.organization == "Observed Labs"
    assert "display_name" in record.provenance


def test_a_list_field_carrying_a_scalar_is_not_wrapped_into_a_link() -> None:
    observed = {
        "social_links": _row("https://x.com/alice"),
        "external_links": _row(["https://alice.dev/"]),
    }
    record = _observed_record(observed, **_POISON)
    assert record.links == ["https://alice.dev/"]
    assert "https://x.com/alice" not in record.links
    assert "social_links" in record.provenance


def test_an_unknown_observed_field_name_is_not_rejected() -> None:
    """Forward compatibility: this slice constrains known shapes, not the name space."""
    observed = {"display_name": _row("Alice Observed"), "future_field": _row("whatever")}
    record = _observed_record(observed, **_POISON)
    assert record.display_name == "Alice Observed"
    assert record.provenance["future_field"]["value"] == "whatever"


def test_a_cross_profile_link_is_still_explained_coarsely() -> None:
    """B2-03B1 makes link *values* authoritative; it does not make the explanation exact.

    The row's `source` for a heterogeneous list is `"multiple"`, which names no extractor.
    Presenting it as the source of the link that matched would be a false attribution, so
    the explanation stays the coarse joined view with a blank source — and the items stay
    in provenance for B2-03B3 to name the extractor that actually observed the match.
    """
    target = "https://beta.example/alice"
    items = [
        {
            "value": target,
            "original": target,
            "source": "html_rel_me",
            "observed_at": _OBSERVED_STAMP,
            "source_method": "HTML",
        },
        {
            "value": "https://alice.dev/",
            "original": "https://alice.dev/",
            "source": "github_api.blog",
            "observed_at": _OBSERVED_STAMP,
            "source_method": "JSON_API",
        },
    ]
    linking = _finding(
        "AlphaSite",
        status="CONFIRMED",
        profile_url="https://alphasite.example/alice",
        observed={
            "social_links": {
                "value": [target, "https://alice.dev/"],
                "original": [target, "https://alice.dev/"],
                "source": "multiple",
                "observed_at": _OBSERVED_STAMP,
                "source_method": "MIXED",
                "items": items,
            }
        },
    )
    linked = _finding("Beta", status="CONFIRMED", profile_url=target, observed={})
    left = records_from_findings([linking])[0]
    pair = compare_records(left, records_from_findings([linked])[0])

    assert "cross_profile_link" in pair["evidence"]
    detail = next(row for row in pair["evidence_detail"] if row["code"] == "cross_profile_link")
    assert detail["left"]["value"] == f"{target}, https://alice.dev/"
    # Coarse on purpose: no extractor is named, and "multiple" is never presented as one.
    assert detail["left"]["source"] == ""
    assert detail["left"]["observed_at"] == ""
    # The per-member provenance B2-03B3 needs is preserved, untouched.
    assert [item["source"] for item in left.provenance["social_links"]["items"]] == [
        "html_rel_me",
        "github_api.blog",
    ]
    assert left.provenance["social_links"]["source"] == "multiple"


# ---------------------------------------------------------------------------
# Astra F1: the synthetic `links` explanation name must not read observed provenance.
#
# `_EVIDENCE_FIELDS` maps `cross_profile_link` onto `links`, an `IdentityRecord` attribute
# that is not a field this contract observes — and B2-03B1 deliberately permits unknown
# observed field names. A valid `observed["links"]` row therefore collided with that
# synthetic name and was quoted as the provenance of a matched URL it had nothing to do
# with. The score was always right; only the explanation lied.
# ---------------------------------------------------------------------------

_BETA_PROFILE = "https://beta.example/alice"
_UNRELATED = "https://unrelated.example/private"


def _linking_pair(alpha_observed: dict) -> tuple[object, dict]:
    """Alpha publicly links to Beta's profile. Returns Alpha's record and the pair."""
    alpha = _finding(
        "AlphaSite",
        status="CONFIRMED",
        profile_url="https://alpha.example/alice",
        observed=alpha_observed,
    )
    beta = _finding("Beta", status="CONFIRMED", profile_url=_BETA_PROFILE, observed={})
    left = records_from_findings([alpha])[0]
    return left, compare_records(left, records_from_findings([beta])[0])


def _link_detail(pair: dict) -> dict:
    return next(row for row in pair["evidence_detail"] if row["code"] == "cross_profile_link")


# F1-A. an unknown scalar `links` row cannot hijack the detail
def test_an_unknown_links_field_cannot_hijack_the_cross_profile_detail() -> None:
    left, pair = _linking_pair(
        {"social_links": _row([_BETA_PROFILE]), "links": _row(_UNRELATED)}
    )
    # The score was never wrong: membership comes from the real link fields.
    assert left.links == [_BETA_PROFILE]
    assert "cross_profile_link" in pair["evidence"]
    assert pair["score"] == WEIGHTS["same_username"] + WEIGHTS["cross_profile_link"]

    detail = _link_detail(pair)
    assert detail["left"]["value"] == ", ".join(left.links)
    assert detail["left"]["source"] == ""
    assert detail["left"]["observed_at"] == ""
    assert _UNRELATED not in json.dumps(pair)

    # Forward compatibility is untouched: the unknown row is still audit transport.
    assert left.provenance["links"]["value"] == _UNRELATED
    assert left.provenance["links"]["source"] == "github_api.field"


# F1-B. an unknown heterogeneous `links` row cannot emit the row-only "multiple" marker
def test_an_unknown_links_field_cannot_present_the_multiple_marker_as_a_source() -> None:
    """`"multiple"` names no extractor, so quoting it as one is the worst version of F1."""
    items = [
        {
            "value": _UNRELATED,
            "original": _UNRELATED,
            "source": "html_rel_me",
            "observed_at": _OBSERVED_STAMP,
            "source_method": "HTML",
        },
        {
            "value": "https://unrelated.example/other",
            "original": "https://unrelated.example/other",
            "source": "github_api.blog",
            "observed_at": _OBSERVED_STAMP,
            "source_method": "JSON_API",
        },
    ]
    left, pair = _linking_pair(
        {
            "social_links": _row([_BETA_PROFILE]),
            "links": {
                "value": [_UNRELATED, "https://unrelated.example/other"],
                "original": [_UNRELATED, "https://unrelated.example/other"],
                "source": "multiple",
                "observed_at": _OBSERVED_STAMP,
                "source_method": "MIXED",
                "items": items,
            },
        }
    )
    assert left.links == [_BETA_PROFILE]
    assert pair["score"] == WEIGHTS["same_username"] + WEIGHTS["cross_profile_link"]

    detail = _link_detail(pair)
    assert detail["left"]["value"] == ", ".join(left.links)
    assert detail["left"]["source"] == ""
    assert detail["left"]["observed_at"] == ""
    assert "multiple" not in json.dumps(pair)
    assert _UNRELATED not in json.dumps(pair)

    # Preserved verbatim for audit, marker and items included.
    assert left.provenance["links"]["source"] == "multiple"
    assert [item["source"] for item in left.provenance["links"]["items"]] == [
        "html_rel_me",
        "github_api.blog",
    ]


# F1-C. the synthetic route does not become a way around the active-membership gate
def test_the_synthetic_link_view_still_honours_the_active_membership_gate() -> None:
    """Routing `links` to `record.links` is safe *because* that list is already filtered.

    A rejected link field, a wrong-shaped one and an unknown one are all excluded from
    membership, so the coarse view cannot resurrect any of them — the synthetic branch
    reads a list the authority rules built, not the transport they filtered.
    """
    left, pair = _linking_pair(
        {
            "social_links": _row([_BETA_PROFILE]),
            "external_links": _row(["https://rejected.example/"], rejected_by="test_rule"),
            "links": _row(_UNRELATED),
        }
    )
    assert left.links == [_BETA_PROFILE]
    detail = _link_detail(pair)
    assert detail["left"]["value"] == _BETA_PROFILE
    assert "rejected.example" not in json.dumps(pair)
    assert _UNRELATED not in json.dumps(pair)

    # A wrong-shaped real link field is excluded the same way.
    scalar_shaped, pair2 = _linking_pair(
        {"social_links": _row([_BETA_PROFILE]), "external_links": _row("https://scalar.example/")}
    )
    assert scalar_shaped.links == [_BETA_PROFILE]
    assert "scalar.example" not in json.dumps(pair2)


def test_an_unknown_links_field_alone_supports_no_cross_profile_link() -> None:
    """It cannot create the evidence either — membership never consulted it."""
    left, pair = _linking_pair({"links": _row([_BETA_PROFILE])})
    assert left.links == []
    assert "cross_profile_link" not in pair["evidence"]
    assert pair["evidence"] == ["same_username"]
    assert left.provenance["links"]["value"] == [_BETA_PROFILE]


# F1-D. true legacy coarse behaviour is unchanged
def test_a_legacy_record_still_explains_its_joined_links_coarsely() -> None:
    alpha = _finding(
        "AlphaSite",
        status="CONFIRMED",
        profile_url="https://alpha.example/alice",
        public_links=[_BETA_PROFILE],
        website="https://alice.dev/",
    )
    assert "observed" not in alpha.data
    beta = _finding("Beta", status="CONFIRMED", profile_url=_BETA_PROFILE)
    left = records_from_findings([alpha])[0]
    pair = compare_records(left, records_from_findings([beta])[0])

    # Legacy links keep the compatibility website append, and the join reflects it.
    assert left.links == [_BETA_PROFILE, "https://alice.dev/"]
    assert "cross_profile_link" in pair["evidence"]
    detail = _link_detail(pair)
    assert detail["left"]["value"] == f"{_BETA_PROFILE}, https://alice.dev/"
    assert detail["left"]["source"] == ""
    assert detail["left"]["observed_at"] == ""
    # No provenance is fabricated for a legacy attribute.
    assert left.provenance == {}


# ---------------------------------------------------------------------------
# Astra F2: a validation diagnostic may not quote payload-controlled mapping keys.
#
# Pydantic's `loc` is not schema-only. For a `RootModel` over a dict the observed field
# name *is* a loc component, and `extra="forbid"` puts the offending key there too — so
# serializing locations published arbitrary transport keys into the operator's log. The
# diagnostic now reports a bounded error count plus the fixed pydantic type codes.
# ---------------------------------------------------------------------------

_NESTED_SECRET = "PRIVATE_PROFILE_TOKEN_DO_NOT_LOG@example.test"
_OUTER_SECRET = "OUTER_SECRET_FIELD_DO_NOT_LOG@example.test"
_VALUE_SECRET = "VALUE_SECRET_DO_NOT_LOG"


def _warn_on_invalid(observed: object, caplog: pytest.LogCaptureFixture) -> str:
    """Every log line records_from_findings() emits for one malformed finding."""
    caplog.clear()
    caplog.set_level(logging.DEBUG, logger="spectre.username")
    finding = _finding("GitHub", status="CONFIRMED", observed=observed)
    records = records_from_findings([finding])
    # Fails closed, and the checked profile is still a record.
    assert len(records) == 1
    assert records[0].platform == "GitHub"
    assert records[0].website == ""
    assert records[0].provenance == {}
    return "\n".join(record.getMessage() for record in caplog.records)


@pytest.mark.parametrize(
    ("label", "observed", "secret"),
    (
        # F2-A: an arbitrary extra key nested inside a known field row.
        (
            "nested extra key",
            {"website": {**_row("https://example.test"), _NESTED_SECRET: "extra"}},
            _NESTED_SECRET,
        ),
        # F2-B: the observed field name itself, on a row missing required keys.
        ("outer field name", {_OUTER_SECRET: {"value": "x"}}, _OUTER_SECRET),
        # F2-C: a secret in a payload value rather than a key.
        ("payload value", {"website": {"value": _VALUE_SECRET, "source": "s"}}, _VALUE_SECRET),
        # Shapes a key can take: unicode, URL-like, and long enough to have survived only
        # by being truncated rather than by policy.
        (
            "unicode key",
            {"website": {**_row("https://example.test"), "ключ_СЕКРЕТ_нелогировать": "x"}},
            "ключ_СЕКРЕТ_нелогировать",
        ),
        (
            "url shaped key",
            {"website": {**_row("https://example.test"), "https://secret.example/?tok=abc": "x"}},
            "https://secret.example/?tok=abc",
        ),
        (
            "long key",
            {"website": {**_row("https://example.test"), "L" + "0123456789" * 30: "x"}},
            "L" + "0123456789" * 30,
        ),
    ),
)
def test_a_validation_warning_never_quotes_the_transport(
    label: str, observed: object, secret: str, caplog: pytest.LogCaptureFixture
) -> None:
    text = _warn_on_invalid(observed, caplog)
    assert text, "a malformed payload must still be diagnosed"
    assert secret not in text
    # Still useful: the operator learns that validation failed and in what way.
    assert "observed enrichment failed validation" in text
    assert "GitHub" in text
    assert "validation error(s)" in text


def test_a_validation_warning_stays_bounded_and_deterministic(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Many errors, many secret keys, one short line built from a fixed vocabulary."""
    observed = {
        _OUTER_SECRET: {"value": "x"},
        "website": {**_row("https://example.test"), _NESTED_SECRET: "e"},
        "bio": {},
        "display_name": {"value": _VALUE_SECRET},
    }
    text = _warn_on_invalid(observed, caplog)
    for secret in (_OUTER_SECRET, _NESTED_SECRET, _VALUE_SECRET):
        assert secret not in text
    diagnostic = text.rsplit("profile record kept: ", 1)[1]
    assert diagnostic.startswith("11 validation error(s): ")
    # Deduplicated pydantic type codes, capped at three, no locations and no message.
    assert diagnostic == "11 validation error(s): missing, extra_forbidden"
    # Same payload, same line: nothing here depends on dict iteration of the transport.
    assert _warn_on_invalid(observed, caplog).rsplit("profile record kept: ", 1)[1] == diagnostic


@pytest.mark.parametrize("payload", (None, [], "malformed", 7))
def test_a_non_mapping_payload_is_diagnosed_by_exception_class_alone(
    payload: object, caplog: pytest.LogCaptureFixture
) -> None:
    """`str(exc)` is refused on principle, so this path names the class and nothing else."""
    text = _warn_on_invalid(payload, caplog)
    assert text.endswith("invalid observed transport (ValueError)")
    # The type name the old message interpolated is gone with it.
    assert "got NoneType" not in text
    assert "got list" not in text


# F1 + F2 interaction: forward compatibility survives both fixes.
def test_unknown_fields_stay_auditable_while_neither_explaining_nor_leaking(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Neither fix was bought by banning unknown observed field names.

    One finding keeps a valid unknown `links` row — available for audit, unable to reach
    the synthetic explanation. A second finding is malformed with a payload-controlled key.
    The valid unknown row survives; the malformed one's key never reaches the log.
    """
    left, pair = _linking_pair(
        {"social_links": _row([_BETA_PROFILE]), "links": _row(_UNRELATED)}
    )
    assert left.provenance["links"]["value"] == _UNRELATED
    assert _UNRELATED not in json.dumps(pair)

    text = _warn_on_invalid({_OUTER_SECRET: {"value": _UNRELATED}}, caplog)
    assert _OUTER_SECRET not in text
    assert _UNRELATED not in text
    assert "validation error(s)" in text


def test_a_link_matched_through_website_still_gets_a_coarse_empty_detail() -> None:
    """A pre-existing coarseness this pass documents rather than changes.

    `_link_points_at()` considers `record.website` alongside `record.links`, so a modern
    record whose observed website *is* the other profile scores `cross_profile_link` — and
    the coarse detail is then empty, because the modern `links` list deliberately excludes
    `website` (it is its own attribute). Nothing untrue is said: the explanation is silent,
    not misattributed, which is the difference from F1. Naming which observation supported
    the match is B2-03B3, so this is pinned as a known state rather than fixed here.
    """
    left, pair = _linking_pair({"website": _row(_BETA_PROFILE), "links": _row(_UNRELATED)})
    assert left.links == []
    assert left.website == _BETA_PROFILE
    assert "cross_profile_link" in pair["evidence"]
    assert pair["score"] == WEIGHTS["same_username"] + WEIGHTS["cross_profile_link"]

    detail = _link_detail(pair)
    assert detail["left"] == {"value": "", "source": "", "observed_at": ""}
    # Silent, and still not borrowing the unknown row.
    assert _UNRELATED not in json.dumps(pair)
    assert left.provenance["links"]["value"] == _UNRELATED
