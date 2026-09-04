"""Offline identity correlation. Same username is not identity."""

from __future__ import annotations

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
