"""Offline identity correlation. Same username is not identity."""

from __future__ import annotations

from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.modules.username.identity import (
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
