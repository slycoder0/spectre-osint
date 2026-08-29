from __future__ import annotations

from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.scoring import score_investigation
from spectre_osint.core.types import Confidence, EntityType, FindingStatus


def _result(*findings: Finding) -> InvestigationResult:
    entity = Entity.create(EntityType.DOMAIN, "example.com", "test", Confidence.CONFIRMED)
    return InvestigationResult(
        case_id="c1",
        case_name="t",
        target="example.com",
        target_type=EntityType.DOMAIN,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[entity],
        findings=list(findings),
    )


def test_scores_are_independent() -> None:
    result = _result(
        Finding(
            module="url",
            title="heuristic",
            status=FindingStatus.INFERENCE,
            summary="INFERENCE",
            data={"heuristic_flags": ["punycode"]},
            confidence=Confidence.LOW,
        )
    )
    scores = score_investigation(result)
    assert scores.risk_level == "SUSPICIOUS"
    assert scores.risk_score != scores.confidence_score
    assert any("heuristic" in x.lower() for x in scores.risk_explain)


def test_username_score_does_not_mention_dns() -> None:
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id="u1",
        case_name="user-case",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user],
        findings=[
            Finding(
                module="username",
                title="Docker Hub",
                status=FindingStatus.FOUND,
                summary="Docker Hub: CONFIRMED https://hub.docker.com/u/alice_osint",
                data={
                    "platform": "Docker Hub",
                    "username": "alice_osint",
                    "check_status": "CONFIRMED",
                    "profile_url": "https://hub.docker.com/u/alice_osint",
                },
                confidence=Confidence.CONFIRMED,
            ),
            Finding(
                module="username",
                title="Instagram",
                status=FindingStatus.LOGIN_REQUIRED,
                summary="Instagram: LOGIN_REQUIRED",
                data={
                    "platform": "Instagram",
                    "username": "alice_osint",
                    "check_status": "LOGIN_REQUIRED",
                    "profile_url": "https://www.instagram.com/alice_osint/",
                },
            ),
        ],
    )
    scores = score_investigation(result)
    blob = " ".join(scores.confidence_explain + scores.risk_explain + scores.reputation_explain)
    assert "DNS" not in blob
    assert "RDAP" not in blob
    assert "CT" not in blob
    assert "confirmed_public_profiles" in scores.confidence_breakdown
    assert scores.confidence_breakdown["target_input"] == 20
    assert scores.confidence_score < 100


def test_score_does_not_use_other_case_entities() -> None:
    other = Entity.create(EntityType.DOMAIN, "example.com", "dns", Confidence.CONFIRMED)
    user = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id="u2",
        case_name="alice-case",
        target="alice",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user],
        findings=[],
    )
    scores = score_investigation(result)
    polluted = InvestigationResult(
        case_id="u2",
        case_name="alice-case",
        target="alice",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user, other],
        findings=[],
    )
    polluted_scores = score_investigation(polluted)
    assert scores.confidence_score == polluted_scores.confidence_score
    assert "DNS" not in " ".join(polluted_scores.confidence_explain)


def test_provider_detections_raise_risk_not_confidence_only() -> None:
    result = _result(
        Finding(
            module="virustotal",
            title="VT",
            status=FindingStatus.FOUND,
            summary="12 detections",
            data={"detections": 12},
            confidence=Confidence.HIGH,
        )
    )
    scores = score_investigation(result)
    assert scores.risk_score > 20
    assert scores.risk_level == "CONFIRMED_BY_PROVIDER"
