from __future__ import annotations

from spectre_osint.core.entities import Entity, Finding, InvestigationResult, ScoreBreakdown, utcnow
from spectre_osint.core.presentation import username_rows
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.reporting.html import write_html_report


def _username_result() -> InvestigationResult:
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    return InvestigationResult(
        case_id="c",
        case_name="demo",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        finished_at=utcnow(),
        run_id=None,
        entities=[user],
        findings=[
            Finding(
                module="username",
                title="Instagram",
                status=FindingStatus.LOGIN_REQUIRED,
                summary="Instagram: LOGIN_REQUIRED https://www.instagram.com/alice_osint/",
                data={
                    "platform": "Instagram",
                    "username": "alice_osint",
                    "check_status": "LOGIN_REQUIRED",
                    "profile_url": "https://www.instagram.com/alice_osint/",
                    "reason": "login wall",
                    "http_status": 200,
                    "access_mode": "ANONYMOUS_PUBLIC",
                    "cache_state": "LIVE",
                },
            ),
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
                    "reason": "JSON identity",
                },
                confidence=Confidence.CONFIRMED,
                entity_id=user.id,
            ),
            Finding(
                module="username",
                title="Bluesky",
                status=FindingStatus.PROVIDER_UNAVAILABLE,
                summary="Bluesky: PROVIDER_UNAVAILABLE (timeout)",
                data={
                    "platform": "Bluesky",
                    "username": "alice_osint",
                    "check_status": "PROVIDER_UNAVAILABLE",
                    "profile_url": "https://bsky.app/profile/alice_osint",
                    "reason": "timeout",
                },
            ),
            Finding(
                module="username",
                title="GitHub",
                status=FindingStatus.BLOCKED,
                summary="GitHub: BLOCKED (HTTP 403)",
                data={
                    "platform": "GitHub",
                    "username": "alice_osint",
                    "check_status": "BLOCKED",
                    "profile_url": "https://github.com/alice_osint",
                    "http_status": 403,
                    "reason": "HTTP 403 blocked",
                },
            ),
        ],
        providers_queried=["username-sites"],
    )


def test_platform_present_on_every_username_row() -> None:
    rows = username_rows(_username_result())
    assert {r["platform"] for r in rows} == {"Instagram", "Docker Hub", "Bluesky", "GitHub"}
    assert all(r["platform"] for r in rows)
    assert all("LOGIN REQUIRED" != r["summary"] for r in rows)


def test_cli_and_report_share_findings(tmp_path, capsys) -> None:
    from spectre_osint.cli.display import print_result

    result = _username_result()
    print_result(result)
    cli = capsys.readouterr().out
    html = write_html_report(result, tmp_path).read_text(encoding="utf-8")
    for name in ("Instagram", "Docker Hub", "Bluesky"):
        assert name in cli
        assert name in html
    assert "LOGIN_REQUIRED" in cli
    assert "LOGIN_REQUIRED" in html
    assert "Platform" in cli


def test_html_report_contains_source_and_scores(tmp_path) -> None:
    entity = Entity.create(EntityType.DOMAIN, "example.com", "user", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id="c",
        case_name="demo",
        target="example.com",
        target_type=EntityType.DOMAIN,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        finished_at=utcnow(),
        entities=[entity],
        findings=[
            Finding(
                module="dns",
                title="DNS",
                status=FindingStatus.FOUND,
                summary="CONFIRMED A=1",
                confidence=Confidence.CONFIRMED,
            )
        ],
        scores=ScoreBreakdown(
            confidence_score=80,
            risk_score=5,
            reputation_score=70,
            confidence_explain=["test"],
            risk_explain=["test"],
            reputation_explain=["test"],
        ),
        providers_queried=["dns"],
    )
    path = write_html_report(result, tmp_path)
    html = path.read_text(encoding="utf-8")
    assert "example.com" in html
    assert "Confidence" in html
    assert "SPECTRE never invents facts" in html
