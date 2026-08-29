from __future__ import annotations

from fastapi.testclient import TestClient

from spectre_osint.core.case_manager import CaseManager
from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.presentation import username_rows
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.web.app import app


def _username_result(case_id: str, case_name: str) -> InvestigationResult:
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    return InvestigationResult(
        case_id=case_id,
        case_name=case_name,
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
    result = _username_result("c", "n")
    rows = username_rows(result)
    assert {r["platform"] for r in rows} == {"Instagram", "Docker Hub", "Bluesky", "GitHub"}
    assert all(r["platform"] for r in rows)
    assert all("LOGIN REQUIRED" != r["summary"] for r in rows)


def test_cli_and_gui_and_report_share_findings(tmp_path, capsys) -> None:
    from spectre_osint.cli.display import print_result
    from spectre_osint.reporting.html import write_html_report

    result = _username_result("c", "demo")
    print_result(result)
    cli = capsys.readouterr().out
    html = write_html_report(result, tmp_path).read_text(encoding="utf-8")
    for name in ("Instagram", "Docker Hub", "Bluesky"):
        assert name in cli
        assert name in html
    assert "LOGIN_REQUIRED" in cli
    assert "LOGIN_REQUIRED" in html
    assert "Platform" in cli


def test_investigation_detail_shows_platforms(settings) -> None:
    init_db(settings)
    manager = CaseManager()
    case = manager.create_unique("user-gbx")
    result = _username_result(case.id, case.name)
    run = manager.start_run(case.id, result.target, "USERNAME")
    result.run_id = run.id
    manager.persist_result(result)
    manager.finish_run(run.id, status="completed")
    with TestClient(app) as client:
        page = client.get(f"/investigations/{case.id}")
        assert page.status_code == 200
        body = page.text
        assert "Instagram" in body
        assert "LOGIN_REQUIRED" in body
        assert "Docker Hub" in body
        assert "Bluesky" in body
        assert "PROVIDER_UNAVAILABLE" in body
        assert "BLOCKED" in body
        assert 'target="_blank"' in body
        assert "https://www.instagram.com/alice_osint/" in body
        assert "<code>alice_osint</code>" in body
        assert "Refresh investigation" in body
        assert "has public profile" in body or "Relationships" in body
        filtered = client.get(f"/investigations/{case.id}?status=LOGIN_REQUIRED")
        assert "Instagram" in filtered.text
        dash = client.get("/")
        assert f"/investigations/{case.id}" in dash.text
    reset_engine()
