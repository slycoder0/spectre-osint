from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from spectre_osint.core.case_manager import CaseManager
from spectre_osint.core.database import init_db, reset_engine, session_scope
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, Relationship, utcnow
from spectre_osint.core.models import EntityRow
from spectre_osint.core.presentation import top_evidence_rows, username_rows
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType
from spectre_osint.web.app import app
from spectre_osint.web.jobs import create_job, reset_jobs, update_job


def _client(settings):
    init_db(settings)
    return TestClient(app)


def _persist_username_case(name: str = "user-gui", *, xss: bool = False, identity: bool = False) -> str:
    manager = CaseManager()
    case = manager.create_unique(name)
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    github = Entity.create(EntityType.SOCIAL_PROFILE, "github/alice_osint", "username", Confidence.CONFIRMED)
    findings = [
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
                "access_mode": "ANONYMOUS_PUBLIC",
            },
            confidence=Confidence.CONFIRMED,
            entity_id=user.id,
        ),
        Finding(
            module="username",
            title="Chess.com",
            status=FindingStatus.FOUND,
            summary="Chess.com: LIKELY",
            data={
                "platform": "Chess.com",
                "username": "alice_osint",
                "check_status": "LIKELY",
                "profile_url": "https://www.chess.com/member/alice_osint",
                "access_mode": "ANONYMOUS_PUBLIC",
                "confidence": "HIGH",
            },
            confidence=Confidence.HIGH,
            entity_id=user.id,
        ),
        Finding(
            module="username",
            title="Mystery",
            status=FindingStatus.INCONCLUSIVE,
            summary="Mystery: INCONCLUSIVE",
            data={
                "platform": "Mystery",
                "username": "alice_osint",
                "check_status": "INCONCLUSIVE",
                "profile_url": "https://mystery.example/alice_osint",
                "access_mode": "ANONYMOUS_PUBLIC",
            },
            confidence=Confidence.LOW,
        ),
    ]
    if xss:
        findings.append(
            Finding(
                module="username",
                title="Evil",
                status=FindingStatus.FOUND,
                summary="<script>alert(1)</script>",
                data={
                    "platform": "<img src=x onerror=alert(1)>",
                    "username": "alice_osint",
                    "check_status": "CONFIRMED",
                    "profile_url": "https://example.com/u/alice_osint",
                    "reason": "<b>raw-html</b>",
                    "access_mode": "ANONYMOUS_PUBLIC",
                },
                confidence=Confidence.CONFIRMED,
            )
        )
    relationships = [
        Relationship(
            from_entity_id=user.id,
            to_entity_id=github.id,
            relation=RelationType.HAS_PROFILE,
            source="username",
            confidence=Confidence.CONFIRMED,
        )
    ]
    identity_payload = None
    if identity:
        identity_payload = {
            "records": 2,
            "max_score": 82,
            "clusters": [
                {
                    "id": "cluster-gui",
                    "band": "STRONG",
                    "score": 82,
                    "platforms": ["Docker Hub", "Chess.com"],
                    "evidence": ["same_personal_domain"],
                    "conflicts": [],
                    "profiles": [
                        {
                            "platform": "Docker Hub",
                            "username": "alice_osint",
                            "profile_url": "https://hub.docker.com/u/alice_osint",
                        },
                        {
                            "platform": "Chess.com",
                            "username": "alice_osint",
                            "profile_url": "https://www.chess.com/member/alice_osint",
                        },
                    ],
                }
            ],
            "pairs": [
                {
                    "left": "Chess.com",
                    "right": "Docker Hub",
                    "score": 82,
                    "band": "STRONG",
                    "evidence": ["same_personal_domain"],
                    "conflicts": [],
                }
            ],
            "unclustered": ["Instagram"],
            "notes": ["Same username is a weak signal and is never sufficient for identity."],
        }
        findings.append(
            Finding(
                module="username",
                title="Identity correlation",
                status=FindingStatus.FOUND,
                summary="1 public identity cluster(s); max pairwise score 82",
                data=identity_payload,
                confidence=Confidence.MEDIUM,
                entity_id=user.id,
            )
        )
    result = InvestigationResult(
        case_id=case.id,
        case_name=case.name,
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        finished_at=utcnow(),
        entities=[user, github],
        findings=findings,
        relationships=relationships,
        identity_correlation=identity_payload,
        providers_queried=["username-sites"],
    )
    run = manager.start_run(case.id, result.target, "USERNAME")
    result.run_id = run.id
    manager.persist_result(result)
    manager.finish_run(run.id, status="completed")
    return case.id


def test_default_language_english(settings) -> None:
    with _client(settings) as client:
        home = client.get("/")
        assert home.status_code == 200
        assert 'lang="en"' in home.text
        assert "Dashboard" in home.text
        assert "Painel" not in home.text
        assert "Investigations" in home.text
        nav = client.get("/investigations")
        assert "Investigations" in nav.text
    reset_engine()


def test_switch_english_to_portuguese_and_persist(settings) -> None:
    with _client(settings) as client:
        switched = client.get("/prefs?lang=pt-BR&next=/", follow_redirects=True)
        assert switched.status_code == 200
        assert 'lang="pt-BR"' in switched.text
        assert "Painel" in switched.text
        assert "Investigações" in switched.text
        persist = client.get("/entities")
        assert persist.status_code == 200
        assert "Entidades" in persist.text
        assert 'lang="pt-BR"' in persist.text
        back = client.get("/prefs?lang=en&next=/", follow_redirects=True)
        assert "Dashboard" in back.text
    reset_engine()


def test_gui_examples_are_synthetic(settings) -> None:
    init_db(settings)
    with TestClient(app) as client:
        home = client.get("/").text
        assert "alice_osint" in home
        assert "alice-sec" in home
        assert "Alice Example" in home
    reset_engine()


def test_composite_form_i18n(settings) -> None:
    init_db(settings)
    with TestClient(app) as client:
        home = client.get("/")
        assert "Additional inputs are investigation leads, not identity confirmation." in home.text
        pt = client.get("/prefs?lang=pt-BR&next=/", follow_redirects=True)
        assert "Entradas adicionais são pistas de investigação, não confirmação de identidade." in pt.text
    reset_engine()


def test_default_theme_dark_and_persist_light(settings) -> None:
    with _client(settings) as client:
        home = client.get("/")
        assert 'data-theme="dark"' in home.text
        assert "prefers-color-scheme" not in home.text
        light = client.get("/prefs?theme=light&next=/", follow_redirects=True)
        assert 'data-theme="light"' in light.text
        again = client.get("/sessions")
        assert 'data-theme="light"' in again.text
    reset_engine()


def test_investigation_overview_identity_graph_and_badges(settings) -> None:
    init_db(settings)
    case_id = _persist_username_case("user-overview", identity=True)
    with TestClient(app) as client:
        page = client.get(f"/investigations/{case_id}")
        body = page.text
        assert page.status_code == 200
        assert "Intelligence summary" in body
        assert "Key findings" in body
        assert "Identity Correlation" in body
        assert "Correlation is not civil identity confirmation." in body
        assert "pair-notable" in body
        assert "Show all pairs" in body
        assert "cluster-gui" in body
        assert "STRONG" in body
        assert "82" in body
        assert "relationship-graph" in body
        assert "badge-CONFIRMED" in body
        assert "badge-LOGIN_REQUIRED" in body
        assert "badge-ANONYMOUS_PUBLIC" in body
        assert "evidence-hit CONFIRMED" in body
        assert "evidence-hit INCONCLUSIVE" not in body
        assert "Mystery" in body
        pt = client.get("/prefs?lang=pt-BR&next=/investigations/" + case_id, follow_redirects=True)
        assert "Correlação não é confirmação de identidade civil." in pt.text
        assert "Resumo de inteligência" in pt.text
    reset_engine()


def test_mentions_grouped_by_input_and_excluded_from_top_evidence(settings) -> None:
    init_db(settings)
    manager = CaseManager()
    case = manager.create_unique("user-mentions-gui")
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id=case.id,
        case_name=case.name,
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        finished_at=utcnow(),
        entities=[user],
        findings=[
            Finding(
                module="username",
                title="GitHub",
                status=FindingStatus.FOUND,
                summary="GitHub",
                data={
                    "platform": "GitHub",
                    "username": "alice_osint",
                    "check_status": "CONFIRMED",
                    "profile_url": "https://github.com/alice_osint",
                    "access_mode": "ANONYMOUS_PUBLIC",
                },
                confidence=Confidence.CONFIRMED,
            ),
            Finding(
                module="mentions",
                title="Public mention",
                status=FindingStatus.OBSERVED,
                summary="OBSERVED",
                data={
                    "query": "alice_osint",
                    "kind": "username",
                    "provider": "hn-algolia",
                    "title": "Thread about alice_osint",
                    "snippet": "user alice_osint posted",
                    "url": "https://news.ycombinator.com/item?id=1",
                    "canonical_url": "https://news.ycombinator.com/item?id=1",
                    "matched_value": "alice_osint",
                    "confidence": "LOW",
                    "domain": "news.ycombinator.com",
                },
                confidence=Confidence.LOW,
            ),
            Finding(
                module="mentions",
                title="Public mention",
                status=FindingStatus.OBSERVED,
                summary="OBSERVED",
                data={
                    "query": "Alice Example",
                    "kind": "name",
                    "provider": "duckduckgo-html",
                    "title": "Alice Example spoke",
                    "snippet": "Alice Example spoke at a conference",
                    "url": "https://example.net/talk",
                    "canonical_url": "https://example.net/talk",
                    "matched_value": "Alice Example",
                    "confidence": "LOW",
                    "domain": "example.net",
                },
                confidence=Confidence.LOW,
            ),
            Finding(
                module="username",
                title="Identity correlation",
                status=FindingStatus.FOUND,
                summary="pairs",
                data={
                    "records": 2,
                    "max_score": 6,
                    "clusters": [],
                    "pairs": [
                        {
                            "left": "GitHub",
                            "right": "Docker Hub",
                            "score": 6,
                            "band": "LOW",
                            "evidence": ["same_username"],
                            "conflicts": [],
                        }
                    ],
                    "unclustered": [],
                },
                confidence=Confidence.LOW,
            ),
        ],
    )
    run = manager.start_run(case.id, result.target, "USERNAME")
    result.run_id = run.id
    manager.persist_result(result)
    manager.finish_run(run.id, status="completed")
    with TestClient(app) as client:
        body = client.get(f"/investigations/{case.id}").text
        assert "alice_osint — 1 mentions" in body
        assert "Alice Example — 1 mentions" in body
        assert "PUBLIC MENTION" in body
        assert "PROFILE HIT" in body
        assert "Hacker News" in body or "hn-algolia" in body
        assert "<mark>alice_osint</mark>" in body
        assert "posted" in body
        assert "evidence-hit" in body
        assert "Public mention" not in body.split("Key findings")[1].split("Identity Correlation")[0]
        notable = body.split("pair-notable")[1].split("all-pairs")[0]
        assert "GitHub ↔ Docker Hub" not in notable
        assert "Show all pairs" in body
        assert "same_username" in body.split("all-pairs")[1]
    reset_engine()


def test_top_evidence_skips_inconclusive_when_confirmed_exists() -> None:
    result = InvestigationResult(
        case_id="c",
        case_name="n",
        target="alice",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        findings=[
            Finding(
                module="username",
                title="A",
                status=FindingStatus.FOUND,
                summary="A",
                data={"platform": "GitHub", "check_status": "CONFIRMED", "username": "alice"},
            ),
            Finding(
                module="username",
                title="B",
                status=FindingStatus.INCONCLUSIVE,
                summary="B",
                data={"platform": "Mystery", "check_status": "INCONCLUSIVE", "username": "alice"},
            ),
        ],
    )
    top = top_evidence_rows(username_rows(result))
    assert [row["platform"] for row in top] == ["GitHub"]


def test_provider_strings_are_escaped(settings) -> None:
    init_db(settings)
    case_id = _persist_username_case("user-xss", xss=True)
    with TestClient(app) as client:
        body = client.get(f"/investigations/{case_id}").text
        assert "<script>alert(1)</script>" not in body
        assert "<img src=x onerror=alert(1)>" not in body
        assert "<b>raw-html</b>" not in body
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
        assert "&lt;img src=x onerror=alert(1)&gt;" in body
        assert "&lt;b&gt;raw-html&lt;/b&gt;" in body
    reset_engine()


def test_entities_latest_vs_historical(settings) -> None:
    init_db(settings)
    manager = CaseManager()
    case = manager.create_unique("hist-case")
    user = Entity.create(EntityType.USERNAME, "olduser", "user", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id=case.id,
        case_name=case.name,
        target="olduser",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        finished_at=utcnow(),
        entities=[user],
        findings=[
            Finding(
                module="username",
                title="GitHub",
                status=FindingStatus.FOUND,
                summary="GitHub",
                data={"platform": "GitHub", "check_status": "CONFIRMED", "username": "olduser"},
                entity_id=user.id,
            )
        ],
    )
    run = manager.start_run(case.id, result.target, "USERNAME")
    result.run_id = run.id
    manager.persist_result(result)
    manager.finish_run(run.id, status="completed")
    stale = datetime.now(UTC) - timedelta(days=9)
    with session_scope() as session:
        row = session.get(EntityRow, f"{case.id}:{user.id}")
        assert row is not None
        row.first_seen = stale
        row.last_seen = stale
    later = Entity.create(EntityType.USERNAME, "newuser", "user", Confidence.CONFIRMED)
    result2 = InvestigationResult(
        case_id=case.id,
        case_name=case.name,
        target="newuser",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        finished_at=utcnow(),
        entities=[later],
        findings=[
            Finding(
                module="username",
                title="GitHub",
                status=FindingStatus.FOUND,
                summary="GitHub",
                data={"platform": "GitHub", "check_status": "CONFIRMED", "username": "newuser"},
                entity_id=later.id,
            )
        ],
    )
    run2 = manager.start_run(case.id, result2.target, "USERNAME")
    result2.run_id = run2.id
    manager.persist_result(result2)
    manager.finish_run(run2.id, status="completed")
    with TestClient(app) as client:
        all_rows = client.get("/entities?observation=ALL")
        assert all_rows.status_code == 200
        assert "olduser" in all_rows.text
        assert "newuser" in all_rows.text
        assert "Historical" in all_rows.text or "Superseded" in all_rows.text
        latest = client.get("/entities?observation=LATEST")
        assert "newuser" in latest.text
        historical = client.get("/entities?observation=HISTORICAL")
        assert "olduser" in historical.text
        assert "First seen" in all_rows.text
        assert "Last seen" in all_rows.text
    reset_engine()


def test_loading_indeterminate_has_no_fake_percent(settings) -> None:
    reset_jobs()
    init_db(settings)
    job = create_job(target="alice", mode="new", target_type="USERNAME")
    with TestClient(app) as client:
        page = client.get(f"/collecting/{job.id}")
        assert page.status_code == 200
        assert "COLLECTING PUBLIC INTELLIGENCE" in page.text.upper() or "Collecting public intelligence" in page.text
        assert 'data-progress-kind="indeterminate"' in page.text
        assert "73%" not in page.text
        assert "46%" not in page.text
        assert "sources processed" not in page.text
    reset_jobs()
    reset_engine()


def test_loading_real_progress_is_counts_not_percent(settings) -> None:
    reset_jobs()
    init_db(settings)
    job = create_job(target="alice", mode="new", target_type="USERNAME")
    update_job(
        job.id,
        {
            "phase": "collecting",
            "done": 18,
            "total": 39,
            "source": "GitHub",
            "source_status": "CONFIRMED",
        },
    )
    with TestClient(app) as client:
        page = client.get(f"/collecting/{job.id}")
        assert "18" in page.text
        assert "39" in page.text
        assert "GitHub" in page.text
        assert "73%" not in page.text
        assert "46%" not in page.text
        assert 'data-progress-kind="determinate"' in page.text
    reset_jobs()
    reset_engine()


def test_loading_complete_and_failed(settings) -> None:
    reset_jobs()
    init_db(settings)
    manager = CaseManager()
    case = manager.create_unique("done-case")
    done = create_job(target="alice", mode="new")
    update_job(done.id, {"status": "complete", "phase": "complete", "case_id": case.id})
    failed = create_job(target="bob", mode="new")
    update_job(failed.id, {"status": "failed", "phase": "failed", "error": "provider timeout"})
    with TestClient(app) as client:
        redirect = client.get(f"/collecting/{done.id}", follow_redirects=False)
        assert redirect.status_code == 303
        assert f"/investigations/{case.id}" in redirect.headers["location"]
        boom = client.get(f"/collecting/{failed.id}")
        assert boom.status_code == 200
        assert "FAILED" in boom.text
        assert "provider timeout" in boom.text
        assert "is-failed" in boom.text
    reset_jobs()
    reset_engine()


def test_investigate_redirects_to_collecting(settings, monkeypatch) -> None:
    init_db(settings)
    monkeypatch.setattr("spectre_osint.web.app.execute_job", lambda job_id: None)
    with TestClient(app) as client:
        response = client.post("/investigate", data={"target": "alice_osint", "mode": "new"}, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/collecting/")
    reset_jobs()
    reset_engine()


def test_home_alias_field_is_an_input(settings) -> None:
    init_db(settings)
    with TestClient(app) as client:
        home = client.get("/").text
        assert 'data-chip-input' in home
        assert "Add an alias, nickname, or handle" in home
        assert "alice-sec" in home
        css = client.get("/static/style.css").text
        assert "background-size: 0" not in css.split(".btn-primary")[1].split(".btn-secondary")[0]
        assert ".btn-primary:hover:not(:disabled)" in css
        assert ".btn-primary:disabled" in css
    reset_engine()


def test_graph_js_opens_drawer_on_click_not_drag() -> None:
    from pathlib import Path

    src = Path("spectre_osint/web/static/graph.js").read_text(encoding="utf-8")
    down = src.split('g.addEventListener("pointerdown"')[1].split("g.addEventListener")[0]
    assert "select(node)" not in down
    assert "DRAG_THRESHOLD" in src
    assert "drag.moved" in src
    assert "select(drag.node)" in src


def test_technical_table_does_not_break_urls(settings) -> None:
    init_db(settings)
    case_id = _persist_username_case("user-urls")
    with TestClient(app) as client:
        body = client.get(f"/investigations/{case_id}").text
        assert "tech-table" in body
        assert "table-scroll" in body
        css = client.get("/static/style.css").text
        assert ".tech-table" in css
        assert "min-width: 1100px" in css
        assert "text-overflow: ellipsis" in css
        assert "scroll-margin-top" in css
        assert "word-break: normal" in css
        assert "white-space: nowrap" in css
        main = css[css.find(".url-cell {\n") :]
        main = main[: main.find(".tech-table")]
        assert "break-all" not in main
        assert "ellipsis" in main
    reset_engine()
