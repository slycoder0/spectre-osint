from __future__ import annotations

from fastapi.testclient import TestClient

from spectre_osint.core.case_manager import CaseManager
from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, Relationship, utcnow
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType
from spectre_osint.web.app import app
from spectre_osint.web.graph_view import aggregated_graph, graph_unchanged_backend


def _result() -> InvestigationResult:
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    profile = Entity.create(
        EntityType.SOCIAL_PROFILE,
        "https://www.last.fm/user/alice_osint",
        source="Last.fm",
        confidence=Confidence.HIGH,
        metadata={"site": "Last.fm", "username": "alice_osint"},
    )
    url = Entity.create(
        EntityType.URL,
        "https://www.last.fm/user/alice_osint",
        source="Last.fm",
        confidence=Confidence.HIGH,
    )
    domain = Entity.create(EntityType.DOMAIN, "last.fm", source="Last.fm", confidence=Confidence.MEDIUM)
    rels = [
        Relationship(
            from_entity_id=user.id,
            to_entity_id=profile.id,
            relation=RelationType.HAS_PROFILE,
            source="Last.fm",
            confidence=Confidence.HIGH,
        ),
        Relationship(
            from_entity_id=user.id,
            to_entity_id=url.id,
            relation=RelationType.LINKS_TO,
            source="Last.fm",
            confidence=Confidence.HIGH,
        ),
    ]
    finding = Finding(
        module="username",
        title="Last.fm",
        status=FindingStatus.FOUND,
        summary="Last.fm: LIKELY",
        data={
            "platform": "Last.fm",
            "username": "alice_osint",
            "check_status": "LIKELY",
            "profile_url": "https://www.last.fm/user/alice_osint",
            "reason": "canonical match",
        },
        confidence=Confidence.HIGH,
        entity_id=user.id,
    )
    return InvestigationResult(
        case_id="c",
        case_name="g",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user, profile, url, domain],
        findings=[finding],
        relationships=rels,
    )


def test_aggregation_does_not_mutate_backend() -> None:
    result = _result()
    before_e, before_r = graph_unchanged_backend(result)
    graph = aggregated_graph(result)
    after_e, after_r = graph_unchanged_backend(result)
    assert before_e == after_e
    assert before_r == after_r
    assert result.entities[1].normalized_value.startswith("https://")
    labels = {n["label"] for n in graph["nodes"]}
    assert "Last.fm" in labels
    assert "alice_osint" in labels
    assert not any("https://www.last.fm/user/alice_osint" == n["label"] for n in graph["nodes"])
    target = next(n for n in graph["nodes"] if n["kind"] == "target")
    assert target["label"] == "alice_osint"
    assert graph["filters"]["email"] is False
    assert graph["filters"]["OPERATOR_PROVIDED_ALIAS"] is False


def test_zero_one_many_nodes() -> None:
    empty = InvestigationResult(
        case_id="c",
        case_name="n",
        target="x",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
    )
    assert aggregated_graph(empty)["nodes"] == []
    one = InvestigationResult(
        case_id="c",
        case_name="n",
        target="x",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[Entity.create(EntityType.USERNAME, "x", "user", Confidence.CONFIRMED)],
    )
    graph = aggregated_graph(one)
    assert len(graph["nodes"]) == 1
    many = _result()
    assert len(aggregated_graph(many)["nodes"]) >= 2


def test_graph_page_has_fallback_and_escaping(settings) -> None:
    init_db(settings)
    manager = CaseManager()
    case = manager.create_unique("graph-case")
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
                title="Evil",
                status=FindingStatus.FOUND,
                summary="<script>alert(1)</script>",
                data={
                    "platform": "Last.fm",
                    "username": "alice_osint",
                    "check_status": "LIKELY",
                    "profile_url": "https://www.last.fm/user/alice_osint",
                    "reason": "<b>xss</b>",
                },
            )
        ],
    )
    run = manager.start_run(case.id, result.target, "USERNAME")
    result.run_id = run.id
    manager.persist_result(result)
    manager.finish_run(run.id, status="completed")
    with TestClient(app) as client:
        page = client.get(f"/investigations/{case.id}")
        assert page.status_code == 200
        assert "relationship-graph" in page.text
        assert "graph-data" in page.text
        assert "<noscript>" in page.text
        assert "<script>alert(1)</script>" not in page.text
        assert "data-graph-filter" in page.text
    reset_engine()
