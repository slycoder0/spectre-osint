from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from spectre_osint.core.case_manager import CaseManager
from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, Relationship, utcnow
from spectre_osint.core.exceptions import ValidationError
from spectre_osint.core.inputs import parse_target_inputs
from spectre_osint.core.types import Confidence, EntityType, FindingStatus, RelationType
from spectre_osint.modules.username.identity import correlate_identities
from spectre_osint.web.app import app


def test_primary_only_and_alias_dedupe() -> None:
    parsed = parse_target_inputs("Alice_osint")
    assert parsed.primary == "alice_osint"
    assert parsed.aliases == []
    two = parse_target_inputs(
        "alice_osint",
        aliases=["alice-sec", "alice-sec", "@alice_osint", "aliceexample"],
    )
    assert two.aliases == ["alice-sec", "aliceexample"]


def test_invalid_email_and_domain() -> None:
    with pytest.raises(ValidationError):
        parse_target_inputs("alice", email="not-an-email")
    with pytest.raises(ValidationError):
        parse_target_inputs("alice", website="%%%")
    empty = parse_target_inputs("alice", email="  ", website="")
    assert empty.email is None
    assert empty.website is None


def test_aliases_rejected_for_non_username() -> None:
    with pytest.raises(ValidationError):
        parse_target_inputs("example.com", aliases=["alice"])


@pytest.mark.asyncio
async def test_multi_alias_sweeps_are_sequential(monkeypatch, settings) -> None:
    from spectre_osint.core.entities import Entity
    from spectre_osint.core.pipeline import InvestigationRunner
    from spectre_osint.core.types import Confidence, EntityType

    current = 0
    peak = 0

    async def fake_analyze(entity, http, **kwargs):
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        await asyncio.sleep(0.02)
        current -= 1
        return {
            "findings": [],
            "entities": [entity],
            "relationships": [],
            "evidence": [],
            "providers_queried": ["username-sites"],
            "identity_correlation": None,
        }

    async def fake_mentions(*args, **kwargs):
        return {"findings": [], "entities": [], "evidence": [], "providers_queried": []}

    monkeypatch.setattr("spectre_osint.core.pipeline.analyze_username", fake_analyze)
    monkeypatch.setattr("spectre_osint.modules.username.engine.load_sites", lambda: [{"name": "GitHub"}] * 2)
    monkeypatch.setattr("spectre_osint.modules.mentions.collect_public_mentions", fake_mentions)
    runner = InvestigationRunner(settings=settings)
    try:
        entity = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)
        await runner._collect_username_bundle(
            entity,
            {"inputs": {"aliases": ["bob"], "primary": "alice"}, "refresh": False},
        )
    finally:
        await runner.close()
    assert peak == 1


def test_pairwise_gui_hides_zero_scores_by_default() -> None:
    from spectre_osint.core.presentation import identity_view

    result = InvestigationResult(
        case_id="c",
        case_name="n",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        identity_correlation={
            "records": 3,
            "max_score": 42,
            "clusters": [],
            "pairs": [
                {
                    "left": "Chess.com",
                    "right": "Docker Hub",
                    "left_username": "alice_osint",
                    "right_username": "alice_osint",
                    "score": 42,
                    "band": "POSSIBLE",
                    "evidence": ["same_personal_domain"],
                    "conflicts": [],
                },
                {
                    "left": "Chess.com",
                    "right": "Steam",
                    "left_username": "alice_osint",
                    "right_username": "alice-sec",
                    "score": 6,
                    "band": "LOW",
                    "evidence": ["same_username"],
                    "conflicts": [],
                },
            ],
            "unclustered": [],
        },
    )
    view = identity_view(result)
    assert [p["score"] for p in view["notable_pairs"]] == [42]
    assert "Chess.com (alice_osint)" in view["notable_pairs"][0]["left_label"]
    assert "Docker Hub (alice_osint)" in view["notable_pairs"][0]["right_label"]
    assert len(view["pairs"]) == 2
    assert all("same_username" not in (p.get("evidence") or []) or int(p["score"]) >= 10 or p.get("conflicts") or set(p.get("evidence") or []) - {"same_username"} for p in view["notable_pairs"])


def test_operator_alias_does_not_raise_identity_score() -> None:
    def finding(platform: str, username: str, **data: object) -> Finding:
        payload = {
            "platform": platform,
            "username": username,
            "check_status": "LIKELY",
            "profile_url": f"https://{platform.lower().replace(' ', '')}.example/{username}",
            **data,
        }
        return Finding(
            module="username",
            title=platform,
            status=FindingStatus.FOUND,
            summary=f"{platform}: LIKELY",
            data=payload,
            confidence=Confidence.HIGH,
        )

    payload = correlate_identities(
        [
            finding("GitHub", "alice_osint"),
            finding("Steam", "alice-sec"),
        ]
    )
    assert payload["max_score"] < 30
    assert payload["clusters"] == []
    assert any("alice_osint" in item or "GitHub" in item for item in payload["unclustered"])


def test_web_rejects_invalid_email(settings) -> None:
    init_db(settings)
    with TestClient(app) as client:
        response = client.post(
            "/investigate",
            data={"target": "alice", "mode": "new", "email": "bad"},
        )
        assert response.status_code == 400
    reset_engine()


def test_refresh_keeps_inputs(settings) -> None:
    init_db(settings)
    manager = CaseManager()
    case = manager.create_unique("in-case")
    user = Entity.create(EntityType.USERNAME, "alice", "user", Confidence.CONFIRMED)
    alias = Entity.create(EntityType.USERNAME, "bob", "operator", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id=case.id,
        case_name=case.name,
        target="alice",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        finished_at=utcnow(),
        entities=[user, alias],
        findings=[
            Finding(
                module="username",
                title="GitHub",
                status=FindingStatus.FOUND,
                summary="GitHub",
                data={"platform": "GitHub", "username": "alice", "check_status": "CONFIRMED"},
            )
        ],
        relationships=[
            Relationship(
                from_entity_id=user.id,
                to_entity_id=alias.id,
                relation=RelationType.OPERATOR_PROVIDED_ALIAS,
                source="operator",
                confidence=Confidence.LOW,
                metadata={"not_identity_evidence": True},
            )
        ],
        inputs={"primary": "alice", "aliases": ["bob"], "primary_type": "USERNAME"},
    )
    run = manager.start_run(case.id, result.target, "USERNAME")
    result.run_id = run.id
    manager.persist_result(result)
    manager.finish_run(run.id, status="completed", extra={"inputs": result.inputs})
    loaded = manager.load_result_by_id(case.id)
    assert loaded is not None
    assert loaded.inputs is not None
    assert loaded.inputs["aliases"] == ["bob"]
    with TestClient(app) as client:
        page = client.get(f"/investigations/{case.id}")
        assert "bob" in page.text
        assert "investigation leads" in page.text.lower() or "pistas de investigação" in page.text.lower() or "Target inputs" in page.text or "Entradas" in page.text
    reset_engine()
