"""Synthetic tests for deterministic username matching and lead provenance."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from spectre_osint.core.entities import Entity, InvestigationResult, utcnow
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.modules.mentions.engine import collect_public_mentions
from spectre_osint.modules.mentions.providers import RawMention
from spectre_osint.modules.search.discover import classify_discovered_profile
from spectre_osint.modules.search.engine import collect_search_intelligence
from spectre_osint.modules.search.planner import plan_queries
from spectre_osint.modules.search.summary import build_intelligence_summary
from spectre_osint.modules.username.identity import records_from_findings
from spectre_osint.modules.username.matching import (
    EXACT_MATCH,
    SIMILAR_CANDIDATE,
    UNRELATED,
    classify_username_match,
    normalize_username_for_matching,
)


def test_normalization_rules() -> None:
    assert normalize_username_for_matching("  @alice_shop  ") == "alice_shop"
    assert normalize_username_for_matching("@Alice_Shop") == "alice_shop"
    assert normalize_username_for_matching("alice") == "alice"
    assert normalize_username_for_matching("") == ""
    assert normalize_username_for_matching(None) == ""


def test_classify_exact_matches() -> None:
    # 1. @alice_shop == alice_shop
    assert classify_username_match("@alice_shop", "alice_shop") == EXACT_MATCH
    # 2. alice_shop == alice_shop
    assert classify_username_match("alice_shop", "alice_shop") == EXACT_MATCH
    # Case insensitivity
    assert classify_username_match("Alice_Shop", "alice_shop") == EXACT_MATCH
    assert classify_username_match("alice_shop", "@ALICE_SHOP") == EXACT_MATCH


def test_classify_similar_candidates() -> None:
    # 3. Numeric suffix
    assert classify_username_match("alice_shop", "alice_shop_1") == SIMILAR_CANDIDATE
    assert classify_username_match("alice_shop", "alice_shop1") == SIMILAR_CANDIDATE
    # 4. Separator variance
    assert classify_username_match("alice_shop", "alice-shop") == SIMILAR_CANDIDATE
    assert classify_username_match("alice_shop", "alice.shop") == SIMILAR_CANDIDATE
    assert classify_username_match("alice_shop", "aliceshop") == SIMILAR_CANDIDATE
    # 5. Token permutation
    assert classify_username_match("alice_shop", "shop_alice") == SIMILAR_CANDIDATE
    # 6. Common affixes
    assert classify_username_match("alice_shop", "alice_shop_official") == SIMILAR_CANDIDATE
    assert classify_username_match("alice_shop", "real_alice_shop") == SIMILAR_CANDIDATE
    assert classify_username_match("alice_shop", "alice_shop_dev") == SIMILAR_CANDIDATE


def test_classify_unrelated() -> None:
    # 7. Unrelated
    assert classify_username_match("alice_shop", "bob_shop") == UNRELATED
    assert classify_username_match("alice_shop", "charlie_smith") == UNRELATED
    assert classify_username_match("alice_shop", "") == UNRELATED
    assert classify_username_match("", "alice_shop") == UNRELATED
    assert classify_username_match(None, "alice_shop") == UNRELATED


def test_discovered_profile_classifies_exact_and_similar() -> None:
    exact = classify_discovered_profile(
        url="https://instagram.com/alice_shop",
        title="Alice Shop (@alice_shop) — Instagram",
        snippet="See posts from Alice Shop",
        username="alice_shop",
        known_hosts={"instagram.com"},
    )
    assert exact.is_candidate is True
    assert exact.match_type == EXACT_MATCH
    assert exact.observed_username == "alice_shop"
    assert exact.requested_username == "alice_shop"

    similar = classify_discovered_profile(
        url="https://instagram.com/alice_shop_1",
        title="Alice Shop (@alice_shop_1) — Instagram",
        snippet="See posts from Alice Shop",
        username="alice_shop",
        known_hosts={"instagram.com"},
    )
    assert similar.is_candidate is True
    assert similar.match_type == SIMILAR_CANDIDATE
    assert similar.observed_username == "alice_shop_1"
    assert similar.requested_username == "alice_shop"

    unrelated = classify_discovered_profile(
        url="https://instagram.com/bob_shop",
        title="Bob Shop (@bob_shop) — Instagram",
        snippet="See posts from Bob Shop",
        username="alice_shop",
        known_hosts={"instagram.com"},
    )
    assert unrelated.is_candidate is False
    assert unrelated.match_type == UNRELATED


def test_query_planner_preserves_originating_lead() -> None:
    leads = {
        "usernames": ["alice_main", "alice_shop"],
        "names": ["Alice Example"],
        "emails": ["alice@example.test"],
        "domains": [],
    }
    queries = plan_queries(leads)
    main_queries = [q for q in queries if q.originating_lead == "alice_main"]
    shop_queries = [q for q in queries if q.originating_lead == "alice_shop"]
    name_queries = [q for q in queries if q.originating_lead == "Alice Example"]
    email_queries = [q for q in queries if q.originating_lead == "alice@example.test"]

    assert len(main_queries) > 0
    assert len(shop_queries) > 0
    assert len(name_queries) > 0
    assert len(email_queries) > 0
    assert all(q.target_value == "alice_main" for q in main_queries if q.input_kind == "username")
    assert all(q.target_value == "alice_shop" for q in shop_queries if q.input_kind == "username")


@pytest.mark.asyncio
async def test_search_intelligence_distinguishes_similar_candidate() -> None:
    entity = Entity.create(EntityType.USERNAME, "alice_main", "user", Confidence.CONFIRMED)
    case_inputs = {
        "aliases": ["alice_shop"],
        "display_name": "Alice Example",
        "email": "alice@example.test",
    }

    class FakeProvider:
        name = "mock_search"

        def available(self, _settings: Any) -> bool:
            return True

        async def search(self, query: str, **kwargs: Any) -> list[RawMention]:
            if "alice_shop" in query:
                return [
                    RawMention(
                        title="Alice Shop (@alice_shop_1) — Instagram",
                        url="https://instagram.com/alice_shop_1",
                        snippet="Public profile for Alice Shop (@alice_shop_1)",
                        provider="mock_search",
                    )
                ]
            if "alice_main" in query:
                return [
                    RawMention(
                        title="alice_main — GitHub",
                        url="https://github.com/alice_main",
                        snippet="alice_main developer profile",
                        provider="mock_search",
                    )
                ]
            return []

    from unittest.mock import patch

    with patch("spectre_osint.modules.search.engine.default_search_providers", return_value=[FakeProvider()]):
        bundle = await collect_search_intelligence(
            entity,
            http=SimpleNamespace(),  # type: ignore[arg-type]
            settings=SimpleNamespace(search_query_budget=12, search_max_pivots=0, search_max_depth=0),  # type: ignore[arg-type]
            case_inputs=case_inputs,
        )

    discovered = [f for f in bundle["findings"] if (f.data or {}).get("kind") == "discovered_profile"]
    assert len(discovered) == 2

    # Verify similar candidate finding
    similar_finding = next(f for f in discovered if f.data.get("username") == "alice_shop_1")
    assert similar_finding.confidence == Confidence.LOW
    assert similar_finding.data["match_type"] == SIMILAR_CANDIDATE
    assert similar_finding.data["requested_username"] == "alice_shop"
    assert similar_finding.data["observed_username"] == "alice_shop_1"
    assert similar_finding.data["originating_lead"] == "alice_shop"
    assert similar_finding.data["candidate"] is True
    assert "Similar profile candidate" in similar_finding.summary
    assert "@alice_shop_1" in similar_finding.summary
    assert "lead: @alice_shop" in similar_finding.summary

    # Verify exact finding
    exact_finding = next(f for f in discovered if f.data.get("username") == "alice_main")
    assert exact_finding.data["match_type"] == EXACT_MATCH
    assert exact_finding.data["requested_username"] == "alice_main"
    assert exact_finding.data["observed_username"] == "alice_main"
    assert exact_finding.data["originating_lead"] == "alice_main"

    # Verify identity correlation strictly ignores search candidate findings
    records = records_from_findings(bundle["findings"])
    assert len(records) == 0

    # Build investigation result and check summary
    result = InvestigationResult(
        case_id="case-test-1",
        case_name="Test Case",
        mode="fast",
        started_at=utcnow(),
        target="alice_main",
        target_type=EntityType.USERNAME,
        findings=bundle["findings"],
        entities=bundle["entities"],
        inputs=case_inputs,
    )
    summary = build_intelligence_summary(result)
    assert summary["coverage"]["discovered_profiles"] == 2
    assert summary["coverage"]["exact_discovered_profiles"] == 1
    assert summary["coverage"]["similar_candidates"] == 1
    # observed_handles must NOT contain alice_shop_1
    assert "alice_shop_1" not in summary["observed_handles"]


@pytest.mark.asyncio
async def test_public_mentions_preserve_originating_lead_and_match_type() -> None:
    class FakeMentionProvider:
        name = "mock_mention"

        def available(self, _settings: Any) -> bool:
            return True

        async def search(self, query: str, **kwargs: Any) -> list[RawMention]:
            return [
                RawMention(
                    title="Discussion mentioning alice_shop",
                    url="https://news.example.com/item/101",
                    snippet="Check out alice_shop for details",
                    provider="mock_mention",
                )
            ]

    bundle = await collect_public_mentions(
        "alice_shop",
        http=SimpleNamespace(),  # type: ignore[arg-type]
        providers=[FakeMentionProvider()],  # type: ignore[list-item]
        originating_lead="alice_shop",
    )
    findings = bundle["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f.data["originating_lead"] == "alice_shop"
    assert f.data["requested_username"] == "alice_shop"
    assert f.data["observed_username"] == "alice_shop"
    assert f.data["match_classification"] == EXACT_MATCH
    assert f.status == FindingStatus.OBSERVED


def test_query_planner_single_username_preserves_order() -> None:
    queries = plan_queries({"usernames": ["alice_main"]}, budget=12)
    assert len(queries) == 4
    assert [q.text for q in queries] == ['"alice_main"', "@alice_main", "inurl:alice_main", '"alice_main" profile']
    assert all(q.originating_lead == "alice_main" for q in queries)


def test_query_planner_fairness_primary_and_three_aliases() -> None:
    leads = {
        "usernames": ["alice_main", "alice_shop", "alice_dev", "alice_store"],
    }
    queries = plan_queries(leads, budget=12)
    assert len(queries) == 12
    # Ensure all 4 leads get exactly 3 queries each with budget 12
    from collections import Counter
    counts = Counter(q.originating_lead for q in queries)
    assert counts["alice_main"] == 3
    assert counts["alice_shop"] == 3
    assert counts["alice_dev"] == 3
    assert counts["alice_store"] == 3
    # Ensure no lead got starved
    assert all(counts[k] > 0 for k in leads["usernames"])


def test_query_planner_budget_smaller_than_leads() -> None:
    leads = {"usernames": ["u1", "u2", "u3", "u4", "u5"]}
    queries = plan_queries(leads, budget=3)
    assert len(queries) == 3
    assert [q.originating_lead for q in queries] == ["u1", "u2", "u3"]
    assert [q.text for q in queries] == ['"u1"', '"u2"', '"u3"']


def test_query_planner_deduplicates_aliases() -> None:
    leads = {"usernames": ["alice_main", "alice_main", "@alice_main", "alice_shop"]}
    queries = plan_queries(leads, budget=12)
    leads_in_queries = set(q.originating_lead for q in queries)
    assert leads_in_queries == {"alice_main", "alice_shop"}
    texts = [q.text for q in queries]
    assert len(texts) == len(set(texts))


def test_query_planner_deterministic_ordering() -> None:
    leads = {
        "usernames": ["alice_main", "alice_shop"],
        "names": ["Alice Example"],
        "emails": ["alice@example.test"],
        "domains": ["example.test"],
    }
    q1 = plan_queries(leads, budget=12)
    q2 = plan_queries(leads, budget=12)
    assert [(q.query_type, q.originating_lead, q.text) for q in q1] == [
        (q.query_type, q.originating_lead, q.text) for q in q2
    ]


def test_query_planner_mixed_inputs_not_regressed() -> None:
    leads = {
        "usernames": ["alice_main", "alice_shop"],
        "names": ["Alice Example"],
        "emails": ["alice@example.test"],
        "domains": ["example.test"],
    }
    queries = plan_queries(leads, budget=12)
    assert len(queries) == 12
    types = set(q.query_type for q in queries)
    assert "username" in types
    assert "handle" in types
    assert "inurl" in types
    assert "profile" in types
    assert "name" in types
    assert "domain" in types
    assert "email" in types


def test_query_planner_one_username_with_email_domain_name_all_covered() -> None:
    leads = {
        "usernames": ["alice_main"],
        "names": ["Alice Example"],
        "emails": ["alice@example.test"],
        "domains": ["example.test"],
    }
    queries = plan_queries(leads, budget=12)
    assert len(queries) == 10
    kinds = set(q.input_kind for q in queries)
    assert kinds == {"username", "email", "domain", "name", "pair"}
    # Pass 1 base coverage queries
    pass1_texts = [q.text for q in queries[:4]]
    assert pass1_texts == ['"alice_main"', '"alice@example.test"', '"example.test"', '"Alice Example"']


def test_query_planner_four_usernames_with_email_domain_name_all_covered() -> None:
    leads = {
        "usernames": ["alice_main", "alice_shop", "alice_dev", "alice_store"],
        "names": ["Alice Example"],
        "emails": ["alice@example.test"],
        "domains": ["example.test"],
    }
    queries = plan_queries(leads, budget=12)
    assert len(queries) == 12
    # Ensure all 4 lead types received at least one query
    kinds = set(q.input_kind for q in queries)
    assert "username" in kinds
    assert "email" in kinds
    assert "domain" in kinds
    assert "name" in kinds
    # Confirm originating_leads
    orig_leads = set(q.originating_lead for q in queries)
    assert "alice_main" in orig_leads
    assert "alice_shop" in orig_leads
    assert "alice_dev" in orig_leads
    assert "alice_store" in orig_leads
    assert "alice@example.test" in orig_leads
    assert "example.test" in orig_leads
    assert "Alice Example" in orig_leads


def test_query_planner_paired_queries_only_when_budget_allows() -> None:
    leads = {
        "usernames": ["alice_main"],
        "names": ["Alice Example"],
        "emails": ["alice@example.test"],
        "domains": ["example.test"],
    }
    # Budget 4 allows only base coverage pass
    q_small = plan_queries(leads, budget=4)
    assert len(q_small) == 4
    assert [q.query_type for q in q_small] == ["username", "email", "domain", "name"]

    # Budget 12 allows depth and pair queries
    q_full = plan_queries(leads, budget=12)
    assert any(q.query_type == "pair" for q in q_full)
    assert any(q.query_type == "username_domain" for q in q_full)


def test_query_planner_strict_global_budget_ceiling() -> None:
    leads = {
        "usernames": [f"user_{i}" for i in range(20)],
        "names": [f"Name {i}" for i in range(10)],
        "emails": [f"user_{i}@example.test" for i in range(10)],
        "domains": [f"domain{i}.test" for i in range(10)],
    }
    queries = plan_queries(leads, budget=12)
    assert len(queries) == 12


def test_query_planner_budget_pressure_twenty_usernames_with_email_and_domain() -> None:
    leads = {
        "usernames": ["alice_main"] + [f"alias_{i:02d}" for i in range(1, 20)],
        "emails": ["alice@example.test"],
        "domains": ["example.test"],
    }
    queries = plan_queries(leads, budget=12)
    assert len(queries) == 12
    # Ensure primary username, email, and domain are present
    orig_leads = [q.originating_lead for q in queries]
    assert orig_leads[0] == "alice_main"
    assert "alice@example.test" in orig_leads
    assert "example.test" in orig_leads
    # Aliases use the remaining 9 slots
    alias_queries = [q for q in queries if q.originating_lead.startswith("alias_")]
    assert len(alias_queries) == 9


def test_query_planner_budget_pressure_budget_four() -> None:
    leads = {
        "usernames": ["alice_main"] + [f"alias_{i:02d}" for i in range(1, 20)],
        "emails": ["alice@example.test"],
        "domains": ["example.test"],
        "names": ["Alice Example"],
    }
    queries = plan_queries(leads, budget=4)
    assert len(queries) == 4
    assert [q.query_type for q in queries] == ["username", "email", "domain", "name"]
    assert [q.originating_lead for q in queries] == [
        "alice_main",
        "alice@example.test",
        "example.test",
        "Alice Example",
    ]


def test_query_planner_budget_pressure_budget_three() -> None:
    leads = {
        "usernames": ["alice_main"] + [f"alias_{i:02d}" for i in range(1, 20)],
        "emails": ["alice@example.test"],
        "domains": ["example.test"],
        "names": ["Alice Example"],
    }
    queries = plan_queries(leads, budget=3)
    assert len(queries) == 3
    assert [q.query_type for q in queries] == ["username", "email", "domain"]
    assert [q.originating_lead for q in queries] == [
        "alice_main",
        "alice@example.test",
        "example.test",
    ]


def test_query_planner_budget_pressure_multiple_emails_and_domains() -> None:
    leads = {
        "usernames": ["alice_main", "alice_shop"],
        "emails": ["alice@work.test", "alice@personal.test"],
        "domains": ["work.test", "personal.test"],
    }
    queries = plan_queries(leads, budget=6)
    assert len(queries) == 6
    # Round 0 & 1 should cover primary, alternating emails and domains, and alias
    orig_leads = [q.originating_lead for q in queries]
    assert orig_leads[0] == "alice_main"
    assert "alice@work.test" in orig_leads
    assert "work.test" in orig_leads
    assert "alice@personal.test" in orig_leads
    assert "personal.test" in orig_leads
    assert "alice_shop" in orig_leads
