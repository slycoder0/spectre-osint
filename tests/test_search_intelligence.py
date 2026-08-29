from __future__ import annotations

from types import SimpleNamespace

import pytest

from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.scoring import score_investigation
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.modules.search.discover import classify_discovered_profile, username_in_path
from spectre_osint.modules.search.engine import SearchEngine, collect_search_intelligence
from spectre_osint.modules.search.extract import extract_indicators
from spectre_osint.modules.search.pivots import propose_pivots
from spectre_osint.modules.search.planner import plan_queries
from spectre_osint.modules.search.providers import SearxngProvider, is_loopback_searxng
from spectre_osint.modules.search.summary import build_intelligence_summary
from spectre_osint.modules.username.identity import (
    BANDS,
    CLUSTER_MIN,
    WEIGHTS,
    records_from_findings,
)


def test_query_planner_dedupes_and_respects_budget() -> None:
    queries = plan_queries(
        {
            "usernames": ["roceiroviajante", "roceiroviajante"],
            "names": ["Italo Garcia Alves"],
            "domains": ["example.com"],
            "emails": ["italo@example.com"],
        },
        budget=12,
    )
    texts = [item.text for item in queries]
    assert len(texts) == len(set(t.lower() for t in texts))
    assert len(queries) <= 12
    assert any(item.query_type == "username" for item in queries)
    assert any(item.query_type == "inurl" for item in queries)
    assert any(item.query_type == "pair" for item in queries)
    assert any('"Italo Garcia Alves"' in item.text for item in queries)
    assert any(item.query_type == "email" for item in queries)


def test_query_planner_is_deterministic() -> None:
    leads = {"usernames": ["alice_osint"], "names": ["Alice Example"], "emails": [], "domains": []}
    assert plan_queries(leads) == plan_queries(leads)


def test_searxng_unconfigured_is_loopback_only() -> None:
    assert is_loopback_searxng("http://127.0.0.1:8080")
    assert is_loopback_searxng("http://localhost:8888")
    assert not is_loopback_searxng("https://searx.example.com")
    assert not is_loopback_searxng("")
    settings = SimpleNamespace(searxng_url=None)
    assert SearxngProvider().available(settings) is False


@pytest.mark.asyncio
async def test_searxng_configured_uses_json_api() -> None:
    captured: dict[str, object] = {}

    class FakeHttp:
        async def get(self, url, **kwargs):
            captured["url"] = url
            captured["params"] = kwargs.get("params")
            captured["ssrf"] = kwargs.get("ssrf")
            return SimpleNamespace(
                json_data={
                    "results": [
                        {
                            "title": "Forum user roceiroviajante",
                            "url": "https://forum.example.com/users/roceiroviajante",
                            "content": "profile of roceiroviajante",
                        }
                    ]
                }
            )

    settings = SimpleNamespace(searxng_url="http://127.0.0.1:8080")
    hits = await SearxngProvider().search("roceiroviajante", http=FakeHttp(), settings=settings, limit=5)
    assert captured["url"] == "http://127.0.0.1:8080/search"
    assert captured["params"]["format"] == "json"
    assert captured["ssrf"] is False
    assert hits[0].url.endswith("/users/roceiroviajante")


def test_username_in_path_is_candidate_not_confirmed() -> None:
    ok, relevance = classify_discovered_profile(
        url="https://forum.example.com/users/roceiroviajante",
        title="roceiroviajante — profile",
        snippet="Public profile for roceiroviajante",
        username="roceiroviajante",
        known_hosts=set(),
    )
    assert ok is True
    assert relevance == "DIRECT"


def test_name_only_search_is_not_a_profile() -> None:
    ok, relevance = classify_discovered_profile(
        url="https://news.example.com/story/123",
        title="Italo Garcia Alves spoke at a conference",
        snippet="Italo Garcia Alves spoke at a conference",
        username="roceiroviajante",
        known_hosts=set(),
    )
    assert ok is False
    assert relevance == ""
    assert username_in_path("roceiroviajante", "https://news.example.com/story/123") is False


def test_associated_requires_second_indicator_on_page() -> None:
    from spectre_osint.modules.mentions.relevance import classify_mention

    leads = {
        "usernames": ["roceiroviajante"],
        "names": ["Italo Garcia Alves"],
        "emails": [],
        "domains": [],
    }
    associated, reason, values = classify_mention(
        "name",
        "full_name",
        title="Italo Garcia Alves (@roceiroviajante)",
        snippet="Italo Garcia Alves on Instagram @roceiroviajante",
        url="https://example.net/post",
        case_inputs=leads,
    )
    assert associated == "ASSOCIATED"
    assert values
    ambiguous, _, empty = classify_mention(
        "name",
        "full_name",
        title="Italo Garcia Alves spoke",
        snippet="A talk by Italo Garcia Alves",
        url="https://example.net/talk",
        case_inputs=leads,
    )
    assert ambiguous == "AMBIGUOUS"
    assert empty == []


def test_ambiguous_does_not_raise_username_score() -> None:
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    base = InvestigationResult(
        case_id="c",
        case_name="n",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user],
        findings=[
            Finding(
                module="username",
                title="GitHub",
                status=FindingStatus.FOUND,
                summary="CONFIRMED",
                data={"platform": "GitHub", "check_status": "CONFIRMED", "username": "alice_osint"},
            )
        ],
    )
    extra = list(base.findings) + [
        Finding(
            module="mentions",
            title="Public mention",
            status=FindingStatus.OBSERVED,
            summary="AMBIGUOUS",
            data={"relevance": "AMBIGUOUS", "kind": "name", "query": "Alice Example"},
        ),
        Finding(
            module="search",
            title="Discovered profile",
            status=FindingStatus.OBSERVED,
            summary="candidate",
            data={
                "kind": "discovered_profile",
                "check_status": "INCONCLUSIVE",
                "username": "alice_osint",
                "host": "forum.example.com",
            },
        ),
    ]
    with_mention = base.model_copy(update={"findings": extra})
    assert score_investigation(base).confidence_score == score_investigation(with_mention).confidence_score


def test_public_mention_and_discovered_stay_out_of_identity_records() -> None:
    findings = [
        Finding(
            module="mentions",
            title="Public mention",
            status=FindingStatus.OBSERVED,
            summary="x",
            data={"platform": "News", "check_status": "OBSERVED", "username": "alice_osint"},
        ),
        Finding(
            module="search",
            title="Discovered profile",
            status=FindingStatus.OBSERVED,
            summary="x",
            data={"check_status": "LIKELY", "username": "alice_osint", "platform": "discovered", "kind": "discovered_profile"},
        ),
        Finding(
            module="username",
            title="GitHub",
            status=FindingStatus.FOUND,
            summary="x",
            data={"check_status": "CONFIRMED", "username": "alice_osint", "platform": "GitHub"},
        ),
    ]
    records = records_from_findings(findings)
    assert [row.platform for row in records] == ["GitHub"]


def test_pivot_dedupe_max_depth_and_budget() -> None:
    indicators = [
        {"indicator_type": "username", "value": "alice_osint", "extraction_rule": "bio_handle"},
        {"indicator_type": "username", "value": "alice_osint", "extraction_rule": "discovered_profile_username"},
        {"indicator_type": "domain", "value": "alice.example", "extraction_rule": "website"},
        {"indicator_type": "domain", "value": "https://alice.example", "extraction_rule": "website"},
    ]
    known = {("username", "alice_osint")}
    rows = propose_pivots(indicators=indicators, known=known, source="instagram", depth=1, remaining=25)
    accepted = [row for row in rows if row["accepted"]]
    rejected = [row for row in rows if not row["accepted"]]
    assert any(row["reject_reason"] == "duplicate" for row in rejected)
    assert len(accepted) == 1
    assert accepted[0]["type"] == "domain"
    limited = propose_pivots(indicators=indicators, known=set(), source="instagram", depth=2, remaining=1)
    assert sum(1 for row in limited if row["accepted"]) == 1


def test_operator_alias_is_not_extracted_as_observed_handle() -> None:
    finding = Finding(
        module="username",
        title="GitHub",
        status=FindingStatus.FOUND,
        summary="CONFIRMED",
        data={
            "platform": "GitHub",
            "check_status": "CONFIRMED",
            "username": "alice_osint",
            "profile_url": "https://github.com/alice_osint",
            "observed": {
                "bio": {
                    "value": "also @alice_osint and @otherhandle",
                    "source": "github_api.bio",
                    "observed_at": utcnow().isoformat(),
                }
            },
        },
    )
    rows = extract_indicators([finding], operator_usernames={"alice_osint"})
    handles = [row["value"].lower() for row in rows if row["indicator_type"] == "username"]
    assert "alice_osint" not in handles
    assert "otherhandle" in handles


def test_summary_is_deterministic_and_does_not_invent_geo() -> None:
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id="c",
        case_name="n",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user],
        findings=[],
        inputs={"display_name": "Alice Example"},
    )
    first = build_intelligence_summary(result)
    second = build_intelligence_summary(result)
    assert first == second
    assert first["geographic_indicators"] == []
    assert first["insufficient_evidence"] is True
    assert "Insufficient evidence" in first["correlation"]


def test_identity_weights_and_bands_unchanged() -> None:
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
    assert BANDS == ((80, "STRONG"), (60, "LIKELY"), (30, "POSSIBLE"), (0, "LOW"))
    assert CLUSTER_MIN == 60


@pytest.mark.asyncio
async def test_legacy_search_engine_not_configured() -> None:
    settings = SimpleNamespace(google_cse_id=None, google_api_key=None)

    def secret_present(name: str) -> bool:
        return False

    settings.secret_present = secret_present  # type: ignore[attr-defined]
    finding = await SearchEngine(http=None, settings=settings).search("alice")  # type: ignore[arg-type]
    assert finding.status == FindingStatus.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_collect_search_intelligence_without_searxng(monkeypatch) -> None:
    from spectre_osint.modules.search import engine as search_engine

    async def fake_run_queries(*_args, **_kwargs):
        return {
            "findings": [],
            "entities": [],
            "evidence": [],
            "providers_queried": [],
            "stats": {},
            "coverage": {},
        }

    monkeypatch.setattr(search_engine, "_run_queries", fake_run_queries)
    entity = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    settings = SimpleNamespace(
        searxng_url=None,
        search_query_budget=12,
        search_max_pivots=25,
        search_max_depth=2,
    )
    bundle = await collect_search_intelligence(
        entity,
        http=None,  # type: ignore[arg-type]
        settings=settings,
        case_inputs={"usernames": ["alice_osint"]},
        existing_findings=[],
    )
    titles = [f.title for f in bundle["findings"]]
    assert "SearXNG" in titles
    assert any(f.status == FindingStatus.NOT_CONFIGURED for f in bundle["findings"] if f.title == "SearXNG")


def _github_finding(**observed: object) -> Finding:
    return Finding(
        module="username",
        title="GitHub",
        status=FindingStatus.FOUND,
        summary="CONFIRMED",
        data={
            "platform": "GitHub",
            "check_status": "CONFIRMED",
            "username": "alice_osint",
            "profile_url": "https://github.com/alice_osint",
            "observed": observed,
        },
    )


def test_known_platform_hosts_do_not_consume_pivot_budget() -> None:
    from spectre_osint.modules.search.novelty import annotate_indicators

    github = _github_finding()
    insta = Finding(
        module="username",
        title="Instagram",
        status=FindingStatus.FOUND,
        summary="CONFIRMED",
        data={
            "platform": "Instagram",
            "check_status": "CONFIRMED",
            "username": "alice_osint",
            "profile_url": "https://www.instagram.com/alice_osint/",
        },
    )
    rows = annotate_indicators(
        extract_indicators([github, insta], operator_usernames={"alice-sec", "alice_osint"}),
        operator_handles={"alice-sec", "alice_osint"},
        operator_emails=set(),
        operator_domains=set(),
        findings=[github, insta],
    )
    pivots = propose_pivots(
        indicators=rows,
        known={("username", "alice-sec"), ("username", "alice_osint")},
        source="search",
        depth=1,
        remaining=25,
    )
    accepted = [row for row in pivots if row["accepted"]]
    suppressed = [row for row in pivots if not row["accepted"]]
    assert not any(row["target"] in {"github.com", "instagram.com"} and row["accepted"] for row in pivots)
    assert any(row.get("reject_reason") == "redundant" for row in suppressed)
    assert all(row["type"] != "domain" or "github.com" not in str(row["target"]) for row in accepted)


def test_external_github_blog_is_a_novel_pivot() -> None:
    from spectre_osint.modules.search.novelty import DERIVED, NOVEL, annotate_indicators

    github = _github_finding(
        website={"value": "https://alice.dev", "source": "github_api.blog", "observed_at": utcnow().isoformat()}
    )
    rows = annotate_indicators(
        extract_indicators([github], operator_usernames={"alice_osint"}),
        operator_handles={"alice_osint"},
        operator_emails=set(),
        operator_domains=set(),
        findings=[github],
    )
    domains = [row for row in rows if row["indicator_type"] == "domain"]
    assert any(row["value"] == "alice.dev" and row["novelty"] in {NOVEL, DERIVED} for row in domains)
    pivots = propose_pivots(
        indicators=rows,
        known={("username", "alice_osint")},
        source="github",
        depth=1,
        remaining=25,
    )
    accepted = [row for row in pivots if row["accepted"]]
    assert any(row["target"] == "alice.dev" for row in accepted)
    assert not any(row["target"] == "github.com" and row["accepted"] for row in pivots)


def test_rel_me_external_link_is_candidate() -> None:
    from spectre_osint.modules.search.novelty import annotate_indicators, useful_discovery

    github = _github_finding(
        social_links={
            "value": ["https://alice.dev/about"],
            "source": "github_api.blog",
            "observed_at": utcnow().isoformat(),
        }
    )
    rows = annotate_indicators(
        extract_indicators([github], operator_usernames={"alice_osint"}),
        operator_handles={"alice_osint"},
        operator_emails=set(),
        operator_domains=set(),
        findings=[github],
    )
    urls = [row for row in rows if row["indicator_type"] == "url" and "alice.dev" in str(row["value"])]
    assert urls
    assert all(useful_discovery(row) for row in urls)


def test_operator_username_is_not_novel() -> None:
    from spectre_osint.modules.search.novelty import OPERATOR_INPUT, classify_indicator

    novelty = classify_indicator(
        {"indicator_type": "username", "value": "alice_osint", "extraction_rule": "bio_handle"},
        operator_handles={"alice_osint"},
        operator_emails=set(),
        operator_domains=set(),
        known_urls=set(),
    )
    assert novelty == OPERATOR_INPUT


def test_duplicate_sources_merge_into_one_indicator() -> None:
    finding = _github_finding(
        website={"value": "https://alice.dev", "source": "github_api.blog", "observed_at": utcnow().isoformat()},
        personal_domain={"value": "alice.dev", "source": "duckduckgo-html", "observed_at": utcnow().isoformat()},
    )
    rows = extract_indicators([finding], operator_usernames={"alice_osint"})
    domains = [row for row in rows if row["indicator_type"] == "domain" and row["value"] == "alice.dev"]
    assert len(domains) == 1
    assert "github_api.blog" in domains[0]["sources"]
    assert "duckduckgo-html" in domains[0]["sources"]


def test_generic_profile_titles_are_not_display_names() -> None:
    from spectre_osint.modules.search.novelty import is_generic_display_name
    from spectre_osint.modules.username.enrichment import clean_display_name

    assert is_generic_display_name("alice_osint’s Music Profile | Last.fm", "alice_osint")
    assert is_generic_display_name("alice_osint's profile on GOG.com", "alice_osint")
    assert is_generic_display_name("alice_osint – WordPress user profile", "alice_osint")
    assert clean_display_name("alice's Music Profile | Last.fm", "alice") == ""
    assert clean_display_name("Alice Example", "alice_osint") == "Alice Example"
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id="c",
        case_name="n",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user],
        findings=[
            Finding(
                module="username",
                title="Last.fm",
                status=FindingStatus.FOUND,
                summary="LIKELY",
                data={
                    "platform": "Last.fm",
                    "check_status": "LIKELY",
                    "username": "alice_osint",
                    "observed": {
                        "display_name": {
                            "value": "alice_osint’s Music Profile | Last.fm",
                            "source": "html_title",
                        }
                    },
                },
            ),
            Finding(
                module="username",
                title="GitHub",
                status=FindingStatus.FOUND,
                summary="CONFIRMED",
                data={
                    "platform": "GitHub",
                    "check_status": "CONFIRMED",
                    "username": "alice_osint",
                    "observed": {
                        "display_name": {"value": "Alice Example", "source": "github_api.name"}
                    },
                },
            ),
        ],
    )
    summary = build_intelligence_summary(result)
    assert "Alice Example" in summary["observed_names"]
    assert all("Last.fm" not in name for name in summary["observed_names"])
    assert summary["new_discoveries"] == []


def test_gui_empty_novelty_copy_exists() -> None:
    from pathlib import Path

    en = Path("spectre_osint/web/i18n/en.json").read_text(encoding="utf-8")
    pt = Path("spectre_osint/web/i18n/pt-BR.json").read_text(encoding="utf-8")
    assert "No new public identity was discovered beyond the supplied inputs." in en
    assert "Nenhuma nova identidade pública foi descoberta além das entradas fornecidas." in pt
    html = Path("spectre_osint/web/templates/investigation.html").read_text(encoding="utf-8")
    assert "new_discoveries" in html
    assert "no_new_discoveries" in html
