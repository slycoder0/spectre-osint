from __future__ import annotations

import logging

import httpx
import pytest
from pydantic import SecretStr

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.presentation import mention_groups, top_evidence_rows, username_rows
from spectre_osint.core.scoring import score_investigation
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.modules.mentions import collect_public_mentions
from spectre_osint.modules.mentions.match import match_input
from spectre_osint.modules.mentions.providers import (
    DuckDuckGoHtmlProvider,
    GitHubSearchProvider,
    GoogleCseProvider,
    HnAlgoliaProvider,
    RawMention,
    RedditSearchProvider,
    default_mention_providers,
)
from spectre_osint.modules.mentions.relevance import AMBIGUOUS, ASSOCIATED, DIRECT, classify_mention
from spectre_osint.modules.username.identity import correlate_identities


def _settings(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        ssrf_enabled=False,
    )
    settings.ensure_dirs()
    return settings


def _hits(*items: dict) -> dict:
    return {"hits": list(items)}


async def _collect(tmp_path, hits: list[dict], query: str, kind: str = "username"):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_hits(*hits))

    settings = _settings(tmp_path)
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        return await collect_public_mentions(
            query, http, limit=5, kind=kind, providers=[HnAlgoliaProvider()]
        )
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_unrelated_search_hits_are_dropped(tmp_path) -> None:
    hits = [
        {"objectID": str(i), "title": title, "url": "https://example.com/x", "story_text": body}
        for i, (title, body) in enumerate(
            [
                ("GBF Ventures raises funding", "incidents and RSS marketing"),
                ("Incident response newsletter", "weekly roundup"),
                ("Marketing RSS dump", "unrelated"),
            ]
            * 3
            + [("Noise", "noise")],
        )
    ]
    bundle = await _collect(tmp_path, hits[:10], "alice_osint")
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert observed == []
    assert bundle["entities"] == []
    assert bundle["mentions"] == []


@pytest.mark.asyncio
async def test_username_in_title_is_observed(tmp_path) -> None:
    bundle = await _collect(
        tmp_path,
        [{"objectID": "1", "title": "Thread about alice_osint", "story_text": "hello", "url": "https://example.com/a"}],
        "alice_osint",
    )
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert len(observed) == 1
    assert observed[0].data["matched_field"] == "title"
    assert observed[0].data["match_type"] == "exact_token"


@pytest.mark.asyncio
async def test_username_in_snippet_is_observed(tmp_path) -> None:
    bundle = await _collect(
        tmp_path,
        [{"objectID": "2", "title": "Public thread", "story_text": "user alice_osint posted", "url": "https://example.com/b"}],
        "alice_osint",
    )
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert len(observed) == 1
    assert observed[0].data["matched_field"] == "snippet"


def test_at_username_token_is_observed() -> None:
    hit = match_input(
        "alice_osint",
        "username",
        title="Comment by @alice_osint",
        snippet="",
        url="https://example.com/thread",
    )
    assert hit is not None
    assert hit.match_type == "exact_token"


def test_username_in_url_is_observed() -> None:
    hit = match_input(
        "alice_osint",
        "username",
        title="Issue",
        snippet="",
        url="https://github.com/alice_osint/notes",
    )
    assert hit is not None
    assert hit.match_type == "url_path_segment"


def test_false_substring_rejected() -> None:
    assert match_input("alice_osint", "username", title="malice_osintx news", snippet="", url="") is None
    assert match_input("alice_osint", "username", title="GBF Ventures", snippet="incidents", url="") is None
    assert match_input("alice_osint", "username", title="alice osint notes", snippet="", url="") is None
    assert match_input("alice_osint", "username", title="alice-osint", snippet="", url="") is None


def test_full_name_observed_partial_rejected() -> None:
    ok = match_input("Alice Example", "name", title="Alice Example spoke", snippet="", url="")
    assert ok is not None
    assert ok.match_type == "full_name"
    assert match_input("Alice Example", "name", title="Alice went home", snippet="", url="") is None
    assert match_input("Alice", "name", title="Alice Example", snippet="", url="") is None


def test_email_and_domain_exact() -> None:
    mail = match_input(
        "alice@example.com",
        "email",
        title="Contact",
        snippet="write alice@example.com",
        url="",
    )
    assert mail is not None
    assert mail.match_type == "exact_email"
    domain = match_input(
        "alice.example",
        "domain",
        title="Site",
        snippet="",
        url="https://blog.alice.example/post",
    )
    assert domain is not None
    assert domain.match_type == "exact_host"
    assert match_input("alice.example", "domain", title="alice wrote example notes", snippet="", url="") is None


@pytest.mark.asyncio
async def test_duplicate_hits_collapse(tmp_path) -> None:
    hit = {
        "objectID": "9",
        "title": "alice_osint on HN",
        "story_text": "alice_osint",
        "url": "https://example.com/dup",
    }
    bundle = await _collect(tmp_path, [hit, dict(hit), dict(hit)], "alice_osint")
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert len(observed) == 1


@pytest.mark.asyncio
async def test_duckduckgo_html_results_are_accepted_when_input_matches(tmp_path) -> None:
    html = """
    <div class="result">
      <a class="result__a" href="https://example.net/u/alice_osint">alice_osint on Example</a>
      <a class="result__snippet">Public writeup about alice_osint</a>
    </div>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    settings = _settings(tmp_path)
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        bundle = await collect_public_mentions(
            "alice_osint", http, kind="username", providers=[DuckDuckGoHtmlProvider()]
        )
    finally:
        await http.close()
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert len(observed) == 1
    assert observed[0].data["provider"] == "duckduckgo-html"
    assert observed[0].entity_id
    assert all(e.type != EntityType.SOCIAL_PROFILE for e in bundle["entities"])


@pytest.mark.asyncio
async def test_per_provider_limit_and_dedupe_across_hits(tmp_path) -> None:
    hits = [
        {"objectID": "1", "title": "alice_osint one", "story_text": "alice_osint", "url": "https://example.com/a"},
        {"objectID": "1", "title": "alice_osint one", "story_text": "alice_osint", "url": "https://example.com/a"},
        {"objectID": "2", "title": "alice_osint two", "story_text": "alice_osint", "url": "https://example.com/b"},
        {"objectID": "3", "title": "alice_osint three", "story_text": "alice_osint", "url": "https://example.com/c"},
        {"objectID": "4", "title": "alice_osint four", "story_text": "alice_osint", "url": "https://example.com/d"},
        {"objectID": "5", "title": "alice_osint five", "story_text": "alice_osint", "url": "https://example.com/e"},
        {"objectID": "6", "title": "alice_osint six", "story_text": "alice_osint", "url": "https://example.com/f"},
    ]
    bundle = await _collect(tmp_path, hits, "alice_osint")
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert len(observed) == 5


def test_mentions_do_not_change_profile_count_or_identity_score() -> None:
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    profile = Finding(
        module="username",
        title="GitHub",
        status=FindingStatus.FOUND,
        summary="GitHub",
        data={"platform": "GitHub", "username": "alice_osint", "check_status": "CONFIRMED"},
        confidence=Confidence.CONFIRMED,
    )
    mention = Finding(
        module="mentions",
        title="Public mention",
        status=FindingStatus.OBSERVED,
        summary="OBSERVED",
        data={"query": "alice_osint", "check_status": "OBSERVED", "platform": "HN"},
        confidence=Confidence.LOW,
    )
    base = InvestigationResult(
        case_id="c",
        case_name="n",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user],
        findings=[profile],
    )
    with_mentions = base.model_copy(update={"findings": [profile, mention]})
    from spectre_osint.core.presentation import username_counts

    assert username_counts(base)["confirmed"] == username_counts(with_mentions)["confirmed"]
    assert score_investigation(base).confidence_score == score_investigation(with_mentions).confidence_score
    ident_base = correlate_identities([profile])
    ident_plus = correlate_identities([profile, mention])
    assert ident_base["max_score"] == ident_plus["max_score"]
    assert ident_base["records"] == ident_plus["records"]


def test_default_providers_are_pluggable_and_include_web_search() -> None:
    names = [provider.name for provider in default_mention_providers()]
    assert names == [
        "duckduckgo-html",
        "hn-algolia",
        "github-search",
        "reddit-search",
        "public-documents",
        "google-cse",
    ]


@pytest.mark.asyncio
async def test_github_issue_hit_is_observed(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "api.github.com/search/issues" in str(request.url)
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "title": "Bug for alice_osint",
                        "html_url": "https://github.com/org/repo/issues/1",
                        "body": "reported by alice_osint",
                        "user": {"login": "reporter"},
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ]
            },
        )

    settings = _settings(tmp_path)
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        bundle = await collect_public_mentions(
            "alice_osint", http, kind="username", providers=[GitHubSearchProvider()]
        )
    finally:
        await http.close()
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert len(observed) == 1
    assert observed[0].data["provider"] == "github-search"
    assert observed[0].data["canonical_url"] == "https://github.com/org/repo/issues/1"
    assert all(e.type == EntityType.PUBLIC_MENTION for e in bundle["entities"])


@pytest.mark.asyncio
async def test_reddit_indexed_hit_is_observed(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "reddit.com/search.json" in str(request.url)
        return httpx.Response(
            200,
            json={
                "data": {
                    "children": [
                        {
                            "data": {
                                "title": "Post about alice_osint",
                                "selftext": "user alice_osint commented",
                                "permalink": "/r/osint/comments/abc/alice_osint/",
                                "author": "mod",
                                "created_utc": "1700000000",
                            }
                        }
                    ]
                }
            },
        )

    settings = _settings(tmp_path)
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        bundle = await collect_public_mentions(
            "alice_osint", http, kind="username", providers=[RedditSearchProvider()]
        )
    finally:
        await http.close()
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert len(observed) == 1
    assert observed[0].data["provider"] == "reddit-search"
    assert "reddit.com/r/osint/comments/abc/alice_osint" in observed[0].data["url"]


@pytest.mark.asyncio
async def test_google_cse_is_explicitly_unavailable_without_keys(tmp_path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        raise AssertionError("Google CSE must not be called without keys")

    settings = _settings(tmp_path)
    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        bundle = await collect_public_mentions(
            "alice_osint", http, kind="username", providers=[GoogleCseProvider()]
        )
    finally:
        await http.close()
    assert seen == []
    assert bundle["providers_unavailable"] == ["google-cse"]
    assert bundle["providers_queried"] == []
    assert bundle["mentions"] == []


@pytest.mark.asyncio
async def test_google_cse_accepts_configured_hits(tmp_path) -> None:
    settings = _settings(tmp_path)
    settings.google_api_key = SecretStr("test-key")
    settings.google_cse_id = "cx-test"

    def handler(request: httpx.Request) -> httpx.Response:
        assert "googleapis.com/customsearch/v1" in str(request.url)
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "title": "Writeup on alice_osint",
                        "link": "https://news.example/alice_osint",
                        "snippet": "article mentioning alice_osint",
                    }
                ]
            },
        )

    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        bundle = await collect_public_mentions(
            "alice_osint", http, kind="username", settings=settings, providers=[GoogleCseProvider()]
        )
    finally:
        await http.close()
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert len(observed) == 1
    assert observed[0].data["provider"] == "google-cse"
    record = bundle["mentions"][0]
    assert record.provider == "google-cse"
    assert record.query_input == "alice_osint"
    assert record.input_type == "username"
    assert record.canonical_url
    assert record.reason


def test_mention_groups_preserve_originating_input() -> None:
    result = InvestigationResult(
        case_id="c",
        case_name="n",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        findings=[
            Finding(
                module="mentions",
                title="Public mention",
                status=FindingStatus.OBSERVED,
                summary="OBSERVED",
                data={"query": "alice_osint", "kind": "username", "provider": "hn-algolia"},
                confidence=Confidence.LOW,
            ),
            Finding(
                module="mentions",
                title="Public mention",
                status=FindingStatus.OBSERVED,
                summary="OBSERVED",
                data={"query": "Alice Example", "kind": "name", "provider": "duckduckgo-html"},
                confidence=Confidence.LOW,
            ),
            Finding(
                module="username",
                title="GitHub",
                status=FindingStatus.FOUND,
                summary="GitHub",
                data={"platform": "GitHub", "username": "alice_osint", "check_status": "CONFIRMED"},
                confidence=Confidence.CONFIRMED,
            ),
        ],
    )
    groups = mention_groups(result)
    assert {g["query"] for g in groups} == {"alice_osint", "Alice Example"}
    assert all(g["count"] == 1 for g in groups)
    top = top_evidence_rows(username_rows(result))
    assert [row["platform"] for row in top] == ["GitHub"]
    assert all(row.get("module") != "mentions" for row in top)


@pytest.mark.asyncio
async def test_mention_coverage_debug_counts(tmp_path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="spectre.mentions")
    hits = [
        {"objectID": "1", "title": "alice_osint one", "story_text": "alice_osint", "url": "https://example.com/a"},
        {"objectID": "2", "title": "unrelated", "story_text": "noise", "url": "https://example.com/b"},
        {"objectID": "1", "title": "alice_osint one", "story_text": "alice_osint", "url": "https://example.com/a"},
        {"objectID": "", "title": "missing", "story_text": "alice_osint", "url": ""},
    ]
    bundle = await _collect(tmp_path, hits, "alice_osint")
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert len(observed) == 1
    lines = [rec.getMessage() for rec in caplog.records if rec.getMessage().startswith("mention provider=")]
    assert lines
    message = lines[-1]
    assert "provider=hn-algolia" in message
    assert "input=username" in message
    assert "raw=4" in message
    assert "parsed=3" in message
    assert "matched=2" in message
    assert "deduped=1" in message
    assert "rejected_no_exact_match=1" in message
    assert "rejected_invalid_url=1" in message
    assert "rejected_duplicate=1" in message
    assert "errors=0" in message
    assert "status=ok" in message
    assert "<html" not in message
    assert "cookie" not in message.lower()


@pytest.mark.asyncio
async def test_google_cse_unavailable_logged_once_per_investigation(
    tmp_path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="spectre.mentions")
    settings = _settings(tmp_path)
    logged: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Google CSE must not be called without keys")

    http = HttpClient(settings, transport=httpx.MockTransport(handler))
    try:
        await collect_public_mentions(
            "alice_osint",
            http,
            kind="username",
            providers=[GoogleCseProvider()],
            unavailable_logged=logged,
        )
        await collect_public_mentions(
            "Alice Example",
            http,
            kind="name",
            providers=[GoogleCseProvider()],
            unavailable_logged=logged,
        )
    finally:
        await http.close()
    notices = [
        rec.getMessage()
        for rec in caplog.records
        if "google-cse" in rec.getMessage() and "unavailable" in rec.getMessage()
    ]
    assert len(notices) == 1
    assert logged == {"google-cse"}


@pytest.mark.asyncio
async def test_mention_debug_does_not_log_raw_email(tmp_path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="spectre.mentions")
    hits = [
        {
            "objectID": "9",
            "title": "Contact alice@example.com",
            "story_text": "write alice@example.com",
            "url": "https://example.com/c",
        }
    ]
    await _collect(tmp_path, hits, "alice@example.com", kind="email")
    blob = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "alice@example.com" not in blob
    assert "input=email" in blob


def test_username_exact_is_direct() -> None:
    band, reason, extra = classify_mention(
        "username",
        "exact_token",
        title="Thread about alice_osint",
        snippet="",
        url="https://example.com/a",
    )
    assert band == DIRECT
    assert reason == "exact_username"
    assert extra == []


def test_at_username_is_direct() -> None:
    band, reason, extra = classify_mention(
        "username",
        "exact_token",
        title="Comment by @alice_osint",
        snippet="",
        url="https://example.com/thread",
    )
    assert band == DIRECT
    assert reason == "exact_username"


def test_username_path_is_direct() -> None:
    band, reason, extra = classify_mention(
        "username",
        "url_path_segment",
        title="Issue",
        snippet="",
        url="https://github.com/alice_osint/notes",
    )
    assert band == DIRECT
    assert reason == "username_path"


def test_email_and_domain_are_direct() -> None:
    mail_band, mail_reason, _ = classify_mention(
        "email",
        "exact_email",
        title="Contact",
        snippet="write alice@example.com",
        url="https://example.com/c",
    )
    assert mail_band == DIRECT
    assert mail_reason == "exact_email"
    host_band, host_reason, _ = classify_mention(
        "domain",
        "exact_host",
        title="Site",
        snippet="",
        url="https://blog.alice.example/post",
    )
    assert host_band == DIRECT
    assert host_reason == "exact_domain"


def test_full_name_alone_is_ambiguous() -> None:
    band, reason, extra = classify_mention(
        "name",
        "full_name",
        title="Alice Example spoke",
        snippet="a talk by Alice Example",
        url="https://news.example/talk",
        case_inputs={"usernames": ["alice_osint"], "emails": [], "domains": []},
    )
    assert band == AMBIGUOUS
    assert reason == "full_name_only"
    assert extra == []


def test_name_plus_username_on_page_is_associated() -> None:
    band, reason, extra = classify_mention(
        "name",
        "full_name",
        title="Alice Example aka alice_osint",
        snippet="alice_osint posted notes",
        url="https://example.net/bio",
        case_inputs={"usernames": ["alice_osint"], "emails": [], "domains": []},
    )
    assert band == ASSOCIATED
    assert reason == "name_plus_username"
    assert "alice_osint" in extra


def test_name_plus_domain_on_page_is_associated() -> None:
    band, reason, extra = classify_mention(
        "name",
        "full_name",
        title="Alice Example",
        snippet="site spectre.example",
        url="https://spectre.example/about",
        case_inputs={"usernames": [], "emails": [], "domains": ["spectre.example"]},
    )
    assert band == ASSOCIATED
    assert reason == "name_plus_domain"


def test_operator_leads_not_on_page_do_not_associate() -> None:
    band, reason, extra = classify_mention(
        "name",
        "full_name",
        title="Alice Example interview",
        snippet="no other identifiers",
        url="https://news.example/other",
        case_inputs={"usernames": ["alice_osint", "alice-sec"], "emails": ["a@b.example"], "domains": ["spectre.example"]},
    )
    assert band == AMBIGUOUS
    assert extra == []


class _StubProvider:
    def __init__(self, name: str, hits: list[RawMention]) -> None:
        self.name = name
        self._hits = hits

    async def search(self, query: str, *, http, settings, limit: int) -> list[RawMention]:
        del query, http, settings, limit
        self.last_raw = len(self._hits)
        self.last_parsed = len(self._hits)
        return list(self._hits)


@pytest.mark.asyncio
async def test_two_providers_same_url_merge_sources(tmp_path) -> None:
    hit = RawMention(
        provider="duckduckgo-html",
        title="alice_osint writeup",
        url="https://example.net/u/alice_osint",
        snippet="user alice_osint posted",
    )
    other = RawMention(
        provider="github-search",
        title="alice_osint writeup",
        url="https://example.net/u/alice_osint",
        snippet="user alice_osint posted",
    )
    settings = _settings(tmp_path)
    http = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    try:
        bundle = await collect_public_mentions(
            "alice_osint",
            http,
            kind="username",
            providers=[_StubProvider("duckduckgo-html", [hit]), _StubProvider("github-search", [other])],
        )
    finally:
        await http.close()
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert len(observed) == 1
    assert observed[0].data["relevance"] == DIRECT
    assert observed[0].data["sources"] == ["duckduckgo-html", "github-search"]
    groups = mention_groups(
        InvestigationResult(
            case_id="c",
            case_name="n",
            target="alice_osint",
            target_type=EntityType.USERNAME,
            mode="PASSIVE_OSINT",
            started_at=utcnow(),
            findings=observed,
        )
    )
    assert groups[0]["count"] == 1
    assert "DuckDuckGo" in groups[0]["mentions"][0]["observed_by"]
    assert "GitHub" in groups[0]["mentions"][0]["observed_by"]


@pytest.mark.asyncio
async def test_collect_classifies_name_hits(tmp_path) -> None:
    settings = _settings(tmp_path)
    http = HttpClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    name_only = RawMention(
        provider="duckduckgo-html",
        title="Alice Example spoke",
        url="https://news.example/talk",
        snippet="Alice Example gave a talk",
    )
    name_and_user = RawMention(
        provider="duckduckgo-html",
        title="Alice Example / alice_osint",
        url="https://example.net/bio",
        snippet="Alice Example writes as alice_osint",
    )
    try:
        alone = await collect_public_mentions(
            "Alice Example",
            http,
            kind="name",
            providers=[_StubProvider("duckduckgo-html", [name_only])],
            case_inputs={"usernames": ["alice_osint"]},
        )
        crossed = await collect_public_mentions(
            "Alice Example",
            http,
            kind="name",
            providers=[_StubProvider("duckduckgo-html", [name_and_user])],
            case_inputs={"usernames": ["alice_osint"]},
        )
    finally:
        await http.close()
    assert alone["findings"][0].data["relevance"] == AMBIGUOUS
    assert crossed["findings"][0].data["relevance"] == ASSOCIATED
    assert crossed["findings"][0].data["relevance_reason"] == "name_plus_username"


def test_ambiguous_mention_never_raises_score_or_identity() -> None:
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    profile = Finding(
        module="username",
        title="GitHub",
        status=FindingStatus.FOUND,
        summary="GitHub",
        data={"platform": "GitHub", "username": "alice_osint", "check_status": "CONFIRMED"},
        confidence=Confidence.CONFIRMED,
    )
    mention = Finding(
        module="mentions",
        title="Public mention",
        status=FindingStatus.OBSERVED,
        summary="OBSERVED",
        data={
            "query": "Alice Example",
            "kind": "name",
            "check_status": "OBSERVED",
            "relevance": "AMBIGUOUS",
            "relevance_reason": "full_name_only",
        },
        confidence=Confidence.LOW,
    )
    base = InvestigationResult(
        case_id="c",
        case_name="n",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user],
        findings=[profile],
    )
    with_mentions = base.model_copy(update={"findings": [profile, mention]})
    from spectre_osint.core.presentation import username_counts

    assert username_counts(base)["confirmed"] == username_counts(with_mentions)["confirmed"]
    assert score_investigation(base).confidence_score == score_investigation(with_mentions).confidence_score
    ident_base = correlate_identities([profile])
    ident_plus = correlate_identities([profile, mention])
    assert ident_base["max_score"] == ident_plus["max_score"]
    top = top_evidence_rows(username_rows(with_mentions))
    assert all(row["platform"] != "Public mention" for row in top)
    assert all(row.get("relevance") != "AMBIGUOUS" for row in top)


@pytest.mark.asyncio
async def test_collect_username_is_direct_and_logs_relevance_counts(
    tmp_path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="spectre.mentions")
    bundle = await _collect(
        tmp_path,
        [{"objectID": "1", "title": "Thread about alice_osint", "story_text": "hello", "url": "https://example.com/a"}],
        "alice_osint",
    )
    observed = [f for f in bundle["findings"] if f.status == FindingStatus.OBSERVED]
    assert observed[0].data["relevance"] == DIRECT
    assert observed[0].entity_id
    assert all(e.type == EntityType.PUBLIC_MENTION for e in bundle["entities"])
    lines = [rec.getMessage() for rec in caplog.records if rec.getMessage().startswith("mention relevance ")]
    assert lines
    assert "direct=1" in lines[-1]
    assert "associated=0" in lines[-1]
    assert "ambiguous=0" in lines[-1]


def test_cli_mentions_panel_is_summary_only(capsys) -> None:
    from spectre_osint.cli.display import print_result

    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    findings = [
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
        )
    ]
    for i in range(8):
        findings.append(
            Finding(
                module="mentions",
                title="Public mention",
                status=FindingStatus.OBSERVED,
                summary=f"card {i}",
                data={
                    "query": "alice_osint",
                    "kind": "username",
                    "title": f"Unique mention title {i} should not all print",
                    "relevance": "DIRECT" if i < 3 else "AMBIGUOUS",
                    "provider": "duckduckgo-html",
                },
                confidence=Confidence.LOW,
            )
        )
    result = InvestigationResult(
        case_id="c",
        case_name="n",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user],
        findings=findings,
        report_path="/tmp/report.html",
    )
    print_result(result)
    out = capsys.readouterr().out
    assert "PUBLIC MENTIONS" in out
    assert "Direct: 3" in out
    assert "Ambiguous: 5" in out
    assert out.count("Unique mention title") <= 5
    assert "Full list" in out
