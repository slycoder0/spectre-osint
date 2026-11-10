"""Compact `spectre username` presentation (B2-06): data view + Rich renderer.

The view (`services/views.py`) decides *what* is true and countable; the renderer
(`cli/render.py`) decides how it looks in each language. Snapshot tests pin the exact
compact output in English and Brazilian Portuguese.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from typing import Any

from rich.console import Console

from spectre_osint.cli.render import clean_text, render_username
from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
from spectre_osint.core.i18n import set_language
from spectre_osint.core.types import Confidence, EntityType, FindingStatus
from spectre_osint.modules.username.observed import ObservedField, SourceMethod
from spectre_osint.services.views import build_username_view

STAMP = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def _observed_name(
    name: str,
    source: str,
    *,
    method: SourceMethod = SourceMethod.JSON_API,
    rejected_by: str | None = None,
) -> dict[str, Any]:
    field = ObservedField(
        value=name,
        original=name,
        source=source,
        observed_at=STAMP,
        source_method=method,
        rejected_by=rejected_by,
    )
    return {"display_name": field.to_transport()}


def _site(
    platform: str,
    status: str,
    *,
    url: str | None = None,
    observed: dict[str, Any] | None = None,
    username: str = "alice_osint",
) -> Finding:
    found = status in {"CONFIRMED", "LIKELY"}
    data: dict[str, Any] = {
        "platform": platform,
        "username": username,
        "check_status": status,
        "profile_url": url or f"https://{platform.lower().replace(' ', '')}.example/{username}",
        "access_mode": "ANONYMOUS_PUBLIC",
        "cache_state": "LIVE",
    }
    if observed is not None:
        data["observed"] = observed
    return Finding(
        module="username",
        title=platform,
        status=FindingStatus.FOUND if found else FindingStatus.NOT_FOUND,
        summary=f"{platform}: {status}",
        data=data,
        confidence=Confidence.CONFIRMED if status == "CONFIRMED" else (
            Confidence.MEDIUM if status == "LIKELY" else None
        ),
    )


def _result(findings: list[Finding], **kwargs: Any) -> InvestigationResult:
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    return InvestigationResult(
        case_id="c",
        case_name="case-username-alice",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user],
        findings=findings,
        **kwargs,
    )


def alice_result() -> InvestigationResult:
    return _result(
        [
            _site("Docker Hub", "NOT_FOUND"),
            _site(
                "Hugging Face",
                "CONFIRMED",
                url="https://huggingface.co/alice_osint",
                observed=_observed_name("A. Example", "hugging_face_api.fullname"),
            ),
            _site("Instagram", "LOGIN_REQUIRED"),
            _site(
                "GitHub",
                "CONFIRMED",
                url="https://github.com/alice_osint",
                observed=_observed_name("Alice Example", "github_api.name"),
            ),
            _site("X", "BLOCKED"),
            _site("Keybase", "LIKELY", url="https://keybase.io/alice_osint"),
            _site("Reddit", "RATE_LIMITED"),
            _site("Bluesky", "PROVIDER_UNAVAILABLE"),
        ],
        report_path="reports/alice_osint.html",
    )


def _render(view: Any, *, verbose: bool = False) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, width=100, color_system=None, highlight=False, force_terminal=False)
    render_username(view, console, verbose=verbose)
    return buffer.getvalue()


# --- the view: what is found, what is unverified ------------------------------------------


def test_found_lists_only_confirmed_and_likely_in_a_stable_order() -> None:
    view = build_username_view(alice_result())
    assert [(p.platform, p.status) for p in view.found] == [
        ("GitHub", "CONFIRMED"),
        ("Hugging Face", "CONFIRMED"),
        ("Keybase", "LIKELY"),
    ]
    assert view.found[0].url == "https://github.com/alice_osint"


def test_every_checked_site_is_found_not_found_or_unverified() -> None:
    view = build_username_view(alice_result())
    assert view.checked == 8
    assert view.not_found == 1
    assert view.checked == len(view.found) + view.not_found + view.unverified.total


def test_unverified_buckets() -> None:
    unverified = build_username_view(alice_result()).unverified
    assert (unverified.blocked, unverified.login, unverified.rate_limited, unverified.inconclusive) == (
        1,
        1,
        1,
        1,
    )
    assert unverified.total == 4


def test_every_non_decisive_status_counts_as_unverified() -> None:
    statuses = [
        "BLOCKED",
        "CHALLENGE_REQUIRED",
        "CAPTCHA_REQUIRED",
        "OAUTH_BROWSER_REJECTED",
        "LOGIN_REQUIRED",
        "SESSION_EXPIRED",
        "RATE_LIMITED",
        "TEMPORARILY_LIMITED",
        "INCONCLUSIVE",
        "PROVIDER_UNAVAILABLE",
        "ERROR",
        "SOMETHING_NEW",
    ]
    findings = [_site(f"Site{i}", status) for i, status in enumerate(statuses)]
    unverified = build_username_view(_result(findings)).unverified
    assert unverified.blocked == 4
    assert unverified.login == 2
    assert unverified.rate_limited == 2
    assert unverified.inconclusive == 4
    assert unverified.total == len(statuses)


def test_two_profiles_two_names_stay_per_platform() -> None:
    view = build_username_view(alice_result())
    assert [(n.platform, n.name) for n in view.names] == [
        ("GitHub", "Alice Example"),
        ("Hugging Face", "A. Example"),
    ]


def test_names_never_come_from_rejected_input_or_unfound_rows() -> None:
    result = _result(
        [
            _site(
                "GitHub",
                "CONFIRMED",
                observed=_observed_name("Some Page Title", "html.title", rejected_by="page_title_unverified"),
            ),
            _site(
                "GitLab",
                "CONFIRMED",
                observed=_observed_name("Typed By Operator", "operator.name", method=SourceMethod.INPUT),
            ),
            _site("Codeberg", "CONFIRMED", observed=_observed_name("alice_osint", "codeberg_api.full_name")),
            _site("Instagram", "LOGIN_REQUIRED", observed=_observed_name("Behind Login", "html.og")),
            _site("Docker Hub", "NOT_FOUND", observed=_observed_name("Nobody", "docker_api.name")),
            _site("Bitbucket", "CONFIRMED", observed={"display_name": {"value": ["not", "a", "scalar"]}}),
        ],
        inputs={"display_name": "Alice Example"},
    )
    assert build_username_view(result).names == ()


def test_search_candidates_and_mentions_are_never_found_profiles() -> None:
    result = _result(
        [
            _site("GitHub", "NOT_FOUND"),
            Finding(
                module="search",
                title="Discovered profile",
                status=FindingStatus.OBSERVED,
                summary="candidate",
                data={
                    "kind": "discovered_profile",
                    "platform": "GitLab",
                    "url": "https://gitlab.com/alice_osint",
                    "profile_url": "https://gitlab.com/alice_osint",
                    "check_status": "CONFIRMED",
                },
            ),
            Finding(
                module="mentions",
                title="Public mention",
                status=FindingStatus.OBSERVED,
                summary="mention",
                data={
                    "query": "alice_osint",
                    "url": "https://forum.example/alice_osint",
                    "check_status": "LIKELY",
                    "relevance": "DIRECT",
                },
            ),
        ]
    )
    view = build_username_view(result)
    assert view.found == ()
    assert view.checked == 1
    assert view.not_found == 1


# --- the renderer: exact compact output (snapshots) ------------------------------------------

EN_SNAPSHOT = """\
alice_osint — 3 profiles found (sites checked: 8)
  [+] GitHub        https://github.com/alice_osint
  [+] Hugging Face  https://huggingface.co/alice_osint
  [~] Keybase       https://keybase.io/alice_osint (likely)

Names observed on each platform (not proof of the same person):
  GitHub: Alice Example
  Hugging Face: A. Example

[?] 4 not verified: 1 blocked, 1 needs login, 1 rate-limited, 1 inconclusive (--verbose lists them)
Full report: reports/alice_osint.html
"""

PT_BR_SNAPSHOT = """\
alice_osint — 3 perfis encontrados (sites consultados: 8)
  [+] GitHub        https://github.com/alice_osint
  [+] Hugging Face  https://huggingface.co/alice_osint
  [~] Keybase       https://keybase.io/alice_osint (provável)

Nomes observados em cada plataforma (não prova que sejam a mesma pessoa):
  GitHub: Alice Example
  Hugging Face: A. Example

[?] 4 não verificados: 1 bloqueado, 1 exige login, 1 com limite de requisições, 1 inconclusivo (--verbose mostra quais)
Relatório completo: reports/alice_osint.html
"""


def test_compact_snapshot_en() -> None:
    set_language("en")
    assert _render(build_username_view(alice_result())) == EN_SNAPSHOT


def test_compact_snapshot_pt_br() -> None:
    set_language("pt-BR")
    assert _render(build_username_view(alice_result())) == PT_BR_SNAPSHOT


def test_unverified_line_is_present_even_at_zero() -> None:
    set_language("en")
    only_found = _result([_site("GitHub", "CONFIRMED", url="https://github.com/alice_osint")])
    assert _render(build_username_view(only_found)) == (
        "alice_osint — 1 profile found (sites checked: 1)\n"
        "  [+] GitHub  https://github.com/alice_osint\n"
        "\n"
        "[?] 0 not verified\n"
    )


def test_unverified_line_is_present_with_no_rows_at_all() -> None:
    set_language("pt-BR")
    out = _render(build_username_view(_result([])))
    assert out.splitlines()[0] == "alice_osint — 0 perfis encontrados (sites consultados: 0)"
    assert "[?] 0 não verificados" in out.splitlines()


def test_hint_is_omitted_in_verbose_mode() -> None:
    set_language("en")
    out = _render(build_username_view(alice_result()), verbose=True)
    assert "4 not verified: 1 blocked, 1 needs login, 1 rate-limited, 1 inconclusive" in out
    assert "(--verbose lists them)" not in out


def test_untrusted_text_cannot_inject_markup_or_terminal_escapes() -> None:
    set_language("en")
    hostile = "Alice\x1b[31m [bold red]Admin[/bold red]‮evil\nsecond"
    result = _result(
        [_site("GitHub", "CONFIRMED", url="https://github.com/alice_osint", observed=_observed_name(hostile, "github_api.name"))]
    )
    out = _render(build_username_view(result))
    assert "\x1b" not in out
    assert "‮" not in out
    assert "GitHub: Alice[31m [bold red]Admin[/bold red]evil second" in out


def test_clean_text_strips_controls_and_bidi_overrides() -> None:
    assert clean_text("a\x00b\x07c\x1bd‪e⁦f\tg\nh") == "abcdef g h"
