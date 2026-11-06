"""Helpers that keep target data out of logs (B2-07), in `core/redaction.py`."""

from __future__ import annotations

import hashlib
import re

import httpx
import pytest

from spectre_osint.core.redaction import (
    MIN_SCRUB_LENGTH,
    clear_target_values,
    exc_label,
    host_ref,
    register_target_values,
    scrub_target_values,
    target_ref,
)

REF = re.compile(r"^[th]:[0-9a-f]{8}$")


def test_exc_label_is_the_class_name_only() -> None:
    exc = httpx.ConnectError("certificate is not valid for 'example.com' url=https://example.com/alice_osint")
    assert exc_label(exc) == "ConnectError"
    assert exc_label(ValueError("alice@example.com")) == "ValueError"


def test_target_ref_is_short_stable_within_a_run_and_case_insensitive() -> None:
    ref = target_ref("alice_osint")
    assert REF.match(ref)
    assert ref.startswith("t:")
    assert target_ref("alice_osint") == ref
    assert target_ref("  ALICE_OSINT ") == ref
    assert target_ref("bob_osint") != ref
    assert "alice" not in ref


def test_target_ref_is_not_a_plain_hash_of_the_value() -> None:
    """A bare SHA-256 of a guessable username could be reversed with a dictionary."""
    digest = target_ref("alice_osint").split(":", 1)[1]
    for plain in (
        hashlib.sha256(b"alice_osint").hexdigest(),
        hashlib.md5(b"alice_osint").hexdigest(),  # noqa: S324
        hashlib.sha1(b"alice_osint").hexdigest(),  # noqa: S324
    ):
        assert not plain.startswith(digest)


def test_target_ref_of_nothing_is_a_dash() -> None:
    assert target_ref("") == "-"
    assert target_ref(None) == "-"


def test_host_ref_names_no_host_and_matches_the_target_digest() -> None:
    ref = host_ref("https://Example.com:8443/alice_osint?q=1")
    assert REF.match(ref)
    assert ref.startswith("h:")
    assert host_ref("example.com") == ref
    assert host_ref("example.com.") == ref
    assert ref.split(":", 1)[1] == target_ref("example.com").split(":", 1)[1]
    assert "example" not in ref


def test_host_ref_keeps_ipv6_hosts_apart() -> None:
    """A bare IPv6 address must not be cut at its first colon (every 2001:db8::/32 host
    would share the reference of "2001")."""
    assert host_ref("2001:db8::1") != host_ref("2001:db8::2")
    assert host_ref("2001:db8::1") != host_ref("2001")
    assert host_ref("2001:db8::1") == host_ref("[2001:db8::1]") == host_ref("http://[2001:DB8::1]:8080/x")
    assert host_ref("2001:0db8:0000::0001") == host_ref("2001:db8::1")
    assert host_ref("example.com:8443/path") == host_ref("example.com")


@pytest.fixture(autouse=True)
def _clean_scrubber():
    clear_target_values()
    yield
    clear_target_values()


def test_scrubber_does_nothing_until_values_are_registered() -> None:
    assert scrub_target_values("GET https://github.com/alice_osint") == "GET https://github.com/alice_osint"


@pytest.mark.parametrize(
    "line",
    [
        "url=https://github.com/alice_osint",
        "user=ALICE_OSINT",
        "slug=case-username-alice-osint",
        "q=%22Alice+Example%22",
        "q=Alice%20Example",
        "lead=alice-example",
        "mail=alice%40example.com",
        "mail=alice@example.com",
        "avatar=" + hashlib.md5(b"alice@example.com").hexdigest(),  # noqa: S324
        "host=www.example.com",
        "report=case-domain-example-com.html",
        "ptr=34.216.184.93.in-addr.arpa",
        "ip=93.184.216.34",
    ],
)
def test_registered_values_are_scrubbed_in_every_form(line: str) -> None:
    register_target_values("alice_osint", "Alice Example", "alice@example.com", "example.com", "93.184.216.34")
    scrubbed = scrub_target_values(line)
    for needle in ("alice", "example", "93.184", "34.216", hashlib.md5(b"alice@example.com").hexdigest()):  # noqa: S324
        assert needle not in scrubbed.casefold(), scrubbed
    assert re.search(r"t:[0-9a-f]{8}", scrubbed)


def test_scrubber_replaces_with_the_values_reference() -> None:
    register_target_values("alice_osint")
    assert scrub_target_values("user=alice_osint") == f"user={target_ref('alice_osint')}"


def test_very_short_values_are_not_scrubbed() -> None:
    register_target_values("jo", "a" * (MIN_SCRUB_LENGTH - 1))
    assert scrub_target_values("major json") == "major json"


def test_none_and_blank_values_are_ignored() -> None:
    register_target_values(None, "", "   ")
    assert scrub_target_values("nothing to hide") == "nothing to hide"


def test_clear_forgets_every_value() -> None:
    register_target_values("alice_osint")
    clear_target_values()
    assert scrub_target_values("alice_osint") == "alice_osint"


# --- the safety net never eats the log's own vocabulary (PR #18 review, item 1) -------------

_VOCABULARY_LINE = (
    "HTTP timeout provider=github err=ReadTimeout username_in_final_url=True AUTHENTICATED_PUBLIC"
)


def test_common_and_short_targets_leave_the_log_vocabulary_intact() -> None:
    """A target that happens to be a site, a log word, a field fragment or a common word
    must not turn `provider=github` into `provider=t:…` or `ReadTimeout` into `Readt:…`."""
    register_target_values("github", "user", "timeout", "error", "the@company.com")
    assert scrub_target_values(_VOCABULARY_LINE) == _VOCABULARY_LINE


def test_only_delimited_occurrences_are_replaced() -> None:
    register_target_values("git")
    assert scrub_target_values("provider=GitHub status=404") == "provider=GitHub status=404"
    register_target_values("alice_osint")
    scrubbed = scrub_target_values("GET https://github.com/alice_osint status=200")
    assert scrubbed == f"GET https://github.com/{target_ref('alice_osint')} status=200"


def test_the_log_vocabulary_comes_from_the_catalog_enums_exceptions_and_templates() -> None:
    from spectre_osint.core.log_vocabulary import log_vocabulary
    from spectre_osint.core.types import AccessMode, Confidence
    from spectre_osint.modules.username.engine import load_sites

    vocabulary = log_vocabulary()
    sites = load_sites()
    token = re.compile(r"[A-Za-z0-9_]+")
    names = {str(site["name"]) for site in sites}
    assert {name.casefold() for name in names if token.fullmatch(name)} <= vocabulary
    assert {str(site["slug"]).casefold() for site in sites} <= vocabulary
    assert {member.value.casefold() for member in (*Confidence, *AccessMode)} <= vocabulary
    assert {"readtimeout", "connecterror", "ssrfblocked", "validationerror"} <= vocabulary
    assert {"timeout", "provider", "retry_after", "pivot"} <= vocabulary
    assert "alice_osint" not in vocabulary


def test_email_parts_do_not_split_ordinary_words() -> None:
    register_target_values("info@gmail.com")
    assert scrub_target_values("information about the provider") == "information about the provider"
    assert "info@gmail.com" not in scrub_target_values("mail=info@gmail.com")


# --- second review of PR #18 ----------------------------------------------------------------


def test_the_log_vocabulary_holds_only_plain_tokens() -> None:
    """A catalog name such as "Chess.com", "Docker Hub" or "Ko-fi" is not a log word: a
    vocabulary entry is never registered, so it would let a real domain through raw."""
    from spectre_osint.core.log_vocabulary import log_vocabulary

    vocabulary = log_vocabulary()
    assert all(re.fullmatch(r"[a-z0-9_]+", word) for word in vocabulary), sorted(
        word for word in vocabulary if not re.fullmatch(r"[a-z0-9_]+", word)
    )
    for name in ("chess.com", "wordpress.org", "about.me", "dev.to", "last.fm", "crates.io", "itch.io"):
        assert name not in vocabulary
    assert {"docker hub", "hugging face", "ko-fi"}.isdisjoint(vocabulary)
    assert {"chess_com", "wordpress_org", "docker_hub", "hugging_face"} <= vocabulary


@pytest.mark.parametrize(("domain", "slug"), [("chess.com", "chess_com"), ("wordpress.org", "wordpress_org")])
def test_a_domain_that_is_also_a_catalog_site_name_is_scrubbed(domain: str, slug: str) -> None:
    register_target_values(domain)
    ref = target_ref(domain)
    assert scrub_target_values(f"host={domain}") == f"host={ref}"
    assert scrub_target_values(f"GET https://{domain}/members") == f"GET https://{ref}/members"
    assert scrub_target_values(f"provider={slug} status=200") == f"provider={slug} status=200"


@pytest.mark.parametrize("line", ["xxalice_osint", "alice_osintyy", "user=xxalice_osint", "alice_osintyy=1"])
def test_a_registered_value_inside_a_longer_word_is_left_intact(line: str) -> None:
    """Fails without the lookaround: the value is long enough, only the boundary keeps it."""
    register_target_values("alice_osint")
    assert scrub_target_values(line) == line


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("pre-alice_osint", "pre-{ref}"),
        ("q=%2Falice_osint", "q=%2F{ref}"),
        ("alice_osint.example.com", "{ref}.example.com"),
    ],
)
def test_a_registered_value_next_to_a_delimiter_is_replaced(line: str, expected: str) -> None:
    register_target_values("alice_osint")
    assert scrub_target_values(line) == expected.format(ref=target_ref("alice_osint"))


def test_an_email_local_part_is_replaced_only_where_it_stands_alone() -> None:
    register_target_values("longlocal@example.com")
    ref = target_ref("longlocal@example.com")
    assert scrub_target_values("longlocalextra") == "longlocalextra"
    assert scrub_target_values("user longlocal here") == f"user {ref} here"
