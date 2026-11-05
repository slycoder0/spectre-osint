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
