from __future__ import annotations

import pytest

from spectre_osint.core.exceptions import ValidationError
from spectre_osint.core.types import EntityType
from spectre_osint.core.validators import (
    canonicalize_url,
    detect_entity_type,
    detect_hash_algo,
    entity_id,
    is_private_ip,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ip,
    normalize_username,
    registrable_domain,
)


def test_normalize_domain_strips_scheme_and_dot() -> None:
    assert normalize_domain("HTTPS://WWW.Example.COM.") == "www.example.com"
    assert registrable_domain("www.example.com") == "example.com"


def test_invalid_domain() -> None:
    with pytest.raises(ValidationError):
        normalize_domain("not a domain")


def test_email() -> None:
    assert normalize_email("  User@Example.COM ") == "user@example.com"
    with pytest.raises(ValidationError):
        normalize_email("not-an-email")


def test_ip() -> None:
    assert normalize_ip("8.8.8.8") == "8.8.8.8"
    assert is_private_ip("127.0.0.1")
    assert is_private_ip("10.0.0.5")
    assert not is_private_ip("1.1.1.1")
    with pytest.raises(ValidationError):
        normalize_ip("999.1.1.1")


def test_hash_types() -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert detect_hash_algo(md5) == "MD5"
    assert detect_hash_algo(sha1) == "SHA1"
    assert detect_hash_algo(sha256) == "SHA256"
    assert normalize_hash(md5.upper()) == md5


def test_url_canonical() -> None:
    assert canonicalize_url("https://Example.COM/Path/") == "https://example.com/Path/"
    assert canonicalize_url("example.com") == "https://example.com/"


def test_username() -> None:
    assert normalize_username("@octocat") == "octocat"


def test_detect_types() -> None:
    assert detect_entity_type("8.8.8.8") == EntityType.IP
    assert detect_entity_type("user@example.com") == EntityType.EMAIL
    assert detect_entity_type("example.com") == EntityType.DOMAIN
    assert detect_entity_type("https://example.com/a") == EntityType.URL
    assert detect_entity_type("d41d8cd98f00b204e9800998ecf8427e") == EntityType.HASH
    assert detect_entity_type("octocat") == EntityType.USERNAME
    assert detect_entity_type("AS15169") == EntityType.ASN
    assert detect_entity_type("Acme Corp") == EntityType.COMPANY


def test_entity_id_is_stable() -> None:
    a = entity_id(EntityType.DOMAIN, "example.com")
    b = entity_id(EntityType.DOMAIN, "example.com")
    assert a == b
    assert a != entity_id(EntityType.IP, "1.1.1.1")
