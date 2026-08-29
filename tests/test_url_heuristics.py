from __future__ import annotations

from spectre_osint.core.validators import (
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    canonicalize_url,
    contains_punycode,
    looks_like_homoglyph,
)


def test_punycode_and_shortener() -> None:
    assert contains_punycode("xn--exmple-cua.com")
    assert "bit.ly" in URL_SHORTENERS
    assert "xyz" in SUSPICIOUS_TLDS
    assert looks_like_homoglyph("exаmple.com")  # cyrillic a
    parsed = canonicalize_url("https://bit.ly/abc")
    assert parsed.startswith("https://bit.ly/")
