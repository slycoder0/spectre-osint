from __future__ import annotations

from spectre_osint.providers.crtsh import _parse_certificates


def test_crtsh_dedup_and_sans() -> None:
    rows = [
        {
            "id": 1,
            "name_value": "example.com\nwww.example.com",
            "common_name": "example.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2024-04-01T00:00:00",
        },
        {
            "id": 1,
            "name_value": "example.com",
            "common_name": "example.com",
        },
        {
            "id": 2,
            "name_value": "*.api.example.com",
            "common_name": "api.example.com",
            "not_before": "2025-01-01T00:00:00",
        },
    ]
    parsed = _parse_certificates(rows, "example.com")
    assert parsed["subdomains"] == ["api.example.com", "example.com", "www.example.com"]
    assert len(parsed["certificates"]) == 2
