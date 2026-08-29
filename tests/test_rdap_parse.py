from __future__ import annotations

from spectre_osint.providers.rdap import _summarize_rdap


def test_rdap_domain_summary() -> None:
    payload = {
        "ldhName": "EXAMPLE.COM",
        "status": ["active"],
        "nameservers": [{"ldhName": "ns1.example.net."}],
        "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            }
        ],
    }
    summary = _summarize_rdap(payload)
    assert summary["registrar"] == "Example Registrar"
    assert "ns1.example.net" in summary["nameservers"]
    assert summary["events"][0]["action"] == "registration"
