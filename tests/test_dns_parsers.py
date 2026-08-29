from __future__ import annotations

from spectre_osint.modules.dns.parsers import identify_mail_provider, parse_dmarc, parse_spf


def test_parse_spf() -> None:
    parsed = parse_spf(["v=spf1 include:_spf.google.com include:sendgrid.net -all"])
    assert parsed["present"] is True
    assert parsed["all_qualifier"] == "-"
    assert "_spf.google.com" in parsed["includes"]


def test_parse_spf_missing() -> None:
    parsed = parse_spf(["something else"])
    assert parsed["present"] is False


def test_parse_dmarc() -> None:
    parsed = parse_dmarc(["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"])
    assert parsed["present"] is True
    assert parsed["policy"] == "reject"
    assert parsed["rua"] == "mailto:dmarc@example.com"


def test_mail_provider_from_mx() -> None:
    providers = identify_mail_provider(["example-com.mail.protection.outlook.com"])
    assert "Microsoft 365" in providers
    providers = identify_mail_provider(["aspmx.l.google.com"])
    assert "Google Workspace" in providers
