"""SPF / DMARC parsers and mail-provider identification from public records."""

from __future__ import annotations

import re
from typing import Any

_SPF_MECH = re.compile(
    r"(?P<qual>[+\-~?])?(?P<mech>include|exists|redirect|ip4|ip6|all|ptr|exp|mx|a)\b(?::(?P<value>\S+))?",
    re.IGNORECASE,
)

MAIL_PROVIDERS: dict[str, str] = {
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "mail.protection.outlook.com": "Microsoft 365",
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "aspmx.l.google.com": "Google Workspace",
    "protonmail.ch": "Proton",
    "proton.me": "Proton",
    "zoho.com": "Zoho",
    "zoho.eu": "Zoho",
    "amazonses.com": "AWS SES",
    "sendgrid.net": "SendGrid",
    "mailgun.org": "Mailgun",
    "emailsrvr.com": "Rackspace",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "messagelabs.com": "Symantec / MessageLabs",
}


def parse_spf(records: list[str]) -> dict[str, Any]:
    joined = " ".join(records)
    spf_txt = next((r for r in records if r.lower().startswith("v=spf1")), None)
    if not spf_txt:
        return {"present": False, "record": None, "mechanisms": []}
    mechanisms = []
    for match in _SPF_MECH.finditer(spf_txt):
        mechanisms.append(
            {
                "qualifier": match.group("qual") or "+",
                "mechanism": match.group("mech").lower(),
                "value": match.group("value"),
            }
        )
    includes = [m["value"] for m in mechanisms if m["mechanism"] == "include" and m["value"]]
    return {
        "present": True,
        "record": spf_txt,
        "mechanisms": mechanisms,
        "includes": includes,
        "all_qualifier": next((m["qualifier"] for m in mechanisms if m["mechanism"] == "all"), None),
        "raw_all": joined,
    }


def parse_dmarc(records: list[str]) -> dict[str, Any]:
    dmarc = next((r for r in records if r.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        return {"present": False, "record": None}
    tags: dict[str, str] = {}
    for part in dmarc.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return {
        "present": True,
        "record": dmarc,
        "policy": tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "rua": tags.get("rua"),
        "ruf": tags.get("ruf"),
        "pct": tags.get("pct"),
        "adkim": tags.get("adkim"),
        "aspf": tags.get("aspf"),
        "tags": tags,
    }


def identify_mail_provider(mx_hosts: list[str], spf_includes: list[str] | None = None) -> list[str]:
    haystack = [h.lower().rstrip(".") for h in mx_hosts]
    haystack.extend(spf_includes or [])
    found: list[str] = []
    for fragment, name in MAIL_PROVIDERS.items():
        if any(fragment in host for host in haystack) and name not in found:
            found.append(name)
    return found
