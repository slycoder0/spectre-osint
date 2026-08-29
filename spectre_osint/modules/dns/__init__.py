from spectre_osint.modules.dns.parsers import identify_mail_provider, parse_dmarc, parse_spf
from spectre_osint.modules.dns.resolver import DNSResult, resolve_dns

__all__ = ["DNSResult", "identify_mail_provider", "parse_dmarc", "parse_spf", "resolve_dns"]
