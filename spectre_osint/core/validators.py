"""Input validation and entity auto-detection.

Normalization rules:
- domains lowercase, no trailing dot, no scheme
- emails lowercase
- URLs canonical
- IPs via ipaddress
- hashes lowercase hex
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlparse, urlunparse

import tldextract

from spectre_osint.core.exceptions import ValidationError
from spectre_osint.core.types import EntityType

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
_HASH_RE = re.compile(r"^[A-Fa-f0-9]+$")
_DOMAIN_LABEL_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
_ASN_RE = re.compile(r"^(AS)?(\d{1,10})$", re.IGNORECASE)
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\-\s()]{6,20}$")

HASH_LENGTHS: dict[int, str] = {
    32: "MD5",
    40: "SHA1",
    64: "SHA256",
    128: "SHA512",
}

SUSPICIOUS_TLDS = frozenset(
    {
        "zip",
        "mov",
        "xyz",
        "top",
        "click",
        "country",
        "gq",
        "tk",
        "ml",
        "cf",
        "ga",
        "work",
        "rest",
        "fit",
        "quest",
        "cfd",
        "sbs",
        "cyou",
        "buzz",
        "icu",
        "cam",
        "lol",
        "monster",
        "bond",
        "shop",
    }
)

URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "rb.gy",
        "lnkd.in",
    }
)


def normalize_domain(value: str) -> str:
    raw = value.strip().lower()
    raw = raw.removeprefix("http://").removeprefix("https://")
    raw = raw.split("/")[0]
    raw = raw.split(":")[0]
    raw = raw.rstrip(".")
    if raw.startswith("www."):
        # Keep www as a distinct hostname; callers may also store the registrable domain.
        pass
    extracted = tldextract.extract(raw)
    if not extracted.suffix:
        raise ValidationError(f"Not a valid domain: {value}")
    return raw


def registrable_domain(value: str) -> str:
    extracted = tldextract.extract(normalize_domain(value))
    if not extracted.domain or not extracted.suffix:
        raise ValidationError(f"Cannot derive registrable domain from: {value}")
    return f"{extracted.domain}.{extracted.suffix}"


def is_domain(value: str) -> bool:
    try:
        normalize_domain(value)
        return True
    except ValidationError:
        return False


def normalize_email(value: str) -> str:
    email = value.strip().lower()
    if not _EMAIL_RE.match(email):
        raise ValidationError(f"Not a valid email: {value}")
    return email


def is_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value.strip()))


def normalize_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValidationError(f"Not a valid IP: {value}") from exc
    return str(ip)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def ip_version(value: str) -> int:
    return ipaddress.ip_address(normalize_ip(value)).version


def is_private_ip(value: str) -> bool:
    ip = ipaddress.ip_address(normalize_ip(value))
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)


def detect_hash_algo(value: str) -> str:
    digest = value.strip().lower()
    if not _HASH_RE.match(digest):
        raise ValidationError(f"Not a hex hash: {value}")
    algo = HASH_LENGTHS.get(len(digest))
    if not algo:
        raise ValidationError(f"Unsupported hash length {len(digest)}")
    return algo


def normalize_hash(value: str) -> str:
    detect_hash_algo(value)
    return value.strip().lower()


def is_hash(value: str) -> bool:
    try:
        detect_hash_algo(value)
        return True
    except ValidationError:
        return False


def canonicalize_url(value: str) -> str:
    raw = value.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationError(f"Unsupported URL scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValidationError(f"Not a valid URL: {value}")
    host = parsed.hostname or ""
    # Keep punycode form as-is; still lowercase the host.
    netloc = host.lower()
    if parsed.port and parsed.port not in {80, 443}:
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path or "/"
    canonical = urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))
    return canonical


def is_url(value: str) -> bool:
    candidate = value.strip()
    if "://" not in candidate and not candidate.startswith("www."):
        return False
    try:
        canonicalize_url(candidate)
        return True
    except ValidationError:
        return False


def normalize_username(value: str) -> str:
    username = value.strip()
    if username.startswith("@"):
        username = username[1:]
    if not _USERNAME_RE.match(username):
        raise ValidationError(f"Not a valid username: {value}")
    return username.lower()


def is_username(value: str) -> bool:
    candidate = value.strip().lstrip("@")
    if is_email(candidate) or is_ip(candidate) or is_hash(candidate) or is_url(candidate):
        return False
    if "." in candidate and is_domain(candidate):
        return False
    return bool(_USERNAME_RE.match(candidate))


def normalize_asn(value: str) -> str:
    match = _ASN_RE.match(value.strip())
    if not match:
        raise ValidationError(f"Not a valid ASN: {value}")
    return f"AS{int(match.group(2))}"


def is_asn(value: str) -> bool:
    return bool(_ASN_RE.match(value.strip()))


def is_phone(value: str) -> bool:
    return bool(_PHONE_RE.match(value.strip()))


def entity_id(entity_type: EntityType, normalized_value: str) -> str:
    material = f"{entity_type}:{normalized_value}".encode()
    return hashlib.sha256(material).hexdigest()[:24]


def detect_entity_type(value: str) -> EntityType:
    """Best-effort type detection. Ambiguous values raise ValidationError."""
    raw = value.strip()
    if not raw:
        raise ValidationError("Empty target")
    if is_hash(raw):
        return EntityType.HASH
    if is_ip(raw):
        return EntityType.IP
    if is_email(raw):
        return EntityType.EMAIL
    if is_url(raw):
        return EntityType.URL
    if is_asn(raw):
        return EntityType.ASN
    if is_domain(raw):
        return EntityType.DOMAIN
    if is_username(raw):
        return EntityType.USERNAME
    if is_phone(raw):
        return EntityType.PHONE
    # Quoted company names or multi-word strings are companies.
    if " " in raw or len(raw) > 3:
        return EntityType.COMPANY
    raise ValidationError(f"Unable to detect entity type for: {value}")


def normalize_for_type(entity_type: EntityType, value: str) -> str:
    mapping = {
        EntityType.DOMAIN: normalize_domain,
        EntityType.SUBDOMAIN: normalize_domain,
        EntityType.EMAIL: normalize_email,
        EntityType.IP: normalize_ip,
        EntityType.URL: canonicalize_url,
        EntityType.HASH: normalize_hash,
        EntityType.USERNAME: normalize_username,
        EntityType.ASN: normalize_asn,
        EntityType.COMPANY: lambda v: re.sub(r"\s+", " ", v.strip()),
        EntityType.PERSON: lambda v: re.sub(r"\s+", " ", v.strip()),
        EntityType.ORGANIZATION: lambda v: re.sub(r"\s+", " ", v.strip()),
    }
    handler = mapping.get(entity_type)
    if handler is None:
        return value.strip()
    return handler(value)


def contains_punycode(host: str) -> bool:
    return "xn--" in host.lower()


def looks_like_homoglyph(host: str) -> bool:
    """Flag mixed-script or unusual unicode in hostnames. Heuristic only."""
    try:
        host.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True
