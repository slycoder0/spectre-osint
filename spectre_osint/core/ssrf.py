"""Central egress policy: block SSRF, private networks, metadata and rebinding.

Public HTTP(S) only. Each hop (including redirects) is resolved and checked
against the same policy. Connections are pinned to an already-validated IP so
a second DNS lookup cannot rebind to loopback or link-local.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin, urlparse

from spectre_osint.core.exceptions import SSRFBlocked

BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",
        "metadata.goog",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)

CLOUD_METADATA_IPS = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "fd00:ec2::254",
    }
)

ALLOWED_SCHEMES = frozenset({"http", "https"})
MAX_REDIRECTS = 5

Resolver = Callable[[str], Awaitable[list[str]]]


def _normalize_ip(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    text = raw.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        pass
    if text.isdigit():
        return ipaddress.ip_address(int(text))
    raise ValueError(f"not an IP: {raw}")


def is_blocked_ip(raw: str) -> bool:
    try:
        ip = _normalize_ip(raw)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None:
            ip = mapped
    if str(ip) in CLOUD_METADATA_IPS:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv6Address) and getattr(ip, "is_site_local", False))
    )


def validate_url_syntax(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise SSRFBlocked(f"blocked scheme: {parsed.scheme or 'missing'}")
    if parsed.username or parsed.password:
        raise SSRFBlocked("URLs with embedded credentials are blocked")
    host = parsed.hostname
    if not host:
        raise SSRFBlocked("URL has no hostname")
    if parsed.port == 0:
        raise SSRFBlocked("invalid port")
    lowered = host.lower().rstrip(".")
    if lowered in BLOCKED_HOSTNAMES or lowered.endswith(".localhost"):
        raise SSRFBlocked(f"blocked hostname: {host}")
    if lowered.endswith(".internal") or lowered.endswith(".local"):
        raise SSRFBlocked(f"blocked hostname: {host}")
    try:
        ip = _normalize_ip(host)
    except ValueError:
        return
    if is_blocked_ip(str(ip)):
        raise SSRFBlocked(f"blocked IP literal: {host}")


async def default_resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFBlocked(f"DNS resolution failed for {host}: {exc}") from exc
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            ips.append(str(sockaddr[0]))
    if not ips:
        raise SSRFBlocked(f"no addresses for {host}")
    return list(dict.fromkeys(ips))


class SSRFPolicy:
    def __init__(
        self,
        *,
        allow_private: bool = False,
        resolver: Resolver | None = None,
        max_redirects: int = MAX_REDIRECTS,
    ) -> None:
        self.allow_private = allow_private
        self.resolver = resolver or default_resolve
        self.max_redirects = max_redirects

    async def check_url(self, url: str) -> list[str]:
        validate_url_syntax(url)
        parsed = urlparse(url)
        host = parsed.hostname or ""
        try:
            ip = _normalize_ip(host)
            ips = [str(ip)]
        except ValueError:
            ips = await self.resolver(host)
        if not self.allow_private:
            blocked = [ip for ip in ips if is_blocked_ip(ip)]
            if blocked:
                raise SSRFBlocked(f"blocked resolved address(es) {blocked} for {host}")
        return ips

    async def pin(self, url: str) -> tuple[str, str, list[str]]:
        """Return (pinned_url, original_host, resolved_ips)."""
        ips = await self.check_url(url)
        parsed = urlparse(url)
        host = parsed.hostname or ""
        pin_ip = ips[0]
        port = parsed.port
        if ":" in pin_ip and not pin_ip.startswith("["):
            hostport = f"[{pin_ip}]"
        else:
            hostport = pin_ip
        if port:
            hostport = f"{hostport}:{port}"
        pinned = parsed._replace(netloc=hostport).geturl()
        return pinned, host, ips

    def next_url(self, current: str, location: str) -> str:
        if not location:
            raise SSRFBlocked("redirect with empty Location")
        return urljoin(current, location)
