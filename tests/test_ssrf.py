from __future__ import annotations

import pytest

from spectre_osint.core.exceptions import SSRFBlocked
from spectre_osint.core.ssrf import SSRFPolicy, is_blocked_ip, validate_url_syntax


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://[::1]/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "http://127.0.0.1:8080/",
        "http://user:pass@example.com/",
    ],
)
def test_validate_url_syntax_blocks(url: str) -> None:
    with pytest.raises(SSRFBlocked):
        validate_url_syntax(url)


def test_public_https_syntax_ok() -> None:
    validate_url_syntax("https://example.com/path")


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "10.1.2.3", "169.254.169.254", "172.16.0.9"])
def test_blocked_ips(ip: str) -> None:
    assert is_blocked_ip(ip)


@pytest.mark.asyncio
async def test_redirect_to_loopback_is_blocked() -> None:
    policy = SSRFPolicy(allow_private=False)

    async def resolver(host: str) -> list[str]:
        if host == "example.com":
            return ["93.184.216.34"]
        return ["127.0.0.1"]

    policy.resolver = resolver
    await policy.check_url("https://example.com/")
    nxt = policy.next_url("https://example.com/", "http://127.0.0.1/secret")
    with pytest.raises(SSRFBlocked):
        await policy.check_url(nxt)


@pytest.mark.asyncio
async def test_dns_rebinding_first_answer_private() -> None:
    policy = SSRFPolicy(allow_private=False)

    async def resolver(_host: str) -> list[str]:
        return ["8.8.8.8", "127.0.0.1"]

    policy.resolver = resolver
    with pytest.raises(SSRFBlocked):
        await policy.check_url("https://evil.example/")


@pytest.mark.asyncio
async def test_pin_uses_validated_public_ip() -> None:
    policy = SSRFPolicy(allow_private=False)

    async def resolver(_host: str) -> list[str]:
        return ["93.184.216.34"]

    policy.resolver = resolver
    pinned, host, ips = await policy.pin("https://example.com/x")
    assert host == "example.com"
    assert "93.184.216.34" in pinned
    assert ips == ["93.184.216.34"]
