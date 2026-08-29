"""Optional ACTIVE recon. Disabled unless --authorized is passed.

Allowed: DNS (already passive), limited TCP connect + banner grab.
Forbidden: exploitation, brute force, credential attacks, mass scanning.
"""

from __future__ import annotations

import asyncio
from typing import Any

from spectre_osint.core.entities import Finding
from spectre_osint.core.exceptions import AuthorizationRequired
from spectre_osint.core.logger import get_logger
from spectre_osint.core.types import Confidence, FindingStatus

logger = get_logger("spectre.network")

DEFAULT_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 587, 993, 995, 3306, 8080)


async def authorized_connect_scan(
    host: str,
    *,
    authorized: bool,
    ports: tuple[int, ...] = DEFAULT_PORTS,
    timeout: float = 2.0,
) -> dict[str, Any]:
    if not authorized:
        raise AuthorizationRequired("Active recon requires --authorized")
    logger.warning(
        "ACTIVE RECON AUTHORIZED host=%s ports=%s — operator asserted authorization",
        host,
        ports,
    )
    open_ports: list[dict[str, Any]] = []

    async def probe(port: int) -> None:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            banner = b""
            try:
                banner = await asyncio.wait_for(reader.read(128), timeout=1.0)
            except Exception:
                banner = b""
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            open_ports.append(
                {
                    "port": port,
                    "state": "open",
                    "banner": banner.decode("latin-1", errors="replace")[:120],
                }
            )
        except Exception:
            return

    await asyncio.gather(*(probe(p) for p in ports))
    finding = Finding(
        module="network",
        title="Authorized TCP connect scan",
        status=FindingStatus.FOUND,
        summary=f"ACTIVE_RECON_AUTHORIZED open={ [p['port'] for p in open_ports] }",
        data={"host": host, "open_ports": sorted(open_ports, key=lambda x: x["port"]), "mode": "ACTIVE_RECON_AUTHORIZED"},
        confidence=Confidence.CONFIRMED,
    )
    return {
        "findings": [finding],
        "entities": [],
        "relationships": [],
        "evidence": [],
        "providers_queried": ["tcp-connect"],
    }
