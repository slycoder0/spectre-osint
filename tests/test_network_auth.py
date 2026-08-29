from __future__ import annotations

import pytest

from spectre_osint.core.exceptions import AuthorizationRequired
from spectre_osint.modules.network.recon import authorized_connect_scan


@pytest.mark.asyncio
async def test_active_recon_requires_authorized() -> None:
    with pytest.raises(AuthorizationRequired):
        await authorized_connect_scan("127.0.0.1", authorized=False)
