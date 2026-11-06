"""B2-08: domain validation must never touch the network.

``tldextract`` fetches the Public Suffix List on its own (via ``requests``) when its disk cache
is empty. That bypasses ``HttpClient`` (SSRF policy, honest User-Agent), makes tests depend on
the network and, offline, prints a traceback to stderr. ``core/validators.py`` must use only the
snapshot shipped inside the package.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import requests
import tldextract
from tldextract import tldextract as tldextract_impl

from spectre_osint.core import validators
from spectre_osint.core.validators import normalize_domain, registrable_domain

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every connection attempt and make it fail like an offline machine."""
    attempts: list[str] = []

    def fail_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        attempts.append(f"getaddrinfo:{host}")
        raise socket.gaierror(11001, "offline (test)")

    def fail_send(self, request, **kwargs):  # noqa: ANN001, ANN003
        attempts.append(f"requests:{request.url}")
        raise requests.exceptions.ConnectionError("offline (test)")

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)
    monkeypatch.setattr(requests.Session, "send", fail_send)
    return attempts


@pytest.fixture
def cold_tldextract_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Empty on-disk cache, as on a fresh machine or CI runner."""
    cache = tmp_path / "tldextract-cache"
    cache.mkdir()
    monkeypatch.setenv("TLDEXTRACT_CACHE", str(cache))
    # The library's own module-level extractor memoizes its list; give it a cold one so the
    # pre-fix code path (``tldextract.extract``) really hits the "no cache" branch.
    monkeypatch.setattr(
        tldextract_impl, "TLD_EXTRACTOR", tldextract.TLDExtract(cache_dir=str(cache))
    )
    return cache


def test_domain_validation_makes_no_connection_with_cold_cache(
    no_network: list[str],
    cold_tldextract_cache: Path,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
) -> None:
    with caplog.at_level(logging.DEBUG):
        assert normalize_domain("sub.example.co.uk") == "sub.example.co.uk"
        assert registrable_domain("sub.example.co.uk") == "example.co.uk"

    assert no_network == []
    assert [r for r in caplog.records if r.name.startswith("tldextract")] == []
    out, err = capfd.readouterr()
    assert "Public Suffix" not in err
    assert err == ""
    assert list(cold_tldextract_cache.iterdir()) == [], "must not write a tldextract disk cache"


def test_validators_extractor_is_configured_offline() -> None:
    """Guard on the configuration itself: no URLs to fetch, no disk cache."""
    extractor = validators._TLD_EXTRACT
    assert tuple(extractor.suffix_list_urls) == ()
    assert extractor.fallback_to_snapshot is True
    assert extractor._cache.enabled is False  # noqa: SLF001


_CHILD = """
import json, socket

attempts = []

def _fail(host, *args, **kwargs):
    attempts.append(str(host))
    raise socket.gaierror(11001, "offline (test)")

socket.getaddrinfo = _fail

from spectre_osint.core.validators import normalize_domain, registrable_domain

print(json.dumps({
    "normalized": normalize_domain("sub.example.co.uk"),
    "registrable": registrable_domain("sub.example.co.uk"),
    "attempts": attempts,
}))
"""


def test_fresh_process_offline_prints_nothing_to_stderr(tmp_path: Path) -> None:
    """The user-visible symptom: a traceback on stderr from a cold, offline first run."""
    cache = tmp_path / "tldextract-cache"
    cache.mkdir()
    env = {**os.environ, "TLDEXTRACT_CACHE": str(cache)}
    # Leave the library's own URL override unset so its default (the two remote URLs) is what
    # the pre-fix code would have used.
    env.pop("TLDEXTRACT_PUBLIC_SUFFIX_LIST_URLS", None)

    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _CHILD],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    assert data == {
        "normalized": "sub.example.co.uk",
        "registrable": "example.co.uk",
        "attempts": [],
    }
