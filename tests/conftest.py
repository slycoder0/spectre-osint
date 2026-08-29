from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi(text: str) -> str:
    """Strip ANSI escape sequences from text for reliable cross-platform assertions."""
    return _ANSI_RE.sub("", text)

os.environ.setdefault("SPECTRE_DATA_DIR", str(Path(__file__).parent / "_tmp_data"))
os.environ.setdefault("SPECTRE_REPORTS_DIR", str(Path(__file__).parent / "_tmp_reports"))
os.environ.setdefault("SPECTRE_LOGS_DIR", str(Path(__file__).parent / "_tmp_logs"))
os.environ.setdefault("SPECTRE_DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SPECTRE_SSRF_ENABLED", "true")
os.environ.setdefault("SPECTRE_AUTH_DIR", str(Path(__file__).parent / "_tmp_auth"))
os.environ.setdefault(
    "SPECTRE_BROWSER_PROFILES_DIR", str(Path(__file__).parent / "_tmp_browser_profiles")
)
os.environ.setdefault(
    "SPECTRE_CHROME_PROFILES_DIR", str(Path(__file__).parent / "_tmp_chrome_profiles")
)
os.environ.setdefault("SPECTRE_BROWSER_BACKEND", "fake")
os.environ.setdefault("SPECTRE_KEYRING", "false")


@pytest.fixture(autouse=True)
def isolate_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRE_AUTH_DIR", str(tmp_path / "auth"))
    monkeypatch.setenv("SPECTRE_BROWSER_PROFILES_DIR", str(tmp_path / "browser-profiles"))
    monkeypatch.setenv("SPECTRE_CHROME_PROFILES_DIR", str(tmp_path / "chrome-profiles"))
    monkeypatch.setenv("SPECTRE_BROWSER_BACKEND", "fake")
    monkeypatch.setenv("SPECTRE_KEYRING", "false")
    from spectre_osint.browser.fake import FakeBrowserBackend, FakeCdpConnector, FakeChromeLauncher
    from spectre_osint.core.config import reload_settings

    FakeBrowserBackend.reset()
    FakeChromeLauncher.reset()
    FakeCdpConnector.reset()
    reload_settings()
    yield
    FakeBrowserBackend.reset()
    FakeChromeLauncher.reset()
    FakeCdpConnector.reset()


@pytest.fixture
def settings(tmp_path, monkeypatch):
    from spectre_osint.core.config import Settings, reload_settings
    from spectre_osint.core.database import reset_engine

    monkeypatch.setenv("SPECTRE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SPECTRE_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("SPECTRE_LOGS_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("SPECTRE_DATABASE_URL", f"sqlite:///{tmp_path / 't.db'}")
    monkeypatch.setenv("SPECTRE_AUTH_DIR", str(tmp_path / "auth"))
    monkeypatch.setenv("SPECTRE_BROWSER_PROFILES_DIR", str(tmp_path / "browser-profiles"))
    monkeypatch.setenv("SPECTRE_CHROME_PROFILES_DIR", str(tmp_path / "chrome-profiles"))
    monkeypatch.setenv("SPECTRE_BROWSER_BACKEND", "fake")
    monkeypatch.setenv("SPECTRE_KEYRING", "false")
    reset_engine()
    reload_settings()
    s = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
    )
    s.ensure_dirs()
    return s


@pytest.fixture
def isolated_db(settings):
    from spectre_osint.core.database import init_db, reset_engine

    init_db(settings)
    yield settings
    reset_engine()
