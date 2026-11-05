"""Version strings stay aligned with ``__version__`` (B2-05).

The beta release must not advertise itself as ``alpha`` in the HTTP user agent,
packaging metadata, the Docker image tag or the config templates.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from spectre_osint import __version__
from spectre_osint.core.config import PROJECT_ROOT, Settings
from spectre_osint.core.http_client import load_user_agents


def _read(name: str) -> str:
    return (PROJECT_ROOT / name).read_text(encoding="utf-8")


def _pyproject() -> dict:
    return tomllib.loads(_read("pyproject.toml"))


def test_default_user_agent_tracks_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SPECTRE_USER_AGENT", raising=False)
    ua = Settings(_env_file=None).user_agent
    assert __version__ in ua
    assert "alpha" not in ua.lower()


def test_user_agent_fallback_tracks_version(tmp_path: Path) -> None:
    fallback = load_user_agents(tmp_path / "missing.txt")
    assert len(fallback) == 1
    assert __version__ in fallback[0]
    assert "alpha" not in fallback[0].lower()


def test_bundled_user_agents_tracks_version() -> None:
    spectre_agents = [ua for ua in load_user_agents() if ua.startswith("SPECTRE-OSINT/")]
    assert spectre_agents
    for ua in spectre_agents:
        assert __version__ in ua
        assert "alpha" not in ua.lower()


def test_packaging_metadata_is_beta_and_lists_windows() -> None:
    project = _pyproject()["project"]
    assert "alpha" not in project["description"].lower()
    classifiers = project["classifiers"]
    assert "Development Status :: 4 - Beta" in classifiers
    assert not any("3 - Alpha" in c for c in classifiers)
    assert "Operating System :: Microsoft :: Windows" in classifiers


def test_pillow_pin_excludes_the_vulnerable_series() -> None:
    deps = _pyproject()["project"]["dependencies"]
    (pillow,) = [d for d in deps if d.lower().startswith("pillow")]
    assert re.fullmatch(r"Pillow>=13\.0\.0,<14", pillow)


def test_docker_image_and_env_template_have_no_alpha_tag() -> None:
    compose = _read("docker-compose.yml")
    assert f"spectre-osint:{__version__}" in compose
    env_example = _read(".env.example")
    assert "alpha" not in env_example.lower()
    assert f"SPECTRE-OSINT/{__version__}" in env_example
