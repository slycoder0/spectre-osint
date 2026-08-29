from __future__ import annotations

from pathlib import Path

import pytest

from spectre_osint.core.exceptions import PathSafetyError, ValidationError
from spectre_osint.core.paths import report_path, slugify, validate_case_name


def test_slugify_strips_separators() -> None:
    assert ".." not in slugify("../etc/passwd")
    assert "/" not in slugify("a/b")
    assert "\\" not in slugify("a\\b")


def test_validate_case_name_rejects_traversal() -> None:
    with pytest.raises(PathSafetyError):
        validate_case_name("../secret")
    with pytest.raises(ValidationError):
        validate_case_name("  ")


def test_report_path_stays_inside_dir(tmp_path: Path) -> None:
    path = report_path(tmp_path, "case-https://example.com", "https://example.com/a", ".html")
    assert path.parent == tmp_path.resolve()
    assert path.suffix == ".html"
    assert ":" not in path.name
    assert "/" not in path.name
