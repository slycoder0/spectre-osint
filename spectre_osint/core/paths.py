"""Safe case names and report artifact paths. Prevents traversal and nested dirs."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from spectre_osint.core.exceptions import PathSafetyError, ValidationError

_UNSAFE = re.compile(r"[^a-zA-Z0-9._-]+")
_MAX_SLUG = 48


def slugify(value: str, *, max_length: int = _MAX_SLUG) -> str:
    text = (value or "").strip()
    text = text.replace("\\", "_").replace("/", "_")
    text = text.replace("..", "_").replace(":", "_")
    text = _UNSAFE.sub("-", text).strip("-._")
    if not text:
        text = "unnamed"
    if len(text) > max_length:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
        text = f"{text[: max_length - 11].rstrip('-._')}-{digest}"
    return text.lower()


def validate_case_name(name: str) -> str:
    if not name or not name.strip():
        raise ValidationError("Case name is empty")
    if any(sep in name for sep in ("/", "\\", "..")):
        raise PathSafetyError("Case name must not contain path separators or '..'")
    slug = slugify(name, max_length=80)
    if slug in {".", ".."}:
        raise PathSafetyError("Invalid case name")
    return slug


def artifact_stem(case_name: str, target: str) -> str:
    digest = hashlib.sha256(f"{case_name}|{target}".encode()).hexdigest()[:12]
    return f"{slugify(case_name, max_length=32)}-{slugify(target, max_length=32)}-{digest}"


def report_path(reports_dir: Path, case_name: str, target: str, suffix: str) -> Path:
    base = reports_dir.expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True)
    if not suffix.startswith((".", "-")):
        suffix = f".{suffix}"
    filename = artifact_stem(case_name, target) + suffix
    path = (base / filename).resolve()
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise PathSafetyError(f"artifact escaped reports dir: {path}") from exc
    return path
