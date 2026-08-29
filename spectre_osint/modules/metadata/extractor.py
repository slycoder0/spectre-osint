"""Metadata extraction for user-supplied files only. No macros, no active content."""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Any

from spectre_osint.core.entities import Entity, Finding
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.types import Confidence, EntityType, FindingStatus

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def analyze_metadata(path: str | Path) -> dict[str, Any]:
    file_path = Path(path).expanduser().resolve()
    if not file_path.exists() or not file_path.is_file():
        raise FileNotFoundError(str(file_path))
    suffix = file_path.suffix.lower()
    data: dict[str, Any] = {
        "filename": file_path.name,
        "size": file_path.stat().st_size,
        "suffix": suffix,
    }
    if suffix in {".jpg", ".jpeg", ".png", ".tif", ".tiff"}:
        data.update(_image_meta(file_path))
    elif suffix == ".pdf":
        data.update(_pdf_meta(file_path))
    elif suffix in {".docx", ".xlsx", ".pptx"}:
        data.update(_ooxml_meta(file_path))
    else:
        data["note"] = "Unsupported type for structured metadata — file was not executed"

    emails = sorted(set(EMAIL_RE.findall(str(data))))
    urls = sorted(set(URL_RE.findall(str(data))))
    data["emails"] = emails
    data["urls"] = urls

    entity = Entity.create(
        EntityType.FILE,
        str(file_path),
        source="local-file",
        confidence=Confidence.CONFIRMED,
        metadata={"filename": file_path.name},
    )
    evidence = make_evidence(
        source="Local file metadata",
        provider="metadata",
        confidence=Confidence.CONFIRMED,
        raw={"filename": file_path.name, "keys": list(data.keys())},
        entity_id=entity.id,
    )
    finding = Finding(
        module="metadata",
        title=f"Metadata {file_path.name}",
        status=FindingStatus.FOUND,
        summary=f"extracted keys={list(data.keys())}",
        data=data,
        confidence=Confidence.CONFIRMED,
        entity_id=entity.id,
    )
    return {
        "findings": [finding],
        "entities": [entity],
        "relationships": [],
        "evidence": [evidence],
        "providers_queried": ["metadata"],
        "target_entity": entity,
    }


def _image_meta(path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        import exifread

        with path.open("rb") as handle:
            tags = exifread.process_file(handle, details=False)
        for key, value in tags.items():
            if "thumbnail" in key.lower():
                continue
            out[str(key)] = str(value)[:500]
        gps_lat = tags.get("GPS GPSLatitude")
        gps_lon = tags.get("GPS GPSLongitude")
        if gps_lat and gps_lon:
            out["gps_present"] = True
            out["GPSLatitude"] = str(gps_lat)
            out["GPSLongitude"] = str(gps_lon)
    except Exception as exc:  # noqa: BLE001
        out["exif_error"] = str(exc)
    try:
        from PIL import Image

        with Image.open(path) as img:
            out["image_format"] = img.format
            out["image_size"] = list(img.size)
            out["image_mode"] = img.mode
    except Exception:
        pass
    return out


def _pdf_meta(path: Path) -> dict[str, Any]:
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        info: Any = reader.metadata or {}
        return {
            "author": getattr(info, "author", None),
            "creator": getattr(info, "creator", None),
            "producer": getattr(info, "producer", None),
            "title": getattr(info, "title", None),
            "creation_date": str(getattr(info, "creation_date", "") or ""),
            "mod_date": str(getattr(info, "modification_date", "") or ""),
            "pages": len(reader.pages),
        }
    except Exception as exc:  # noqa: BLE001
        return {"pdf_error": str(exc)}


def _ooxml_meta(path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        with zipfile.ZipFile(path) as zf:
            if "docProps/core.xml" in zf.namelist():
                xml = zf.read("docProps/core.xml").decode("utf-8", errors="replace")
                for tag in ("creator", "lastModifiedBy", "created", "modified", "title"):
                    match = re.search(rf"<{tag}[^>]*>([^<]+)</{tag}>", xml)
                    if match:
                        out[tag] = match.group(1)
            if "docProps/app.xml" in zf.namelist():
                xml = zf.read("docProps/app.xml").decode("utf-8", errors="replace")
                match = re.search(r"<Application>([^<]+)</Application>", xml)
                if match:
                    out["software"] = match.group(1)
    except Exception as exc:  # noqa: BLE001
        out["ooxml_error"] = str(exc)
    return out
