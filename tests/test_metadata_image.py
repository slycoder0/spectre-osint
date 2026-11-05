"""Image metadata extraction against a synthetic PNG (safety net for the Pillow pin)."""

from __future__ import annotations

from pathlib import Path

from PIL import Image

from spectre_osint.core.types import EntityType
from spectre_osint.modules.metadata.extractor import analyze_metadata


def test_png_metadata_reports_format_size_and_mode(tmp_path: Path) -> None:
    path = tmp_path / "alice_example.png"
    Image.new("RGB", (4, 3), color=(10, 20, 30)).save(path, format="PNG")

    result = analyze_metadata(path)

    (finding,) = result["findings"]
    assert finding.data["suffix"] == ".png"
    assert finding.data["image_format"] == "PNG"
    assert finding.data["image_size"] == [4, 3]
    assert finding.data["image_mode"] == "RGB"
    assert "gps_present" not in finding.data
    assert result["target_entity"].type is EntityType.FILE


def test_corrupt_png_does_not_raise(tmp_path: Path) -> None:
    path = tmp_path / "broken.png"
    path.write_bytes(b"not really a png")

    (finding,) = analyze_metadata(path)["findings"]

    assert finding.data["suffix"] == ".png"
    assert "image_format" not in finding.data
