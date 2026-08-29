from __future__ import annotations

from spectre_osint.core.entities import Entity
from spectre_osint.core.types import Confidence, EntityType


def test_entity_create_normalizes() -> None:
    entity = Entity.create(EntityType.EMAIL, "A@Example.COM", source="test", confidence=Confidence.CONFIRMED)
    assert entity.normalized_value == "a@example.com"
    assert entity.id == Entity.create(
        EntityType.EMAIL, "a@example.com", source="other", confidence=Confidence.LOW
    ).id
