"""Evidence-backed links from a public profile website field.

Same-session or same-case membership is never treated as a relationship.
Same username on two platforms is possible_match only when an adapter says so.
"""

from __future__ import annotations

from urllib.parse import urlparse

from spectre_osint.core.entities import Entity, Relationship
from spectre_osint.core.types import Confidence, EntityType, RelationType
from spectre_osint.core.validators import is_domain, is_url, normalize_domain

_PLATFORM_HOSTS = frozenset(
    {
        "github.com",
        "www.github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeberg.org",
        "twitter.com",
        "x.com",
        "instagram.com",
        "www.instagram.com",
        "facebook.com",
        "www.facebook.com",
        "tiktok.com",
        "www.tiktok.com",
        "reddit.com",
        "www.reddit.com",
        "youtube.com",
        "www.youtube.com",
        "twitch.tv",
        "www.twitch.tv",
        "linkedin.com",
        "www.linkedin.com",
    }
)


def normalize_public_website(raw: str | None) -> str | None:
    if not raw or not str(raw).strip():
        return None
    text = str(raw).strip()
    if text.startswith("//"):
        text = "https:" + text
    if not text.lower().startswith(("http://", "https://")):
        text = "https://" + text
    if not is_url(text):
        return None
    parsed = urlparse(text)
    host = (parsed.hostname or "").lower()
    if not host or host in _PLATFORM_HOSTS:
        return None
    return text


def link_public_website(
    source_entity: Entity,
    raw_url: str | None,
    *,
    source: str,
    evidence_id: str | None,
    confidence: Confidence,
) -> dict:
    url = normalize_public_website(raw_url)
    entities: list[Entity] = []
    relationships: list[Relationship] = []
    if not url:
        return {"entities": entities, "relationships": relationships}
    url_entity = Entity.create(
        EntityType.URL,
        url,
        source=source,
        confidence=confidence,
        tags=["public-website"],
        metadata={"from_profile": source_entity.normalized_value},
    )
    entities.append(url_entity)
    relationships.append(
        Relationship(
            from_entity_id=source_entity.id,
            to_entity_id=url_entity.id,
            relation=RelationType.LINKS_TO,
            source=source,
            confidence=confidence,
            evidence_id=evidence_id,
            metadata={"field": "website", "not_identity": True},
        )
    )
    host = urlparse(url).hostname or ""
    if is_domain(host):
        domain = Entity.create(
            EntityType.DOMAIN,
            normalize_domain(host),
            source=source,
            confidence=confidence,
            tags=["public-website"],
        )
        entities.append(domain)
        relationships.append(
            Relationship(
                from_entity_id=source_entity.id,
                to_entity_id=domain.id,
                relation=RelationType.LINKS_TO,
                source=source,
                confidence=confidence,
                evidence_id=evidence_id,
                metadata={"field": "website_host", "not_identity": True},
            )
        )
    return {"entities": entities, "relationships": relationships}
