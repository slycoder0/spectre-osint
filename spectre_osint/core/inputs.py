"""Operator-provided investigation inputs. Leads, not identity evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from spectre_osint.core.exceptions import ValidationError
from spectre_osint.core.types import EntityType
from spectre_osint.core.validators import (
    canonicalize_url,
    detect_entity_type,
    is_domain,
    is_email,
    is_url,
    is_username,
    normalize_domain,
    normalize_email,
    normalize_username,
)


@dataclass
class TargetInputs:
    primary: str
    primary_type: EntityType
    aliases: list[str] = field(default_factory=list)
    display_name: str | None = None
    email: str | None = None
    website: str | None = None
    website_type: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["primary_type"] = self.primary_type.value
        return payload

    @property
    def usernames(self) -> list[str]:
        if self.primary_type != EntityType.USERNAME:
            return []
        out = [self.primary]
        for alias in self.aliases:
            if alias not in out:
                out.append(alias)
        return out


def _clean(value: str | None) -> str:
    return str(value or "").strip()


def parse_target_inputs(
    primary: str,
    *,
    aliases: list[str] | None = None,
    display_name: str | None = None,
    email: str | None = None,
    website: str | None = None,
    force_type: EntityType | None = None,
) -> TargetInputs:
    raw = _clean(primary)
    if not raw:
        raise ValidationError("Primary target is required.")
    primary_type = force_type or detect_entity_type(raw)
    if primary_type == EntityType.USERNAME:
        raw = normalize_username(raw)
    elif primary_type == EntityType.EMAIL:
        raw = normalize_email(raw)
    elif primary_type == EntityType.DOMAIN:
        raw = normalize_domain(raw)
    elif primary_type == EntityType.URL:
        raw = canonicalize_url(raw)

    alias_out: list[str] = []
    seen = {raw.lower()} if primary_type == EntityType.USERNAME else set()
    for item in aliases or []:
        text = _clean(item)
        if not text:
            continue
        if not is_username(text):
            raise ValidationError(f"Invalid alias username: {item}")
        handle = normalize_username(text)
        if handle in seen:
            continue
        if primary_type != EntityType.USERNAME:
            raise ValidationError("Aliases are only valid when the primary target is a username.")
        seen.add(handle)
        alias_out.append(handle)

    name = _clean(display_name) or None
    mail = _clean(email) or None
    site = _clean(website) or None
    website_type: str | None = None
    if mail:
        if not is_email(mail):
            raise ValidationError(f"Invalid email: {email}")
        mail = normalize_email(mail)
    if site:
        if is_url(site):
            site = canonicalize_url(site)
            website_type = EntityType.URL.value
        elif is_domain(site):
            site = normalize_domain(site)
            website_type = EntityType.DOMAIN.value
        else:
            raise ValidationError(f"Invalid website/domain: {website}")

    return TargetInputs(
        primary=raw,
        primary_type=primary_type,
        aliases=alias_out,
        display_name=name,
        email=mail,
        website=site,
        website_type=website_type,
    )


def inputs_from_mapping(data: dict[str, Any] | None, *, fallback_target: str) -> TargetInputs:
    raw = data or {}
    primary = str(raw.get("primary") or fallback_target)
    force = None
    ptype = raw.get("primary_type")
    if isinstance(ptype, str) and ptype in EntityType._value2member_map_:
        force = EntityType(ptype)
    return parse_target_inputs(
        primary,
        aliases=list(raw.get("aliases") or []),
        display_name=raw.get("display_name"),
        email=raw.get("email"),
        website=raw.get("website"),
        force_type=force,
    )
