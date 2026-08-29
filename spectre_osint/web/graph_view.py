"""Presentation-only aggregated graph. Never mutates persisted entities."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from spectre_osint.core.entities import InvestigationResult
from spectre_osint.core.presentation import username_rows
from spectre_osint.core.types import EntityType, RelationType

FOCUS_RELATIONS = {
    RelationType.HAS_PROFILE.value,
    RelationType.LINKS_TO.value,
    RelationType.IDENTITY_LINK.value,
}
OPERATOR_RELATIONS = {
    RelationType.OPERATOR_PROVIDED_ALIAS.value,
    RelationType.OPERATOR_PROVIDED_INPUT.value,
}

_SHAPE = {
    "target": "circle-lg",
    "username": "circle",
    "profile": "circle",
    "domain": "diamond",
    "email": "square",
    "ip": "hexagon",
    "person": "dashed-circle",
    "mention": "circle-sm",
    "other": "circle-sm",
}


def _etype(entity: Any) -> str:
    kind = getattr(entity, "type", "")
    return str(getattr(kind, "value", kind) or "")


def _host(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _norm_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    path = (parsed.path or "/").rstrip("/") or "/"
    return f"{host}{path}"


def aggregated_graph(result: InvestigationResult) -> dict[str, Any]:
    """Build a visual graph. Leaves result.entities / relationships untouched."""
    rows = username_rows(result)
    by_url: dict[str, dict[str, Any]] = {}
    for row in rows:
        url = _norm_url(str(row.get("profile_url") or ""))
        if url:
            by_url[url] = row

    visual: dict[str, dict[str, Any]] = {}
    entity_map: dict[str, str] = {}

    def add_visual(vid: str, **payload: Any) -> dict[str, Any]:
        node = visual.get(vid)
        if node is None:
            node = {
                "id": vid,
                "entity_ids": [],
                "urls": [],
                "domains": [],
                "relations": [],
                "evidence": [],
                **payload,
            }
            visual[vid] = node
        else:
            for key, value in payload.items():
                if key in {"entity_ids", "urls", "domains", "relations", "evidence"}:
                    continue
                if not node.get(key) and value:
                    node[key] = value
        return node

    target = result.target
    for entity in result.entities:
        etype = _etype(entity)
        value = str(entity.normalized_value or entity.value)
        meta = dict(entity.metadata or {})
        if etype == EntityType.USERNAME.value:
            kind = "target" if value == target else "username"
            vid = f"vis:user:{value}"
            node = add_visual(
                vid,
                label=value,
                full_label=value,
                kind=kind,
                group="username" if kind == "username" else "target",
                shape="dashed-circle" if kind == "username" else _SHAPE[kind],
                type="USERNAME",
                alias=kind == "username",
            )
            node["entity_ids"].append(entity.id)
            entity_map[entity.id] = vid
            continue
        if etype == EntityType.SOCIAL_PROFILE.value:
            url = str(entity.value or entity.normalized_value)
            row = by_url.get(_norm_url(url), {})
            platform = str(meta.get("site") or entity.source or row.get("platform") or _host(url) or "profile")
            username = str(meta.get("username") or row.get("username") or "")
            vid = f"vis:profile:{platform.lower()}:{username or _norm_url(url)}"
            node = add_visual(
                vid,
                label=platform,
                full_label=f"{platform} ({username})" if username else platform,
                kind="profile",
                group="profile",
                shape=_SHAPE["profile"],
                type="SOCIAL_PROFILE",
                platform=platform,
                username=username,
                status=row.get("status") or "",
                confidence=row.get("confidence") or str(entity.confidence),
                access=row.get("access_mode") or "",
            )
            node["entity_ids"].append(entity.id)
            if url and url not in node["urls"]:
                node["urls"].append(url)
            host = _host(url)
            if host and host not in node["domains"]:
                node["domains"].append(host)
            detail = str(row.get("detail") or "")
            if detail and detail not in node["evidence"]:
                node["evidence"].append(detail)
            entity_map[entity.id] = vid
            continue
        if etype == EntityType.URL.value:
            url = value
            host = _host(url)
            absorbed = None
            nurl = _norm_url(url)
            for node in visual.values():
                if nurl in {_norm_url(u) for u in node.get("urls") or []}:
                    absorbed = node
                    break
                if node.get("kind") == "profile" and host and host in (node.get("domains") or []):
                    absorbed = node
                    break
            if absorbed is not None:
                absorbed["entity_ids"].append(entity.id)
                if url not in absorbed["urls"]:
                    absorbed["urls"].append(url)
                entity_map[entity.id] = absorbed["id"]
                continue
            vid = f"vis:url:{nurl or entity.id}"
            node = add_visual(
                vid,
                label=host or url[:32],
                full_label=url,
                kind="other",
                group="other",
                shape=_SHAPE["other"],
                type="URL",
            )
            node["entity_ids"].append(entity.id)
            node["urls"].append(url)
            entity_map[entity.id] = vid
            continue
        if etype == EntityType.DOMAIN.value:
            host = value.lower().removeprefix("www.")
            absorbed = None
            for node in visual.values():
                if node.get("kind") == "profile" and host in (node.get("domains") or []):
                    absorbed = node
                    break
            if absorbed is not None:
                absorbed["entity_ids"].append(entity.id)
                if host not in absorbed["domains"]:
                    absorbed["domains"].append(host)
                entity_map[entity.id] = absorbed["id"]
                continue
            vid = f"vis:domain:{host}"
            node = add_visual(
                vid,
                label=host,
                full_label=host,
                kind="domain",
                group="domain",
                shape=_SHAPE["domain"],
                type="DOMAIN",
            )
            node["entity_ids"].append(entity.id)
            node["domains"].append(host)
            entity_map[entity.id] = vid
            continue
        if etype == EntityType.EMAIL.value:
            vid = f"vis:email:{value.lower()}"
            node = add_visual(
                vid,
                label=value,
                full_label=value,
                kind="email",
                group="email",
                shape=_SHAPE["email"],
                type="EMAIL",
            )
            node["entity_ids"].append(entity.id)
            entity_map[entity.id] = vid
            continue
        if etype == EntityType.IP.value:
            vid = f"vis:ip:{value}"
            node = add_visual(
                vid,
                label=value,
                full_label=value,
                kind="ip",
                group="ip",
                shape=_SHAPE["ip"],
                type="IP",
            )
            node["entity_ids"].append(entity.id)
            entity_map[entity.id] = vid
            continue
        if etype == EntityType.PERSON.value:
            vid = f"vis:person:{entity.id}"
            node = add_visual(
                vid,
                label="PERSON candidate",
                full_label=value,
                kind="person",
                group="person",
                shape=_SHAPE["person"],
                type="PERSON",
            )
            node["entity_ids"].append(entity.id)
            entity_map[entity.id] = vid
            continue
        if etype == EntityType.PUBLIC_MENTION.value:
            vid = f"vis:mention:{entity.id}"
            node = add_visual(
                vid,
                label=(meta.get("source") or "mention")[:28],
                full_label=value,
                kind="mention",
                group="mention",
                shape=_SHAPE["mention"],
                type="PUBLIC_MENTION",
                status="OBSERVED",
            )
            node["entity_ids"].append(entity.id)
            if entity.value:
                node["urls"].append(str(meta.get("url") or entity.value))
            entity_map[entity.id] = vid
            continue
        vid = f"vis:other:{entity.id}"
        node = add_visual(
            vid,
            label=str(value)[:28],
            full_label=str(value),
            kind="other",
            group="other",
            shape=_SHAPE["other"],
            type=etype,
        )
        node["entity_ids"].append(entity.id)
        entity_map[entity.id] = vid

    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for rel in result.relationships:
        src = entity_map.get(rel.from_entity_id)
        dst = entity_map.get(rel.to_entity_id)
        if not src or not dst or src == dst:
            continue
        relation = str(getattr(rel.relation, "value", rel.relation))
        key = (src, dst) if src <= dst else (dst, src)
        item = edges.get(key)
        if item is None:
            item = {
                "from": src,
                "to": dst,
                "relations": [],
                "relation": relation,
                "group": relation,
                "default_on": relation in FOCUS_RELATIONS,
                "style": "operator"
                if relation in OPERATOR_RELATIONS
                else ("identity" if relation == RelationType.IDENTITY_LINK.value else "default"),
            }
            edges[key] = item
        if relation not in item["relations"]:
            item["relations"].append(relation)
        ends = [visual[src], visual[dst]] if src in visual and dst in visual else []
        for linked in ends:
            if relation not in linked["relations"]:
                linked["relations"].append(relation)

    nodes = []
    for node in visual.values():
        node["entity_ids"] = sorted(set(node["entity_ids"]))
        node["urls"] = list(dict.fromkeys(node["urls"]))
        node["domains"] = list(dict.fromkeys(node["domains"]))
        nodes.append(node)

    return {
        "nodes": nodes,
        "edges": list(edges.values()),
        "raw_entity_count": len(result.entities),
        "raw_relationship_count": len(result.relationships),
        "aggregated": True,
        "default_edge_on": sorted(FOCUS_RELATIONS),
        "operator_relations": sorted(OPERATOR_RELATIONS),
        "filters": {
            "profile": True,
            "domain": False,
            "email": False,
            "ip": False,
            "mention": False,
            "username": True,
            "person": False,
            "other": False,
            "HAS_PROFILE": True,
            "LINKS_TO": True,
            "IDENTITY_LINK": True,
            "OPERATOR_PROVIDED_ALIAS": False,
            "OPERATOR_PROVIDED_INPUT": False,
        },
    }


def graph_unchanged_backend(result: InvestigationResult) -> tuple[list[str], list[str]]:
    return [e.id for e in result.entities], [r.id for r in result.relationships]
