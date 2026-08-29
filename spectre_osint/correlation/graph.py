"""NetworkX correlation graph over entities and evidence-backed edges."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import networkx as nx

from spectre_osint.core.entities import InvestigationResult


def build_graph(result: InvestigationResult) -> nx.DiGraph:
    graph = nx.DiGraph()
    entities = {e.id: e for e in result.entities}
    for entity in result.entities:
        graph.add_node(
            entity.id,
            label=entity.normalized_value,
            type=entity.type.value,
            confidence=entity.confidence.value,
            source=entity.source,
        )
    for rel in result.relationships:
        if rel.from_entity_id not in entities or rel.to_entity_id not in entities:
            # Still draw the edge if both node ids exist; otherwise skip silently.
            if rel.from_entity_id not in graph or rel.to_entity_id not in graph:
                continue
        attrs = {
            "relation": rel.relation.value,
            "source": rel.source,
            "confidence": rel.confidence.value,
        }
        if rel.evidence_id:
            attrs["evidence_id"] = rel.evidence_id
        graph.add_edge(rel.from_entity_id, rel.to_entity_id, **attrs)
    return graph


def _strip_none(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if v is not None}


def export_graphml(graph: nx.DiGraph, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    clean = graph.copy()
    for _, data in clean.nodes(data=True):
        none_keys = [k for k, v in list(data.items()) if v is None]
        for key in none_keys:
            del data[key]
        data.update(_strip_none(dict(data)))
    for _, _, data in clean.edges(data=True):
        none_keys = [k for k, v in list(data.items()) if v is None]
        for key in none_keys:
            del data[key]
    nx.write_graphml(clean, path)
    return path


def to_cytoscape(graph: nx.DiGraph) -> dict[str, Any]:
    elements: list[dict[str, Any]] = []
    for node, data in graph.nodes(data=True):
        elements.append({"data": {"id": node, **data}})
    for source, target, data in graph.edges(data=True):
        elements.append(
            {
                "data": {
                    "id": f"{source}->{target}:{data.get('relation')}",
                    "source": source,
                    "target": target,
                    **data,
                }
            }
        )
    return {"elements": elements}
