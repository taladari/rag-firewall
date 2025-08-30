# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

from __future__ import annotations
from typing import Any, Dict, Iterable
import networkx as nx
from rag_firewall.graph.types import GraphNode, GraphEdge, GraphPath, Subgraph
from .base import GraphRetrieverAdapter

class NetworkXAdapter(GraphRetrieverAdapter):
    """
    Tiny demo adapter.
    - Expects an nx.MultiDiGraph (or DiGraph).
    - `query` can be any key you decide; here we treat it as a simple
      label filter like "Meeting" or "Decision" and return neighborhood.
    """
    def __init__(self, graph: nx.MultiDiGraph | nx.DiGraph):
        self.G = graph

    def retrieve(self, query: str, radius: int = 1) -> Subgraph:
        # Example: return all nodes with label==query and their r-hop neighborhood
        nodes: Dict[str, GraphNode] = {}
        edges: Dict[str, GraphEdge] = {}
        paths: list[GraphPath] = []

        # collect seed nodes
        seeds = [n for n, d in self.G.nodes(data=True) if d.get("label") == query]
        seen: set[str] = set()
        for s in seeds:
            # r-hop ego subgraph
            ego = nx.ego_graph(self.G, s, radius=radius, undirected=False)
            for n, d in ego.nodes(data=True):
                if n not in nodes:
                    nodes[n] = GraphNode(
                        id=str(n),
                        label=str(d.get("label", "Unknown")),
                        props={k: v for k, v in d.items() if k not in ("label",)},
                        ts=d.get("ts"),
                    )
            for u, v, k, d in ego.edges(keys=True, data=True) if isinstance(self.G, nx.MultiDiGraph) \
                    else [(u, v, None, d) for u, v, d in ego.edges(data=True)]:
                eid = f"{u}->{v}#{k}" if k is not None else f"{u}->{v}"
                if eid not in edges:
                    edges[eid] = GraphEdge(
                        id=eid,
                        type=str(d.get("type", "edge")),
                        src=str(u),
                        dst=str(v),
                        props={k2: v2 for k2, v2 in d.items() if k2 not in ("type",)},
                        ts=d.get("ts"),
                    )
            seen.update(ego.nodes())

        # optional naïve paths (node-only)
        for n in seeds:
            paths.append(GraphPath(node_ids=[n], edge_ids=[]))

        return Subgraph(nodes=nodes, edges=edges, paths=paths, meta={"query": query, "radius": radius})