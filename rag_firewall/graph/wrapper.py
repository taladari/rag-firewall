# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

from __future__ import annotations
from typing import Any, Dict, Iterable, List, Tuple
import time

from rag_firewall.audit import Audit, AuditEvent
from rag_firewall.provenance.hasher import Hasher
from rag_firewall.graph.types import Subgraph, GraphNode, GraphEdge, GraphPath


def _join_text_fields(props: Dict[str, Any], include_keys: Iterable[str] | None = None) -> str:
    if include_keys:
        vals = [str(props.get(k, "")) for k in include_keys]
    else:
        # default: join all str-like props
        vals = [str(v) for v in props.values() if isinstance(v, (str, int, float))]
    return "\n".join(v for v in vals if v)


class GraphTextSerializer:
    """Default serializer: flatten a subgraph into LLM-ready text docs."""
    def __call__(self, sg: Subgraph) -> List[Dict[str, Any]]:
        docs: List[Dict[str, Any]] = []
        for n in sg.nodes.values():
            text = _join_text_fields(n.props)
            meta = dict(n.props)
            meta.update({"_type": "node", "_id": n.id, "_label": n.label})
            docs.append({"page_content": f"[{n.label}#{n.id}]\n{text}", "metadata": meta})
        for e in sg.edges.values():
            text = _join_text_fields(e.props)
            meta = dict(e.props)
            meta.update({"_type": "edge", "_id": e.id, "_label": e.type, "_src": e.src, "_dst": e.dst})
            docs.append({"page_content": f"({e.type}:{e.src}->{e.dst})\n{text}", "metadata": meta})
        return docs


class FirewallGraph:
    """
    Runs your existing scanners/policies on node/edge text before prompt assembly.
    - Produces a sanitized Subgraph (possibly pruned).
    - Optionally serializes to text docs for LangChain/LlamaIndex.
    """
    def __init__(self, firewall, schema: Dict[str, Any] | None = None, serializer=None):
        self.firewall = firewall
        self.schema = schema or {}
        self.serializer = serializer or GraphTextSerializer()

    def sanitize(self, sg: Subgraph) -> Subgraph:
        # --- Build a single batch of docs for all artifacts (nodes + edges) ---
        if not hasattr(self.firewall, "evaluate"):
            raise AttributeError("FirewallGraph requires firewall.evaluate(docs) to be available")

        batch: List[Dict[str, Any]] = []
        idx_to_art: List[Tuple[str, str]] = []  # (kind, id) -> ("node", nid) or ("edge", eid)

        # Nodes
        for nid, n in sg.nodes.items():
            text = _join_text_fields(n.props, self._text_fields_for_label(n.label))
            meta = dict(n.props)
            meta.update({
                "label": n.label,
                "timestamp": n.ts,
                "_artifact_kind": "node",
                "_artifact_id": nid,
            })
            meta["hash"] = Hasher.hash_text((nid or "") + (text or ""))
            batch.append({"page_content": text, "metadata": meta})
            idx_to_art.append(("node", nid))

        # Edges
        for eid, e in sg.edges.items():
            text = _join_text_fields(e.props, self._text_fields_for_edge(e.type))
            meta = dict(e.props)
            meta.update({
                "edge_type": e.type,
                "src": e.src,
                "dst": e.dst,
                "timestamp": e.ts,
                "_artifact_kind": "edge",
                "_artifact_id": eid,
            })
            meta["hash"] = Hasher.hash_text((eid or "") + (text or ""))
            batch.append({"page_content": text, "metadata": meta})
            idx_to_art.append(("edge", eid))

        # --- Evaluate via the real firewall pipeline (scanners + policies) ---
        out_docs = self.firewall.evaluate(batch) or []

        # --- Decide/prune using actual decisions; audit consistently ---
        keep_nodes: Dict[str, GraphNode] = {}
        keep_edges: Dict[str, GraphEdge] = {}

        for i, out in enumerate(out_docs):
            kind, art_id = idx_to_art[i]
            meta = (out or {}).get("metadata", {}) or {}
            r = meta.get("_ragfw", {}) or {}

            Audit.log(AuditEvent(
                ts=time.time(),
                chunk_hash=meta.get("hash"),
                decision=r.get("decision", "allow"),
                score=float(r.get("score", 1.0)),
                reasons=r.get("reasons", []),
                findings=r.get("findings", []),
                policy=r.get("policy"),
            ))

            # Only drop artifacts that your policy engine decided to deny
            if r.get("decision") == "deny":
                continue

            if kind == "node":
                n = sg.nodes.get(art_id)
                if n is not None:
                    keep_nodes[art_id] = n
            else:
                e = sg.edges.get(art_id)
                if e is not None:
                    # keep edge only if endpoints survived
                    if e.src in keep_nodes and e.dst in keep_nodes:
                        keep_edges[art_id] = e

        # --- Prune paths accordingly ---
        keep_paths: List[GraphPath] = []
        for p in sg.paths:
            if all(nid in keep_nodes for nid in p.node_ids) and all(eid in keep_edges for eid in p.edge_ids):
                keep_paths.append(p)

        return Subgraph(nodes=keep_nodes, edges=keep_edges, paths=keep_paths, meta=dict(sg.meta))

    def to_documents(self, sanitized: Subgraph) -> List[Dict[str, Any]]:
        return self.serializer(sanitized)

    # --- helpers ---
    def _text_fields_for_label(self, label: str) -> List[str] | None:
        return (self.schema.get("text_fields") or {}).get(label)

    def _text_fields_for_edge(self, etype: str) -> List[str] | None:
        return (self.schema.get("edge_text_fields") or {}).get(etype)