# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

"""LlamaIndex integration shims for RAG Firewall.

Usage:
    from rag_firewall import Firewall
    from rag_firewall.integrations.llamaindex import TrustyRetriever

    safe = TrustyRetriever(base_retriever, firewall=fw, provenance_store=prov)
    nodes = safe.retrieve("query")
"""
from typing import Any, List, Optional

try:
    from llama_index.core.retrievers import BaseRetriever as LIBaseRetriever
    from llama_index.core.schema import NodeWithScore
except Exception:  # pragma: no cover
    class LIBaseRetriever:  # minimal stub
        def retrieve(self, query: str): raise NotImplementedError
    class NodeWithScore: pass

from ..firewall import Firewall

class TrustyRetriever(LIBaseRetriever):
    def __init__(self, base: LIBaseRetriever, firewall: Firewall, provenance_store: Optional[Any]=None):
        self.base = base
        self.firewall = firewall
        self.provenance = provenance_store

    def retrieve(self, query: str) -> List[NodeWithScore]:
        results = self.base.retrieve(query)
        safe = []
        enriched = []
        for r in results:
            # NodeWithScore has .node with .get_content(), .metadata
            node = getattr(r, "node", None)
            text = None
            md = {}
            if node is not None:
                try:
                    text = node.get_content()
                except Exception:
                    text = getattr(node, "text", None)
                md = getattr(node, "metadata", {}) or {}
            payload = {"page_content": text, "metadata": md}
            dec, findings = self.firewall.decide(payload, base_score=getattr(r, "score", 1.0) or 1.0, context={"query": query})
            if dec.get("action") == "deny":
                continue
            md["_ragfw"] = {"decision": dec.get("action"), "score": dec.get("score", 1.0), "reasons": dec.get("reasons", []), "policy": dec.get("policy")}
            # Attach back
            if node is not None:
                try:
                    node.metadata = md
                except Exception:
                    pass
            # Update score for re-ranking
            try:
                r.score = md["_ragfw"]["score"]
            except Exception:
                pass
            safe.append(r)
        safe.sort(key=lambda x: getattr(x, "score", 1.0) or 1.0, reverse=True)
        return safe
