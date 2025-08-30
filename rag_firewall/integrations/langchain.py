# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

"""LangChain integration shims for RAG Firewall.

Provides a drop-in retriever that wraps any LangChain retriever.
Usage:

    from rag_firewall import Firewall
    from rag_firewall.integrations.langchain import FirewallRetriever

    fw = Firewall.from_yaml("firewall.yaml")
    safe_retriever = FirewallRetriever(base_retriever, firewall=fw, provenance_store=prov)

You must install langchain separately.
"""
from typing import Any, List, Optional

try:
    from langchain_core.documents import Document
    from langchain_core.retrievers import BaseRetriever
except Exception:  # pragma: no cover
    Document = Any
    class BaseRetriever:  # minimal stub to avoid hard dependency
        def get_relevant_documents(self, query: str) -> List[Any]:
            raise NotImplementedError

from ..firewall import Firewall

class FirewallRetriever(BaseRetriever):
    """Wraps any BaseRetriever and applies RAG Firewall decisions."""
    def __init__(self, base: BaseRetriever, firewall: Firewall, provenance_store: Optional[Any]=None):
        self.base = base
        self.firewall = firewall
        self.provenance = provenance_store

    def _get_relevant_documents(self, query: str) -> List[Document]:
        # LC v0.2+ uses _get_relevant_documents
        docs = self.base.get_relevant_documents(query) if hasattr(self.base, "get_relevant_documents") else self.base._get_relevant_documents(query)
        safe_docs = []
        for d in docs:
            # LangChain Document has .page_content/.metadata
            payload = {"page_content": getattr(d, "page_content", None), "metadata": getattr(d, "metadata", {})}
            dec, findings = self.firewall.decide(payload, base_score=1.0, context={"query": query})
            if dec.get("action") == "deny":
                continue
            md = payload["metadata"]
            md["_ragfw"] = {"decision": dec.get("action"), "score": dec.get("score", 1.0), "reasons": dec.get("reasons", []), "policy": dec.get("policy")}
            # Rebuild Document preserving other fields
            try:
                DocumentCls = d.__class__
                nd = DocumentCls(page_content=payload["page_content"], metadata=md)
            except Exception:
                nd = d
                if hasattr(nd, "metadata"):
                    nd.metadata = md
            safe_docs.append(nd)
        # naive re-rank by score
        def _score(doc):
            return getattr(doc, "metadata", {}).get("_ragfw", {}).get("score", 1.0)
        safe_docs.sort(key=_score, reverse=True)
        return safe_docs

    # Back-compat for LC that calls get_relevant_documents
    def get_relevant_documents(self, query: str) -> List[Document]:
        return self._get_relevant_documents(query)
