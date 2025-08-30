# SPDX-License-Identifier: Apache-2.0
"""
Minimal GraphRAG demo with NetworkX + FirewallGraph.
Run: python examples/graph_example.py
"""
from __future__ import annotations
import networkx as nx
from rag_firewall import Firewall
from rag_firewall.graph.wrapper import FirewallGraph
from rag_firewall.integrations.graph.networkx_adapter import NetworkXAdapter
from rag_firewall.scanners.secrets_scanner import SecretsScanner
from rag_firewall.scanners.regex_scanner import RegexInjectionScanner
from rag_firewall.scanners.url_scanner import URLScanner
from rag_firewall.scanners.pii_scanner import PIIScanner
from rag_firewall.scanners.encoding_scanner import EncodedContentScanner
from rag_firewall.scanners.conflict_scanner import ConflictScanner

def build_graph():
    G = nx.MultiDiGraph()
    # People
    G.add_node("john", label="Person", name="John Smith", bio="Eng lead", ts=1_722_000_000)
    G.add_node("sarah", label="Person", name="Sarah K", bio="PM", ts=1_722_000_000)
    # Meeting
    G.add_node("m1", label="Meeting", summary="API redesign discussion", minutes="Decision: adopt plan A.", ts=1_722_100_000)
    # Note with dangerous content
    G.add_node("n1", label="Note", text="AWS key AKIAABCDEFGHIJKLMNOP", ts=1_721_000_000)
    # Edges
    G.add_edge("john","m1", key="r1", type="participated_in")
    G.add_edge("sarah","m1", key="r2", type="participated_in")
    G.add_edge("m1","n1", key="r3", type="has_note")
    return G

def build_firewall():
    fw = Firewall(
        scanners=[
            RegexInjectionScanner(),
            SecretsScanner(),
            URLScanner(allowlist=["intranet.acme.local"], denylist=["evil.example.com"]),
            PIIScanner(),
            EncodedContentScanner(),
            ConflictScanner(stale_days=365),
        ],
        policies=[
            {"name": "block_secrets", "match": {}, "action": "deny"},
            {"name": "prefer_recent", "action": "rerank", "weight": {"recency": 0.6, "relevance": 0.4}},
            {"name": "allow_default", "action": "allow"},
        ],
    )
    return fw

if __name__ == "__main__":
    G = build_graph()
    adapter = NetworkXAdapter(G)
    sg = adapter.retrieve(query="Meeting", radius=1)

    fw = build_firewall()
    fg = FirewallGraph(firewall=fw, schema={
        "text_fields": {
            "Person": ["bio"],
            "Meeting": ["summary", "minutes"],
            "Note": ["text"]
        }
    })

    sanitized = fg.sanitize(sg)
    docs = fg.to_documents(sanitized)
    print(f"Nodes kept: {list(sanitized.nodes.keys())}")
    print(f"Edges kept: {list(sanitized.edges.keys())}")
    print("--- Serialized docs (first 1) ---")
    if docs:
        print(docs[0]["page_content"])
        print(docs[0]["metadata"].get("_ragfw"))