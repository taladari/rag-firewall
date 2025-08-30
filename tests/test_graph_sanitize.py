# SPDX-License-Identifier: Apache-2.0
import networkx as nx
from rag_firewall import Firewall
from rag_firewall.graph.wrapper import FirewallGraph
from rag_firewall.integrations.graph.networkx_adapter import NetworkXAdapter
from rag_firewall.scanners.secrets_scanner import SecretsScanner

def test_graph_secret_node_is_pruned():
    G = nx.DiGraph()
    G.add_node("m1", label="Meeting", summary="OK", minutes="Decision: A")
    G.add_node("n1", label="Note", text="AWS key AKIAABCDEFGHIJKLMNOP")
    G.add_edge("m1","n1", type="has_note")

    adapter = NetworkXAdapter(G)
    sg = adapter.retrieve(query="Meeting", radius=1)

    fw = Firewall(scanners=[SecretsScanner()], policies=[{"name":"deny_all_secrets","match":{},"action":"deny"}])
    fg = FirewallGraph(firewall=fw, schema={"text_fields":{"Meeting":["summary","minutes"], "Note":["text"]}})
    sanitized = fg.sanitize(sg)

    assert "n1" not in sanitized.nodes  # secret node pruned
    # edge to pruned node should be dropped as well
    assert all(e.dst != "n1" and e.src != "n1" for e in sanitized.edges.values())