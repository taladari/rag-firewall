# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class GraphNode:
    id: str
    label: str
    props: Dict[str, Any] = field(default_factory=dict)
    ts: Optional[float] = None  # optional timestamp for staleness/conflict

@dataclass
class GraphEdge:
    id: str
    type: str
    src: str
    dst: str
    props: Dict[str, Any] = field(default_factory=dict)
    ts: Optional[float] = None

@dataclass
class GraphPath:
    node_ids: List[str]
    edge_ids: List[str]

@dataclass
class Subgraph:
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: Dict[str, GraphEdge] = field(default_factory=dict)
    paths: List[GraphPath] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)