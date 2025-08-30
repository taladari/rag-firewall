# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
from rag_firewall.graph.types import Subgraph


class GraphRetrieverAdapter(ABC):
    """Adapter that turns a user query (or params) into a Subgraph."""
    @abstractmethod
    def retrieve(self, query: str, **kwargs: Any) -> Subgraph:
        raise NotImplementedError