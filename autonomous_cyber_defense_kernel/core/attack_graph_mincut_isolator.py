"""
Attack Graph Multi-Terminal Min-Cut Quarantine Isolator.
Solves the capacity-constrained network cut problem: identifies the minimal set of
firewall/network edges to sever to mathematically guarantee zero reachability from
compromised nodes to critical crown-jewel infrastructure with minimum business disruption.
"""

from __future__ import annotations
import collections
import time
from typing import List, Dict, Set, Optional, Tuple
from autonomous_cyber_defense_kernel.core.models import (
    AssetNode,
    NetworkEdge,
    IsolationPlan,
)


class AttackGraphMinCutIsolator:
    """
    Computes optimal blast-radius containment using Max-Flow / Min-Cut duality
    on directed network infrastructure attack graphs.
    """

    def __init__(self, nodes: List[AssetNode], edges: List[NetworkEdge]):
        self.nodes = {n.asset_id: n for n in nodes}
        self.edges = edges
        self.edge_map = {e.edge_id: e for e in edges}

    def compute_isolation_cut(self) -> IsolationPlan:
        """
        Constructs super-source (all compromised nodes) and super-sink (all crown jewel assets),
        then solves the minimum-cost cut using Edmonds-Karp BFS augmenting paths.
        """
        start_t = time.perf_counter()

        infected_nodes = [n.asset_id for n in self.nodes.values() if n.is_compromised]
        crown_jewels = [n.asset_id for n in self.nodes.values() if n.is_crown_jewel]

        # If no infection or no crown jewels, no cut needed
        if not infected_nodes or not crown_jewels:
            elapsed_us = (time.perf_counter() - start_t) * 1_000_000.0
            return IsolationPlan(
                severed_edges=[],
                quarantined_nodes=infected_nodes,
                crown_jewels_secured=len(crown_jewels),
                total_disruption_cost=0.0,
                is_containment_guaranteed=True,
                execution_latency_us=elapsed_us,
            )

        SUPER_SRC = "__SUPER_SRC__"
        SUPER_SNK = "__SUPER_SNK__"

        # Build capacity graph: u -> v -> capacity
        capacity: Dict[str, Dict[str, float]] = collections.defaultdict(dict)
        flow: Dict[str, Dict[str, float]] = collections.defaultdict(lambda: collections.defaultdict(float))

        # Add network edges
        for e in self.edges:
            # Edge capacity equals business cost to sever
            cap = max(1.0, e.business_cost_to_sever)
            capacity[e.source_id][e.target_id] = capacity[e.source_id].get(e.target_id, 0.0) + cap
            # Ensure back-edge exists in capacity dict
            if e.source_id not in capacity[e.target_id]:
                capacity[e.target_id][e.source_id] = 0.0

        # Connect SUPER_SRC to all infected nodes with infinite capacity
        INF = float(1e9)
        for inf_id in infected_nodes:
            capacity[SUPER_SRC][inf_id] = INF
            capacity[inf_id][SUPER_SRC] = 0.0

        # Connect all crown jewels to SUPER_SNK with infinite capacity
        for cj_id in crown_jewels:
            capacity[cj_id][SUPER_SNK] = INF
            capacity[SUPER_SNK][cj_id] = 0.0

        # Edmonds-Karp Max-Flow algorithm
        def bfs() -> Optional[List[str]]:
            parent: Dict[str, Optional[str]] = {SUPER_SRC: None}
            queue = collections.deque([SUPER_SRC])

            while queue:
                u = queue.popleft()
                if u == SUPER_SNK:
                    break
                for v in capacity[u]:
                    residual = capacity[u][v] - flow[u][v]
                    if residual > 1e-6 and v not in parent:
                        parent[v] = u
                        queue.append(v)

            if SUPER_SNK not in parent:
                return None

            path = []
            curr = SUPER_SNK
            while curr is not None:
                path.append(curr)
                curr = parent[curr]
            path.reverse()
            return path

        # Augment flow along paths
        while True:
            path = bfs()
            if not path:
                break
            # Find bottleneck capacity
            bottleneck = min(capacity[path[i]][path[i+1]] - flow[path[i]][path[i+1]] for i in range(len(path) - 1))
            for i in range(len(path) - 1):
                u, v = path[i], path[i+1]
                flow[u][v] += bottleneck
                flow[v][u] -= bottleneck

        # Find reachable vertices from SUPER_SRC in residual graph
        visited_reachable = set()
        queue = collections.deque([SUPER_SRC])
        visited_reachable.add(SUPER_SRC)

        while queue:
            u = queue.popleft()
            for v in capacity[u]:
                if (capacity[u][v] - flow[u][v]) > 1e-6 and v not in visited_reachable:
                    visited_reachable.add(v)
                    queue.append(v)

        # Min-Cut edges: edges originating in reachable set and terminating in unreachable set
        severed_edges: List[NetworkEdge] = []
        total_cut_cost = 0.0

        for e in self.edges:
            if e.source_id in visited_reachable and e.target_id not in visited_reachable:
                severed_edges.append(e)
                total_cut_cost += e.business_cost_to_sever

        quarantined_hosts = [n for n in visited_reachable if n != SUPER_SRC]
        elapsed_us = (time.perf_counter() - start_t) * 1_000_000.0

        return IsolationPlan(
            severed_edges=severed_edges,
            quarantined_nodes=quarantined_hosts,
            crown_jewels_secured=len(crown_jewels),
            total_disruption_cost=total_cut_cost,
            is_containment_guaranteed=True,
            execution_latency_us=elapsed_us,
        )
