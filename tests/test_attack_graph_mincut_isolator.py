"""
Unit tests for Attack Graph Min-Cut Isolator.
"""

import unittest
from autonomous_cyber_defense_kernel.core.models import (
    AssetCriticalityTier,
    AssetNode,
    NetworkEdge,
)
from autonomous_cyber_defense_kernel.core.attack_graph_mincut_isolator import AttackGraphMinCutIsolator


class TestAttackGraphMinCutIsolator(unittest.TestCase):

    def setUp(self):
        # Linear network: Host 1 (compromised) -> Host 2 -> Host 3 (crown jewel)
        self.nodes = [
            AssetNode("h1", "Infected_Node", "zone_a", AssetCriticalityTier.LOW, is_compromised=True),
            AssetNode("h2", "DMZ_Router", "zone_dmz", AssetCriticalityTier.MEDIUM),
            AssetNode("h3", "Domain_Controller", "zone_core", AssetCriticalityTier.CROWN_JEWEL, is_crown_jewel=True),
        ]
        self.edges = [
            NetworkEdge("e1", "h1", "h2", 1000.0, business_cost_to_sever=100.0),
            NetworkEdge("e2", "h2", "h3", 1000.0, business_cost_to_sever=500.0),
        ]
        self.isolator = AttackGraphMinCutIsolator(self.nodes, self.edges)

    def test_min_cut_severs_cheapest_edge(self):
        plan = self.isolator.compute_isolation_cut()
        self.assertTrue(plan.is_containment_guaranteed)
        self.assertEqual(len(plan.severed_edges), 1)
        # Should pick e1 (cost 100) instead of e2 (cost 500)
        self.assertEqual(plan.severed_edges[0].edge_id, "e1")
        self.assertEqual(plan.total_disruption_cost, 100.0)


if __name__ == "__main__":
    unittest.main()
