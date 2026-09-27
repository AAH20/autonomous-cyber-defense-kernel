"""
Unit tests for Stackelberg Honeynet Allocator.
"""

import unittest
from autonomous_cyber_defense_kernel.core.models import (
    SubnetHost,
    DecoyResource,
)
from autonomous_cyber_defense_kernel.core.stackelberg_honeynet_allocator import StackelbergHoneynetAllocator


class TestStackelbergHoneynetAllocator(unittest.TestCase):

    def setUp(self):
        self.subnets = [
            SubnetHost("s1", "10.0.1.0/24", vulnerability_surface=0.9, real_service_type="db", attacker_attractiveness=0.95),
            SubnetHost("s2", "10.0.2.0/24", vulnerability_surface=0.1, real_service_type="printer", attacker_attractiveness=0.10),
        ]
        self.decoys = [
            DecoyResource("d1", "10.0.1.0/24", "fake_mysql", deployment_cost=300.0, entrapment_probability=0.8),
            DecoyResource("d2", "10.0.2.0/24", "fake_printer", deployment_cost=100.0, entrapment_probability=0.5),
        ]
        self.allocator = StackelbergHoneynetAllocator(self.subnets, self.decoys, budget_limit=350.0)

    def test_allocator_prioritizes_high_attractiveness_subnet(self):
        strategy = self.allocator.compute_optimal_deception()
        self.assertLessEqual(strategy.total_deployment_cost, 350.0)
        self.assertEqual(len(strategy.allocated_decoys), 1)
        # Should deploy d1 on vulnerable and attractive subnet s1
        self.assertEqual(strategy.allocated_decoys[0].decoy_id, "d1")
        self.assertGreater(strategy.attacker_entrapment_prob, 0.5)


if __name__ == "__main__":
    unittest.main()
