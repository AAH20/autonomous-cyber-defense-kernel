"""
Unit tests for integrated AutonomousCyberDefenseEngine.
"""

import unittest
from autonomous_cyber_defense_kernel.engine import AutonomousCyberDefenseEngine


class TestAutonomousCyberDefenseEngine(unittest.TestCase):

    def setUp(self):
        self.engine = AutonomousCyberDefenseEngine()

    def test_run_mincut_isolation_benchmark(self):
        res = self.engine.run_mincut_isolation_benchmark()
        self.assertIn("severed_edges_count", res)
        self.assertTrue(res["containment_guaranteed"])
        self.assertGreater(res["severed_edges_count"], 0)

    def test_run_honeynet_allocation_benchmark(self):
        res = self.engine.run_honeynet_allocation_benchmark()
        self.assertIn("deployed_decoys_count", res)
        self.assertGreater(res["deployed_decoys_count"], 0)
        self.assertGreater(res["attacker_entrapment_probability_pct"], 0.0)

    def test_run_cfi_patch_benchmark(self):
        res = self.engine.run_cfi_patch_benchmark()
        self.assertIn("formally_verified_safe_patches", res)
        self.assertGreater(res["formally_verified_safe_patches"], 0)

    def test_run_privilege_audit_benchmark(self):
        res = self.engine.run_privilege_audit_benchmark()
        self.assertIn("escalation_cycles_detected", res)
        self.assertGreater(res["escalation_cycles_detected"], 0)

    def test_run_killchain_correlation_benchmark(self):
        res = self.engine.run_killchain_correlation_benchmark(num_alerts=50)
        self.assertIn("isolated_kill_chain_trees", res)
        self.assertGreater(res["isolated_kill_chain_trees"], 0)
        self.assertGreater(res["noise_reduction_ratio_pct"], 50.0)

    def test_run_comprehensive_benchmark(self):
        rep = self.engine.run_comprehensive_benchmark()
        self.assertGreater(rep.total_runtime_ms, 0.0)
        self.assertIsNotNone(rep.mincut_isolation_summary)
        self.assertIsNotNone(rep.honeynet_allocation_summary)
        self.assertIsNotNone(rep.cfi_patch_summary)
        self.assertIsNotNone(rep.privilege_audit_summary)
        self.assertIsNotNone(rep.killchain_correlation_summary)


if __name__ == "__main__":
    unittest.main()
