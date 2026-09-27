"""
Unit tests for Kill-Chain Causal Correlator.
"""

import unittest
from autonomous_cyber_defense_kernel.core.models import (
    MitreTactic,
    SecurityAlert,
)
from autonomous_cyber_defense_kernel.core.kill_chain_causal_correlator import KillChainCausalCorrelator


class TestKillChainCausalCorrelator(unittest.TestCase):

    def setUp(self):
        self.correlator = KillChainCausalCorrelator()

    def test_multi_stage_killchain_correlated(self):
        # 3 alerts forming valid causal chain on host_1
        t0 = 1000000
        alerts = [
            SecurityAlert("a1", t0, "host_1", MitreTactic.INITIAL_ACCESS, severity=0.9, causal_signature="apt_x"),
            SecurityAlert("a2", t0 + 10000, "host_1", MitreTactic.EXECUTION, severity=0.8, causal_signature="apt_x"),
            SecurityAlert("a3", t0 + 20000, "host_1", MitreTactic.LATERAL_MOVEMENT, severity=0.85, causal_signature="apt_x"),
            SecurityAlert("noise_1", t0 + 5000, "host_other", MitreTactic.DISCOVERY, severity=0.1, causal_signature="noise"),
        ]
        report = self.correlator.correlate_alerts(alerts, min_chain_stages=3)

        self.assertEqual(len(report.isolated_kill_chains), 1)
        chain = report.isolated_kill_chains[0]
        self.assertEqual(len(chain.ordered_alerts), 3)
        self.assertGreater(report.noise_reduction_ratio_pct, 0.0)


if __name__ == "__main__":
    unittest.main()
