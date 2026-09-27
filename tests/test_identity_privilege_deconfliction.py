"""
Unit tests for Identity Privilege Deconfliction Solver.
"""

import unittest
from autonomous_cyber_defense_kernel.core.models import (
    IdentityEntity,
    DelegationEdge,
)
from autonomous_cyber_defense_kernel.core.identity_privilege_deconfliction import IdentityPrivilegeDeconflictionSolver


class TestIdentityPrivilegeDeconfliction(unittest.TestCase):

    def setUp(self):
        self.entities = [
            IdentityEntity("user_alice", "USER", privilege_tier=1),
            IdentityEntity("group_dev", "GROUP", privilege_tier=4),
            IdentityEntity("group_admin", "GROUP", privilege_tier=10),
        ]
        # alice -> dev -> admin (escalation path)
        # dev -> alice (backdoor loop)
        self.edges = [
            DelegationEdge("e1", "user_alice", "group_dev", "MemberOf"),
            DelegationEdge("e2", "group_dev", "group_admin", "Administer"),
            DelegationEdge("e3", "group_dev", "user_alice", "WriteOwner"),
        ]
        self.solver = IdentityPrivilegeDeconflictionSolver(self.entities, self.edges)

    def test_cycle_and_escalation_detection(self):
        report = self.solver.audit_and_remediate(max_unprivileged_tier=2, admin_tier=10)
        self.assertGreater(report.escalation_cycles_found, 0)
        self.assertGreater(len(report.backdoor_paths_detected), 0)
        self.assertGreater(len(report.recommended_revocations), 0)


if __name__ == "__main__":
    unittest.main()
