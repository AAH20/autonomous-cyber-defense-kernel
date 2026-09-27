"""
Unit tests for CFI Binary Patch Verifier.
"""

import unittest
from autonomous_cyber_defense_kernel.core.models import BinaryPatchCandidate
from autonomous_cyber_defense_kernel.core.cfi_binary_patch_verifier import CfiBinaryPatchVerifier


class TestCfiBinaryPatchVerifier(unittest.TestCase):

    def setUp(self):
        allowed_targets = {0x401500, 0x401600}
        valid_returns = {0x401010}
        self.verifier = CfiBinaryPatchVerifier(allowed_targets, valid_returns)

    def test_safe_patch_passes_cfi(self):
        safe_patch = BinaryPatchCandidate(
            "p_safe", "safe_func", "bof", 16, 0x401500, 3, preserves_stack_alignment=True, respects_cfi=True
        )
        report = self.verifier.verify_patch(safe_patch, [0x401500], base_address=0x401000)
        self.assertTrue(report.is_safe)
        self.assertEqual(report.cfi_violations_detected, 0)

    def test_illegal_target_rejected(self):
        unsafe_patch = BinaryPatchCandidate(
            "p_unsafe", "unsafe_func", "bof", 16, 0x999999, 3, preserves_stack_alignment=True, respects_cfi=True
        )
        # 0x999999 is not in allowed_targets
        report = self.verifier.verify_patch(unsafe_patch, [0x999999], base_address=0x401000)
        self.assertFalse(report.is_safe)
        self.assertGreater(report.cfi_violations_detected, 0)


if __name__ == "__main__":
    unittest.main()
