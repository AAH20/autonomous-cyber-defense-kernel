"""
Autonomous Cyber Defense Kernel.
Zero external dependencies. Pure Python 3.10+ standard library.
"""

from autonomous_cyber_defense_kernel.core.models import (
    AssetCriticalityTier,
    MitreTactic,
    AssetNode,
    NetworkEdge,
    IsolationPlan,
    SubnetHost,
    DecoyResource,
    DeceptionStrategy,
    CfiBranchTarget,
    BinaryPatchCandidate,
    PatchVerificationReport,
    IdentityEntity,
    DelegationEdge,
    PrivilegeAuditReport,
    SecurityAlert,
    CausalKillChainTree,
    CorrelationReport,
    CyberDefenseBenchmarkReport,
)

from autonomous_cyber_defense_kernel.core.attack_graph_mincut_isolator import AttackGraphMinCutIsolator
from autonomous_cyber_defense_kernel.core.stackelberg_honeynet_allocator import StackelbergHoneynetAllocator
from autonomous_cyber_defense_kernel.core.cfi_binary_patch_verifier import CfiBinaryPatchVerifier
from autonomous_cyber_defense_kernel.core.identity_privilege_deconfliction import IdentityPrivilegeDeconflictionSolver
from autonomous_cyber_defense_kernel.core.kill_chain_causal_correlator import KillChainCausalCorrelator
from autonomous_cyber_defense_kernel.engine import AutonomousCyberDefenseEngine

__all__ = [
    "AssetCriticalityTier",
    "MitreTactic",
    "AssetNode",
    "NetworkEdge",
    "IsolationPlan",
    "SubnetHost",
    "DecoyResource",
    "DeceptionStrategy",
    "CfiBranchTarget",
    "BinaryPatchCandidate",
    "PatchVerificationReport",
    "IdentityEntity",
    "DelegationEdge",
    "PrivilegeAuditReport",
    "SecurityAlert",
    "CausalKillChainTree",
    "CorrelationReport",
    "CyberDefenseBenchmarkReport",
    "AttackGraphMinCutIsolator",
    "StackelbergHoneynetAllocator",
    "CfiBinaryPatchVerifier",
    "IdentityPrivilegeDeconflictionSolver",
    "KillChainCausalCorrelator",
    "AutonomousCyberDefenseEngine",
]
