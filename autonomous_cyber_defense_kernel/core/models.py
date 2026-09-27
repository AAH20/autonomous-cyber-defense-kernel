"""
Data models and typed structures for Autonomous Cyber Defense Kernel.
Zero external pip dependencies. Strict Python 3.10+ typing.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Set, Optional, Tuple


class AssetCriticalityTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CROWN_JEWEL = "CROWN_JEWEL"


class MitreTactic(str, Enum):
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"


@dataclass(slots=True)
class AssetNode:
    asset_id: str
    name: str
    zone: str
    criticality: AssetCriticalityTier
    is_compromised: bool = False
    is_crown_jewel: bool = False


@dataclass(slots=True)
class NetworkEdge:
    edge_id: str
    source_id: str
    target_id: str
    bandwidth_mbps: float
    business_cost_to_sever: float  # Operational cost/penalty for cutting this link
    protocols: List[str] = field(default_factory=list)


@dataclass(slots=True)
class IsolationPlan:
    severed_edges: List[NetworkEdge]
    quarantined_nodes: List[str]
    crown_jewels_secured: int
    total_disruption_cost: float
    is_containment_guaranteed: bool
    execution_latency_us: float


@dataclass(slots=True)
class SubnetHost:
    host_id: str
    subnet: str
    vulnerability_surface: float  # [0, 1]
    real_service_type: str
    attacker_attractiveness: float  # [0, 1]


@dataclass(slots=True)
class DecoyResource:
    decoy_id: str
    target_subnet: str
    decoy_type: str
    deployment_cost: float
    entrapment_probability: float  # Probability an attacker targeting this subnet engages decoy


@dataclass(slots=True)
class DeceptionStrategy:
    allocated_decoys: List[DecoyResource]
    total_deployment_cost: float
    attacker_entrapment_prob: float
    defensive_utility: float
    execution_latency_us: float


@dataclass(slots=True)
class CfiBranchTarget:
    branch_address: int
    valid_targets: Set[int]
    is_indirect: bool = False


@dataclass(slots=True)
class BinaryPatchCandidate:
    patch_id: str
    function_symbol: str
    vuln_class: str
    original_size_bytes: int
    trampoline_target_addr: int
    injected_instructions_count: int
    preserves_stack_alignment: bool
    respects_cfi: bool


@dataclass(slots=True)
class PatchVerificationReport:
    patch_id: str
    is_safe: bool
    cfi_violations_detected: int
    forward_edge_valid: bool
    backward_edge_valid: bool
    stack_canary_verified: bool
    verification_time_us: float


@dataclass(slots=True)
class IdentityEntity:
    entity_id: str
    entity_type: str  # USER, GROUP, SERVICE_ACCOUNT, ROLE
    privilege_tier: int  # 1 (Standard User) to 10 (Domain Admin / Root)


@dataclass(slots=True)
class DelegationEdge:
    edge_id: str
    source_id: str
    target_id: str
    permission_granted: str
    can_escalate: bool = False


@dataclass(slots=True)
class PrivilegeAuditReport:
    escalation_cycles_found: int
    backdoor_paths_detected: List[List[str]]
    recommended_revocations: List[DelegationEdge]
    residual_risk_score: float
    audit_latency_us: float


@dataclass(slots=True)
class SecurityAlert:
    alert_id: str
    timestamp_ms: int
    host_id: str
    tactic: MitreTactic
    severity: float  # [0, 1]
    causal_signature: str


@dataclass(slots=True)
class CausalKillChainTree:
    chain_id: str
    root_alert_id: str
    ordered_alerts: List[SecurityAlert]
    distinct_stages: List[MitreTactic]
    affected_hosts: Set[str]
    confidence_score: float


@dataclass(slots=True)
class CorrelationReport:
    total_alerts_processed: int
    isolated_kill_chains: List[CausalKillChainTree]
    noise_reduction_ratio_pct: float
    mean_chain_confidence: float
    correlation_latency_ms: float


@dataclass(slots=True)
class CyberDefenseBenchmarkReport:
    total_runtime_ms: float
    timestamp: str
    mincut_isolation_summary: Dict[str, float]
    honeynet_allocation_summary: Dict[str, float]
    cfi_patch_summary: Dict[str, float]
    privilege_audit_summary: Dict[str, float]
    killchain_correlation_summary: Dict[str, float]
