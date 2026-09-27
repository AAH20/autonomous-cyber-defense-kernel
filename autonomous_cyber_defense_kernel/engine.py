"""
Integrated Execution Engine for Autonomous Cyber Defense Kernel.
Runs sub-millisecond benchmarks across all 5 core algorithmic defensive modules.
"""

from __future__ import annotations
import datetime
import random
import time
from typing import Dict, Any, List, Set
from autonomous_cyber_defense_kernel.core.models import (
    AssetCriticalityTier,
    MitreTactic,
    AssetNode,
    NetworkEdge,
    SubnetHost,
    DecoyResource,
    BinaryPatchCandidate,
    IdentityEntity,
    DelegationEdge,
    SecurityAlert,
    CyberDefenseBenchmarkReport,
)
from autonomous_cyber_defense_kernel.core.attack_graph_mincut_isolator import AttackGraphMinCutIsolator
from autonomous_cyber_defense_kernel.core.stackelberg_honeynet_allocator import StackelbergHoneynetAllocator
from autonomous_cyber_defense_kernel.core.cfi_binary_patch_verifier import CfiBinaryPatchVerifier
from autonomous_cyber_defense_kernel.core.identity_privilege_deconfliction import IdentityPrivilegeDeconflictionSolver
from autonomous_cyber_defense_kernel.core.kill_chain_causal_correlator import KillChainCausalCorrelator


class AutonomousCyberDefenseEngine:
    """Orchestrates comprehensive microsecond-grade defensive cybersecurity benchmarks."""

    def __init__(self):
        pass

    def run_mincut_isolation_benchmark(self) -> Dict[str, Any]:
        """Benchmarks multi-terminal min-cut quarantine on a 50-node network."""
        prng = random.Random(42)
        nodes: List[AssetNode] = []
        for i in range(50):
            is_comp = (i < 4)  # First 4 nodes infected (initial ingress)
            is_cj = (i >= 42)  # Last 8 nodes are crown jewel DBs / domain controllers
            crit = AssetCriticalityTier.CROWN_JEWEL if is_cj else (AssetCriticalityTier.HIGH if i > 30 else AssetCriticalityTier.MEDIUM)
            nodes.append(AssetNode(
                asset_id=f"host_{i}",
                name=f"EnterpriseHost_{i}",
                zone=f"vlan_{i // 10}",
                criticality=crit,
                is_compromised=is_comp,
                is_crown_jewel=is_cj,
            ))

        # Build network edges with business interruption costs
        edges: List[NetworkEdge] = []
        edge_id = 0
        for i in range(50):
            # Connect to adjacent hosts in same and next vlan
            for offset in [1, 2, 8, 10]:
                target = (i + offset) % 50
                if target != i:
                    cost = prng.uniform(50.0, 500.0)
                    edges.append(NetworkEdge(
                        edge_id=f"edge_{edge_id}",
                        source_id=f"host_{i}",
                        target_id=f"host_{target}",
                        bandwidth_mbps=1000.0,
                        business_cost_to_sever=cost,
                        protocols=["TCP/443", "TCP/445", "TCP/80"],
                    ))
                    edge_id += 1

        isolator = AttackGraphMinCutIsolator(nodes, edges)
        plan = isolator.compute_isolation_cut()

        return {
            "total_nodes_in_graph": len(nodes),
            "total_edges_in_graph": len(edges),
            "compromised_nodes_count": 4,
            "crown_jewel_nodes_count": 8,
            "severed_edges_count": len(plan.severed_edges),
            "total_disruption_cost_usd": plan.total_disruption_cost,
            "quarantined_hosts_count": len(plan.quarantined_nodes),
            "containment_guaranteed": plan.is_containment_guaranteed,
            "isolation_latency_us": plan.execution_latency_us,
        }

    def run_honeynet_allocation_benchmark(self) -> Dict[str, Any]:
        """Benchmarks Stackelberg bilevel decoy and honeynet resource allocation."""
        prng = random.Random(123)
        subnets = [
            SubnetHost(f"subnet_{i}", f"10.0.{i}.0/24", vulnerability_surface=prng.uniform(0.2, 0.85), real_service_type="web" if i < 5 else "db", attacker_attractiveness=prng.uniform(0.3, 0.95))
            for i in range(15)
        ]

        decoys = []
        for i in range(40):
            sub_id = f"10.0.{i % 15}.0/24"
            decoys.append(DecoyResource(
                decoy_id=f"decoy_{i}",
                target_subnet=sub_id,
                decoy_type=["honeypot_ssh", "canary_token", "fake_db", "decoy_ad_account"][i % 4],
                deployment_cost=prng.uniform(150.0, 600.0),
                entrapment_probability=prng.uniform(0.40, 0.85),
            ))

        allocator = StackelbergHoneynetAllocator(subnets, decoys, budget_limit=4500.0)
        strategy = allocator.compute_optimal_deception()

        return {
            "target_subnets_protected": len(subnets),
            "candidate_decoys_evaluated": len(decoys),
            "deployed_decoys_count": len(strategy.allocated_decoys),
            "total_deployment_cost_usd": strategy.total_deployment_cost,
            "attacker_entrapment_probability_pct": strategy.attacker_entrapment_prob * 100.0,
            "defensive_utility_score": strategy.defensive_utility,
            "allocation_latency_us": strategy.execution_latency_us,
        }

    def run_cfi_patch_benchmark(self) -> Dict[str, Any]:
        """Benchmarks Control-Flow Integrity (CFI) binary hot-patch verification."""
        allowed_targets = {0x401000, 0x401200, 0x401400, 0x401800, 0x402000, 0x403000}
        valid_returns = {0x401000 + 15, 0x401200 + 15, 0x401400 + 15, 0x401800 + 15, 0x402000 + 15}
        verifier = CfiBinaryPatchVerifier(allowed_targets, valid_returns)

        # Synthesized candidate patches
        patches = [
            BinaryPatchCandidate("patch_1", "malloc_check", "buffer_overflow", 15, 0x402000, 4, preserves_stack_alignment=True, respects_cfi=True),
            BinaryPatchCandidate("patch_2", "bounds_check", "integer_overflow", 15, 0x401400, 3, preserves_stack_alignment=True, respects_cfi=True),
            BinaryPatchCandidate("patch_3", "format_check", "format_string", 15, 0x401800, 5, preserves_stack_alignment=True, respects_cfi=True),
            BinaryPatchCandidate("patch_4", "invalid_hook", "uaf", 15, 0x500000, 4, preserves_stack_alignment=False, respects_cfi=False),
        ]

        verified_count = 0
        total_violations = 0
        total_time_us = 0.0

        for p in patches:
            branch_targets = [p.trampoline_target_addr]
            rep = verifier.verify_patch(p, branch_targets, base_address=0x401000)
            if rep.is_safe:
                verified_count += 1
            total_violations += rep.cfi_violations_detected
            total_time_us += rep.verification_time_us

        return {
            "total_candidate_patches": len(patches),
            "formally_verified_safe_patches": verified_count,
            "rejected_unsafe_patches": len(patches) - verified_count,
            "cfi_violations_caught": total_violations,
            "average_verification_time_us": total_time_us / len(patches),
        }

    def run_privilege_audit_benchmark(self) -> Dict[str, Any]:
        """Benchmarks identity privilege graph audit and transitive backdoor elimination."""
        entities = [
            IdentityEntity(f"user_{i}", "USER", privilege_tier=1 if i < 20 else (3 if i < 30 else 5))
            for i in range(35)
        ] + [
            IdentityEntity("domain_admins", "GROUP", privilege_tier=10),
            IdentityEntity("it_support", "GROUP", privilege_tier=6),
            IdentityEntity("svc_backup", "SERVICE_ACCOUNT", privilege_tier=8),
        ]

        # Delegations with intentional backdoor escalation chains and circular loops
        edges = [
            DelegationEdge("del_1", "user_5", "it_support", "MemberOf"),
            DelegationEdge("del_2", "it_support", "svc_backup", "GenericAll"),
            DelegationEdge("del_3", "svc_backup", "domain_admins", "DCSync"),
            # Circular backdoor loop: user_10 -> user_12 -> user_14 -> user_10
            DelegationEdge("del_4", "user_10", "user_12", "WriteDacl"),
            DelegationEdge("del_5", "user_12", "user_14", "GenericWrite"),
            DelegationEdge("del_6", "user_14", "user_10", "Owns"),
        ]

        auditor = IdentityPrivilegeDeconflictionSolver(entities, edges)
        report = auditor.audit_and_remediate(max_unprivileged_tier=3, admin_tier=10)

        return {
            "identity_entities_audited": len(entities),
            "privilege_delegations_audited": len(edges),
            "escalation_cycles_detected": report.escalation_cycles_found,
            "dangerous_paths_to_admin": len(report.backdoor_paths_detected),
            "minimal_edges_revoked": len(report.recommended_revocations),
            "residual_risk_score": report.residual_risk_score,
            "audit_latency_us": report.audit_latency_us,
        }

    def run_killchain_correlation_benchmark(self, num_alerts: int = 250) -> Dict[str, Any]:
        """Benchmarks SIEM / EDR causal kill-chain correlation and noise reduction."""
        prng = random.Random(777)
        tactics_seq = [
            MitreTactic.INITIAL_ACCESS,
            MitreTactic.EXECUTION,
            MitreTactic.PRIVILEGE_ESCALATION,
            MitreTactic.LATERAL_MOVEMENT,
            MitreTactic.EXFILTRATION,
        ]

        alerts: List[SecurityAlert] = []
        base_t = 1700000000000

        # Inject 3 coherent multi-stage attack chains
        for chain_idx in range(3):
            chain_sig = f"apt_session_{chain_idx}"
            for step_idx, tactic in enumerate(tactics_seq):
                alerts.append(SecurityAlert(
                    alert_id=f"chain_{chain_idx}_alert_{step_idx}",
                    timestamp_ms=base_t + (chain_idx * 500000) + (step_idx * 60000),
                    host_id=f"host_{chain_idx * 5 + step_idx}",
                    tactic=tactic,
                    severity=0.85 + (step_idx * 0.02),
                    causal_signature=chain_sig,
                ))

        # Inject background uncorrelated noise alerts (benign anomalies, noisy EDR detections)
        for i in range(num_alerts - len(alerts)):
            alerts.append(SecurityAlert(
                alert_id=f"noise_alert_{i}",
                timestamp_ms=base_t + prng.randint(0, 3000000),
                host_id=f"host_{prng.randint(0, 49)}",
                tactic=prng.choice(list(MitreTactic)),
                severity=prng.uniform(0.1, 0.45),
                causal_signature=f"noise_sig_{i}",
            ))

        correlator = KillChainCausalCorrelator()
        report = correlator.correlate_alerts(alerts, min_chain_stages=3)

        return {
            "raw_alerts_processed": report.total_alerts_processed,
            "isolated_kill_chain_trees": len(report.isolated_kill_chains),
            "noise_reduction_ratio_pct": report.noise_reduction_ratio_pct,
            "mean_chain_confidence": report.mean_chain_confidence,
            "correlation_latency_ms": report.correlation_latency_ms,
        }

    def run_comprehensive_benchmark(self) -> CyberDefenseBenchmarkReport:
        """Executes all 5 cyber defense solvers into a unified benchmark report."""
        t0 = time.perf_counter()

        mincut_res = self.run_mincut_isolation_benchmark()
        honey_res = self.run_honeynet_allocation_benchmark()
        cfi_res = self.run_cfi_patch_benchmark()
        priv_res = self.run_privilege_audit_benchmark()
        kill_res = self.run_killchain_correlation_benchmark()

        total_runtime_ms = (time.perf_counter() - t0) * 1000.0

        return CyberDefenseBenchmarkReport(
            total_runtime_ms=total_runtime_ms,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            mincut_isolation_summary=mincut_res,
            honeynet_allocation_summary=honey_res,
            cfi_patch_summary=cfi_res,
            privilege_audit_summary=priv_res,
            killchain_correlation_summary=kill_res,
        )
