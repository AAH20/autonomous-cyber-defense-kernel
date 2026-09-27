"""
Command-Line Interface for Autonomous Cyber Defense Kernel.
Provides CLI subcommands for individual defensive solvers and unified benchmark execution.
"""

from __future__ import annotations
import argparse
import json
import sys
from autonomous_cyber_defense_kernel.engine import AutonomousCyberDefenseEngine


def print_banner():
    banner = r"""
================================================================================
       AUTONOMOUS CYBER DEFENSE APEX NP-HARD KERNEL
   Attack-Graph Min-Cut, Stackelberg Deception, CFI Verification & Kill-Chains
================================================================================
"""
    print(banner)


def run_benchmark_all():
    print_banner()
    print("[*] Launching Autonomous Cyber Defense Algorithmic Benchmarks...")
    engine = AutonomousCyberDefenseEngine()

    report = engine.run_comprehensive_benchmark()

    print("\n" + "=" * 80)
    print("1. ATTACK GRAPH MULTI-TERMINAL MIN-CUT QUARANTINE ISOLATOR")
    print("=" * 80)
    mincut = report.mincut_isolation_summary
    print(f"  * Enterprise Graph Size          : {mincut['total_nodes_in_graph']} nodes, {mincut['total_edges_in_graph']} edges")
    print(f"  * Active Ingress Compromises     : {mincut['compromised_nodes_count']} infected endpoints")
    print(f"  * Crown Jewel Infrastructure     : {mincut['crown_jewel_nodes_count']} domain controllers / core DBs")
    print(f"  * Severed Firewall / Route Edges : {mincut['severed_edges_count']} boundary links")
    print(f"  * Total Business Disruption Cost : ${mincut['total_disruption_cost_usd']:,.2f}")
    print(f"  * Quarantined Compromised Hosts  : {mincut['quarantined_hosts_count']} nodes")
    print(f"  * Zero-Reachability Guaranteed   : {mincut['containment_guaranteed']}")
    print(f"  * Solver Isolation Latency       : {mincut['isolation_latency_us']:.2f} µs")

    print("\n" + "=" * 80)
    print("2. BILEVEL STACKELBERG HONEYNET & DECEPTION ALLOCATOR")
    print("=" * 80)
    honey = report.honeynet_allocation_summary
    print(f"  * Monitored Enterprise Subnets   : {honey['target_subnets_protected']}")
    print(f"  * Decoy Candidates Evaluated     : {honey['candidate_decoys_evaluated']} (honeypots & canaries)")
    print(f"  * Deployed Strategic Decoys      : {honey['deployed_decoys_count']}")
    print(f"  * Total Deployment Expenditure   : ${honey['total_deployment_cost_usd']:,.2f}")
    print(f"  * Attacker Entrapment Likelihood : {honey['attacker_entrapment_probability_pct']:.1f}%")
    print(f"  * Defensive Payoff Utility       : {honey['defensive_utility_score']:.2f}")
    print(f"  * Game-Theoretic Solver Latency  : {honey['allocation_latency_us']:.2f} µs")

    print("\n" + "=" * 80)
    print("3. CONTROL-FLOW INTEGRITY (CFI) BINARY HOT-PATCH VERIFIER")
    print("=" * 80)
    cfi = report.cfi_patch_summary
    print(f"  * Candidate Patches Evaluated    : {cfi['total_candidate_patches']}")
    print(f"  * Formally Verified Safe Patches : {cfi['formally_verified_safe_patches']}")
    print(f"  * Unsafe Exploitable Discarded   : {cfi['rejected_unsafe_patches']}")
    print(f"  * CFI Invariant Violations Caught: {cfi['cfi_violations_caught']}")
    print(f"  * Average Verification Latency   : {cfi['average_verification_time_us']:.2f} µs")

    print("\n" + "=" * 80)
    print("4. IDENTITY PRIVILEGE GRAPH DECONFLICTION & BACKDOOR ELIMINATOR")
    print("=" * 80)
    priv = report.privilege_audit_summary
    print(f"  * Audited Identity Entities      : {priv['identity_entities_audited']} (users, groups, service accts)")
    print(f"  * Delegations & Access Edges     : {priv['privilege_delegations_audited']}")
    print(f"  * Circular Escalation Loops      : {priv['escalation_cycles_detected']} cyclic backdoors")
    print(f"  * Dangerous Paths to Admin Tier  : {priv['dangerous_paths_to_admin']} transitive paths")
    print(f"  * Minimal Edge Revocations       : {priv['minimal_edges_revoked']} delegations cut")
    print(f"  * Residual Privilege Risk Score  : {priv['residual_risk_score']:.1f}")
    print(f"  * FAS Graph Solver Latency       : {priv['audit_latency_us']:.2f} µs")

    print("\n" + "=" * 80)
    print("5. SIEM / EDR CAUSAL KILL-CHAIN CORRELATOR (MITRE ATT&CK)")
    print("=" * 80)
    kill = report.killchain_correlation_summary
    print(f"  * Raw Telemetry Alerts Ingested  : {kill['raw_alerts_processed']:,}")
    print(f"  * Discovered Multi-Stage Chains  : {kill['isolated_kill_chain_trees']} APT kill-chain trees")
    print(f"  * Noise Reduction Filtering Ratio: {kill['noise_reduction_ratio_pct']:.1f}% noise eliminated")
    print(f"  * Average Kill-Chain Confidence  : {kill['mean_chain_confidence']*100.0:.1f}%")
    print(f"  * Stream Correlation Latency     : {kill['correlation_latency_ms']:.2f} ms")

    print("\n" + "=" * 80)
    print(f"ALL 5 DEFENSIVE CYBER SOLVERS EXECUTED IN {report.total_runtime_ms:.2f} ms")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous Cyber Defense Apex NP-Hard Solver Suite CLI"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("benchmark-all", help="Execute all 5 defensive solvers with unified telemetry")
    subparsers.add_parser("isolate", help="Run Attack-Graph Multi-Terminal Min-Cut Quarantine")
    subparsers.add_parser("honeynet", help="Run Stackelberg Bilevel Honeynet Allocation")
    subparsers.add_parser("verify-patch", help="Run CFI Binary Hot-Patch Verification")
    subparsers.add_parser("audit-privileges", help="Run Identity Privilege Graph Audit")
    subparsers.add_parser("correlate", help="Run SIEM / EDR Causal Kill-Chain Correlator")

    args = parser.parse_args()

    engine = AutonomousCyberDefenseEngine()

    if args.command == "benchmark-all" or args.command is None:
        run_benchmark_all()
    elif args.command == "isolate":
        res = engine.run_mincut_isolation_benchmark()
        print(json.dumps(res, indent=2))
    elif args.command == "honeynet":
        res = engine.run_honeynet_allocation_benchmark()
        print(json.dumps(res, indent=2))
    elif args.command == "verify-patch":
        res = engine.run_cfi_patch_benchmark()
        print(json.dumps(res, indent=2))
    elif args.command == "audit-privileges":
        res = engine.run_privilege_audit_benchmark()
        print(json.dumps(res, indent=2))
    elif args.command == "correlate":
        res = engine.run_killchain_correlation_benchmark()
        print(json.dumps(res, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
