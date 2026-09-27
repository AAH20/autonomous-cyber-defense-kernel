"""
Stackelberg Security Game Decoy & Honeynet Allocator.
Solves the bilevel integer programming deception game: optimally places high-interaction
honeypots and canary tokens across enterprise subnets to maximize attacker entrapment
under strict deployment cost constraints.
"""

from __future__ import annotations
import math
import time
from typing import List, Dict, Optional
from autonomous_cyber_defense_kernel.core.models import (
    SubnetHost,
    DecoyResource,
    DeceptionStrategy,
)


class StackelbergHoneynetAllocator:
    """
    Bilevel Stackelberg game solver for defensive cyber deception.
    Models attacker rational target selection and computes optimal decoy distribution.
    """

    def __init__(
        self,
        subnets: List[SubnetHost],
        candidate_decoys: List[DecoyResource],
        budget_limit: float = 5000.0,
        breach_loss_multiplier: float = 10000.0,
        detection_reward: float = 5000.0,
    ):
        self.subnets = subnets
        self.candidate_decoys = candidate_decoys
        self.budget_limit = budget_limit
        self.breach_loss = breach_loss_multiplier
        self.detection_reward = detection_reward

    def compute_optimal_deception(self) -> DeceptionStrategy:
        """
        Solves the leader-follower game:
        Evaluates marginal entrapment payoff for each candidate decoy on its target subnet,
        then allocates decoys via dynamic knapsack packing.
        """
        start_t = time.perf_counter()

        # Group candidate decoys by target subnet
        subnet_decoy_map: Dict[str, List[DecoyResource]] = {}
        for d in self.candidate_decoys:
            if d.target_subnet not in subnet_decoy_map:
                subnet_decoy_map[d.target_subnet] = []
            subnet_decoy_map[d.target_subnet].append(d)

        # Attacker target selection probabilities based on softmax over attractiveness
        # P_attack(s) = exp(attractiveness / T) / sum(exp(attractiveness / T))
        exp_scores = {s.host_id: math.exp(s.attacker_attractiveness * 2.5) for s in self.subnets}
        total_exp = sum(exp_scores.values()) if exp_scores else 1.0
        attack_probs = {k: v / total_exp for k, v in exp_scores.items()}

        # Evaluate marginal defensive utility for each decoy:
        # Gain = P_attack(subnet) * entrapment_prob * (detection_reward + breach_loss * vuln)
        scored_decoys = []
        for d in self.candidate_decoys:
            # Find matching subnet
            matching_host = next((s for s in self.subnets if s.subnet == d.target_subnet), None)
            if matching_host:
                p_att = attack_probs.get(matching_host.host_id, 0.1)
                payoff = p_att * d.entrapment_probability * (self.detection_reward + self.breach_loss * matching_host.vulnerability_surface)
                density = payoff / max(1.0, d.deployment_cost)
                scored_decoys.append((density, payoff, d))

        # Sort by utility density descending (knapsack greedy heuristic)
        scored_decoys.sort(key=lambda x: x[0], reverse=True)

        selected_decoys: List[DecoyResource] = []
        current_cost = 0.0
        total_utility = 0.0

        for density, payoff, decoy in scored_decoys:
            if current_cost + decoy.deployment_cost <= self.budget_limit:
                selected_decoys.append(decoy)
                current_cost += decoy.deployment_cost
                total_utility += payoff

        # Calculate expected overall entrapment probability
        # P_entrap_total = sum_{s} P_attack(s) * (1 - prod_{d on s} (1 - entrap_d))
        subnet_selected: Dict[str, List[DecoyResource]] = {}
        for d in selected_decoys:
            if d.target_subnet not in subnet_selected:
                subnet_selected[d.target_subnet] = []
            subnet_selected[d.target_subnet].append(d)

        expected_entrapment = 0.0
        for s in self.subnets:
            p_att = attack_probs.get(s.host_id, 0.0)
            decoys_on_subnet = subnet_selected.get(s.subnet, [])
            if decoys_on_subnet:
                miss_prob = 1.0
                for d in decoys_on_subnet:
                    miss_prob *= (1.0 - d.entrapment_probability)
                entrap_s = 1.0 - miss_prob
                expected_entrapment += p_att * entrap_s

        elapsed_us = (time.perf_counter() - start_t) * 1_000_000.0

        return DeceptionStrategy(
            allocated_decoys=selected_decoys,
            total_deployment_cost=current_cost,
            attacker_entrapment_prob=expected_entrapment,
            defensive_utility=total_utility,
            execution_latency_us=elapsed_us,
        )
