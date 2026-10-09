from __future__ import annotations

import csv
import random
import sys
import time
from pathlib import Path

from run_authorization_attacks import evaluate, prepare_case
from run_barrier_binding_attacks import SCENARIOS, mutate
from ztai import Ed25519Signer, TrustStore


MECHANISMS = (
    "bearer_token",
    "epoch_identity",
    "signed_action_permit",
    "barrier_bound_principal_chain",
)


def build_signers_and_trust() -> tuple[dict[str, Ed25519Signer], TrustStore]:
    signers = {
        "principal": Ed25519Signer("principal:alice"),
        "instance": Ed25519Signer("instance:repaired"),
        "attacker": Ed25519Signer("attacker"),
        "attestation": Ed25519Signer("rats-verifier"),
        "recovery": Ed25519Signer("recovery-control"),
        "barrier": Ed25519Signer("barrier-control"),
        "delegation": Ed25519Signer("delegation-control"),
        "permit": Ed25519Signer("permit-control"),
    }
    trust = TrustStore()
    for role, name in (
        ("principal", "principal"),
        ("agent_instance", "instance"),
        ("agent_instance", "attacker"),
        ("attestation_verifier", "attestation"),
        ("recovery_authority", "recovery"),
        ("authority_barrier_authority", "barrier"),
        ("delegation_authority", "delegation"),
        ("permit_authority", "permit"),
    ):
        trust.register(role, signers[name])
    return signers, trust


def mechanism_order(trial: int, seed: int) -> tuple[str, ...]:
    offset = (trial + seed) % len(MECHANISMS)
    return MECHANISMS[offset:] + MECHANISMS[:offset]


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: run_barrier_baseline_comparison.py SEED TRIALS OUTPUT_CSV",
            file=sys.stderr,
        )
        return 2
    seed = int(sys.argv[1])
    trials = int(sys.argv[2])
    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    signers, trust = build_signers_and_trust()

    fields = (
        "seed",
        "trial",
        "scenario",
        "mechanism",
        "attack",
        "expected_authorized",
        "authorized",
        "unsafe_accept",
        "false_reject",
        "oracle_match",
        "evaluation_position",
        "reason",
        "latency_ns",
    )
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for trial in range(trials):
            scenario = SCENARIOS[(trial + seed) % len(SCENARIOS)]
            request, enforcer, now, active_epoch = prepare_case(
                scenario="valid",
                seed=seed,
                trial=trial,
                rng=rng,
                trust=trust,
                signers=signers,
            )
            request = mutate(
                request,
                scenario=scenario,
                identity=f"{seed}:{trial}",
                now=now,
                signers=signers,
            )
            expected = scenario == "valid"
            decisions: dict[str, bool] = {}
            for position, mechanism in enumerate(mechanism_order(trial, seed)):
                implementation = (
                    "effect_closed_principal_chain"
                    if mechanism == "barrier_bound_principal_chain"
                    else mechanism
                )
                started = time.perf_counter_ns()
                authorized, reason = evaluate(
                    implementation,
                    request,
                    enforcer,
                    now=now,
                    active_epoch=active_epoch,
                )
                latency = time.perf_counter_ns() - started
                decisions[mechanism] = authorized
                writer.writerow(
                    {
                        "seed": seed,
                        "trial": trial,
                        "scenario": scenario,
                        "mechanism": mechanism,
                        "attack": not expected,
                        "expected_authorized": expected,
                        "authorized": authorized,
                        "unsafe_accept": not expected and authorized,
                        "false_reject": expected and not authorized,
                        "oracle_match": authorized == expected,
                        "evaluation_position": position,
                        "reason": reason,
                        "latency_ns": latency,
                    }
                )
            if not decisions["barrier_bound_principal_chain"] == expected:
                raise AssertionError(
                    f"barrier-bound oracle mismatch: {scenario=} {decisions=}"
                )
            if expected and not all(decisions.values()):
                raise AssertionError(
                    f"valid request rejected by a baseline: {decisions=}"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
