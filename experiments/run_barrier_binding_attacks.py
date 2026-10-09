from __future__ import annotations

import csv
import dataclasses
import random
import sys
import time
from pathlib import Path

from run_authorization_attacks import prepare_case
from ztai import (
    AuthorityBarrierCertificate,
    AuthorizedEffectRequest,
    Ed25519Signer,
    TrustStore,
    make_execution_proof,
)
from ztai.model import RecoveryCertificate, digest


SCENARIOS = (
    "valid",
    "missing_barrier",
    "forged_barrier",
    "substituted_barrier",
    "permit_barrier_substitution",
    "delegation_barrier_substitution",
    "recovery_barrier_substitution",
    "wrong_provider_set",
    "future_barrier",
    "cross_workload_barrier",
    "cross_epoch_barrier",
)


def resign_permit(
    request: AuthorizedEffectRequest,
    permit,
    *,
    signers: dict[str, Ed25519Signer],
    now: int,
) -> AuthorizedEffectRequest:
    permit_envelope = signers["permit"].sign("action_permit", permit)
    proof = make_execution_proof(
        signers["instance"], permit_envelope, request.intent, now=now
    )
    return dataclasses.replace(
        request,
        permit_envelope=permit_envelope,
        proof_envelope=proof,
    )


def alternate_barrier(
    request: AuthorizedEffectRequest,
    *,
    identity: str,
    scenario: str,
    now: int,
) -> AuthorityBarrierCertificate:
    original = request.authority_barrier_envelope
    if original is None or not isinstance(original.payload, AuthorityBarrierCertificate):
        raise TypeError("valid request is missing its authority barrier")
    barrier = original.payload
    changes: dict[str, object] = {
        "transition_id": f"alternate:{identity}",
        "transition_digest": digest({"alternate": identity}),
        "acknowledgement_digests": (digest({"alternate_ack": identity}),),
    }
    if scenario == "wrong_provider_set":
        changes["provider_ids"] = ("inventory",)
    elif scenario == "future_barrier":
        changes["formed_at"] = now + 1
    elif scenario == "cross_workload_barrier":
        changes["workload_id"] = f"{barrier.workload_id}:other"
    elif scenario == "cross_epoch_barrier":
        changes["active_epoch"] = barrier.active_epoch + 1
    return dataclasses.replace(barrier, **changes)


def mutate(
    request: AuthorizedEffectRequest,
    *,
    scenario: str,
    identity: str,
    now: int,
    signers: dict[str, Ed25519Signer],
) -> AuthorizedEffectRequest:
    barrier_envelope = request.authority_barrier_envelope
    if barrier_envelope is None or not isinstance(
        barrier_envelope.payload, AuthorityBarrierCertificate
    ):
        raise TypeError("valid request is missing its authority barrier")
    if scenario == "valid":
        return request
    if scenario == "missing_barrier":
        return dataclasses.replace(request, authority_barrier_envelope=None)
    if scenario == "forged_barrier":
        return dataclasses.replace(
            request,
            authority_barrier_envelope=signers["attacker"].sign(
                "authority_barrier", barrier_envelope.payload
            ),
        )
    if scenario in {
        "substituted_barrier",
        "wrong_provider_set",
        "future_barrier",
        "cross_workload_barrier",
        "cross_epoch_barrier",
    }:
        barrier = alternate_barrier(
            request,
            identity=identity,
            scenario=scenario,
            now=now,
        )
        return dataclasses.replace(
            request,
            authority_barrier_envelope=signers["barrier"].sign(
                "authority_barrier", barrier
            ),
        )

    replacement_digest = digest({"replacement_barrier": identity})
    if scenario == "permit_barrier_substitution":
        permit = dataclasses.replace(
            request.permit_envelope.payload,
            authority_barrier_digest=replacement_digest,
        )
        return resign_permit(request, permit, signers=signers, now=now)

    grant = dataclasses.replace(
        request.delegation_envelope.payload,
        authority_barrier_digest=replacement_digest,
    )
    if scenario == "delegation_barrier_substitution":
        delegation_envelope = signers["delegation"].sign(
            "delegation_grant", grant
        )
        permit = dataclasses.replace(
            request.permit_envelope.payload,
            delegation_digest=digest(grant),
            authority_barrier_digest=replacement_digest,
        )
        changed = dataclasses.replace(
            request, delegation_envelope=delegation_envelope
        )
        return resign_permit(changed, permit, signers=signers, now=now)

    if scenario == "recovery_barrier_substitution":
        recovery = request.recovery_envelope.payload
        if not isinstance(recovery, RecoveryCertificate):
            raise TypeError("valid request has malformed recovery evidence")
        recovery_grant = dataclasses.replace(
            recovery.grant,
            authority_barrier_digest=replacement_digest,
        )
        recovery = dataclasses.replace(recovery, grant=recovery_grant)
        recovery = dataclasses.replace(
            recovery,
            lineage_digest=digest(
                {
                    "incident": recovery.grant.incident_digest,
                    "closure": recovery.grant.closure_digest,
                    "attestation": recovery.grant.attestation_digest,
                    "grant": digest(recovery.grant),
                    "reconciliation": recovery.reconciliation_digest,
                    "instructions": recovery.instructions,
                }
            ),
        )
        recovery_envelope = signers["recovery"].sign(
            "recovery_certificate", recovery
        )
        grant = dataclasses.replace(
            grant,
            recovery_certificate_digest=digest(recovery),
        )
        delegation_envelope = signers["delegation"].sign(
            "delegation_grant", grant
        )
        permit = dataclasses.replace(
            request.permit_envelope.payload,
            delegation_digest=digest(grant),
            authority_barrier_digest=replacement_digest,
        )
        changed = dataclasses.replace(
            request,
            recovery_envelope=recovery_envelope,
            delegation_envelope=delegation_envelope,
        )
        return resign_permit(changed, permit, signers=signers, now=now)
    raise ValueError(scenario)


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: run_barrier_binding_attacks.py SEED TRIALS OUTPUT_CSV",
            file=sys.stderr,
        )
        return 2
    seed = int(sys.argv[1])
    trials = int(sys.argv[2])
    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
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

    fields = (
        "seed",
        "trial",
        "scenario",
        "expected_authorized",
        "authorized",
        "correct",
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
            started = time.perf_counter_ns()
            decision = enforcer.verify_full_chain(
                request, now=now, active_epoch=active_epoch
            )
            latency = time.perf_counter_ns() - started
            expected = scenario == "valid"
            correct = decision.authorized == expected
            if not correct:
                raise AssertionError(
                    f"barrier-binding oracle mismatch: {scenario=} {decision=}"
                )
            writer.writerow(
                {
                    "seed": seed,
                    "trial": trial,
                    "scenario": scenario,
                    "expected_authorized": expected,
                    "authorized": decision.authorized,
                    "correct": correct,
                    "reason": "|".join(decision.reasons),
                    "latency_ns": latency,
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
