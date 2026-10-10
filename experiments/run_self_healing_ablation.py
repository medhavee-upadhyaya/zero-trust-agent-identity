from __future__ import annotations

import csv
import dataclasses
import random
import sys
import tempfile
import time
from pathlib import Path

from run_networked_authority_faults import (
    PROVIDER_IDS,
    effect_request,
    network_providers,
    replace_provider,
    start_provider,
)
from run_self_healing_faults import (
    EXPECTED_AUTHORIZED,
    RECOVERABLE,
    ROTATION_SCENARIOS,
    SCENARIOS,
    ConflictingNetworkProvider,
)
from ztai import (
    AuthorityTransition,
    DistributedAuthorityCoordinator,
    Ed25519Signer,
    NetworkAuthorityProvider,
    ProviderClient,
    ProviderDatabase,
    ProviderKeyRotationAttestation,
    ProviderProcess,
    RecoveryStatus,
    SelfHealingAuthorityController,
    TrustStore,
    make_provider_key_rotation_attestation,
)
from ztai.crypto import decode_public_key


MECHANISMS = (
    "no_healing",
    "transport_retry",
    "blind_key_auto_trust",
    "bounded_attested_healing",
)


def mechanism_order(trial: int, seed: int) -> tuple[str, ...]:
    occurrence = trial // len(SCENARIOS)
    offset = (occurrence + seed) % len(MECHANISMS)
    return MECHANISMS[offset:] + MECHANISMS[:offset]


def ensure_base_provider(
    *,
    provider_id: str,
    databases: dict[str, ProviderDatabase],
    processes: dict[str, ProviderProcess],
    base_signers: dict[str, Ed25519Signer],
    transition_signer: Ed25519Signer,
    trust: TrustStore,
) -> None:
    process = processes[provider_id]
    alive = process.process is not None and process.process.is_alive()
    base_fingerprint = base_signers[provider_id].public_key_fingerprint
    if not alive or process.signer.public_key_fingerprint != base_fingerprint:
        replace_provider(
            provider_id=provider_id,
            signer=base_signers[provider_id],
            databases=databases,
            processes=processes,
            transition_signer=transition_signer,
        )
    trust.register("effect_provider", base_signers[provider_id])


def operational_recover(
    *,
    mechanism: str,
    transition_envelope,
    now: int,
    providers,
    trust: TrustStore,
    barrier_signer: Ed25519Signer,
    repair_provider,
    rotation_attestations,
):
    attempts = 1
    coordinator = DistributedAuthorityCoordinator(
        trust_store=trust,
        providers=providers,
        barrier_signer=barrier_signer,
    )
    decision = coordinator.establish_barrier(transition_envelope, now=now)
    if mechanism == "no_healing":
        return decision, attempts, coordinator

    while decision.status is RecoveryStatus.QUARANTINED and attempts < 3:
        changed = False
        for reason in decision.reasons:
            if reason.startswith("unavailable_provider:"):
                provider_id = reason.split(":", 1)[1]
                providers[provider_id] = repair_provider(
                    provider_id, "transport_failure"
                )
                changed = True
            elif (
                mechanism == "blind_key_auto_trust"
                and reason.startswith("invalid_ack_signature:")
            ):
                provider_id = reason.split(":", 1)[1]
                envelope = rotation_attestations.get(provider_id)
                if envelope is None or not isinstance(
                    envelope.payload, ProviderKeyRotationAttestation
                ):
                    continue
                try:
                    public_key = decode_public_key(
                        envelope.payload.new_public_key
                    )
                except (TypeError, ValueError):
                    continue
                trust.register_public_key(
                    "effect_provider", provider_id, public_key
                )
                providers[provider_id] = repair_provider(
                    provider_id, "blind_key_auto_trust"
                )
                changed = True
        if not changed:
            break
        attempts += 1
        coordinator = DistributedAuthorityCoordinator(
            trust_store=trust,
            providers=providers,
            barrier_signer=barrier_signer,
        )
        decision = coordinator.establish_barrier(
            transition_envelope,
            now=now + attempts - 1,
        )
    return decision, attempts, coordinator


def run_mechanism(
    *,
    seed: int,
    trial: int,
    scenario: str,
    mechanism: str,
    position: int,
    target: str,
    databases: dict[str, ProviderDatabase],
    processes: dict[str, ProviderProcess],
    base_signers: dict[str, Ed25519Signer],
    transition_signer: Ed25519Signer,
    barrier_signer: Ed25519Signer,
    audit_signer: Ed25519Signer,
    key_attestation_signer: Ed25519Signer,
    attacker: Ed25519Signer,
    trust: TrustStore,
) -> dict[str, object]:
    ensure_base_provider(
        provider_id=target,
        databases=databases,
        processes=processes,
        base_signers=base_signers,
        transition_signer=transition_signer,
        trust=trust,
    )
    identity = f"{seed}:{trial}:{scenario}:{mechanism}"
    pair_id = f"{seed}:{trial}:{scenario}"
    incident_id = f"incident:{identity}"
    workload_id = f"agent:{identity}"
    old_epoch = trial * 2 + 1
    new_epoch = old_epoch + 1
    issued_at = 30_000 + trial * 10
    for database in databases.values():
        database.establish_epoch(workload_id, old_epoch, issued_at - 1)
    transition = AuthorityTransition(
        f"transition:{identity}",
        incident_id,
        workload_id,
        1,
        old_epoch,
        new_epoch,
        PROVIDER_IDS,
        issued_at,
    )
    transition_envelope = transition_signer.sign(
        "authority_transition", transition
    )
    providers = network_providers(processes)
    rotation_attestations = {}

    try:
        if scenario == "delayed_transition":
            providers[target] = NetworkAuthorityProvider(
                target,
                processes[target].base_url,
                timeout=0.25,
                fault="drop_before_persist",
            )
        elif scenario == "lost_ack_after_persist":
            providers[target] = NetworkAuthorityProvider(
                target,
                processes[target].base_url,
                timeout=0.25,
                fault="drop_after_persist",
            )
        elif scenario == "crash_before_persist":
            providers[target] = NetworkAuthorityProvider(
                target,
                processes[target].base_url,
                timeout=0.25,
                fault="crash_before_persist",
            )
        elif scenario == "crash_after_persist":
            providers[target] = NetworkAuthorityProvider(
                target,
                processes[target].base_url,
                timeout=0.25,
                fault="crash_after_persist",
            )
        elif scenario in {"temporary_partition", "permanent_partition"}:
            providers[target] = NetworkAuthorityProvider(
                target,
                "http://127.0.0.1:1",
                timeout=0.05,
            )
        elif scenario in ROTATION_SCENARIOS:
            rotated_signer = Ed25519Signer(target)
            replace_provider(
                provider_id=target,
                signer=rotated_signer,
                databases=databases,
                processes=processes,
                transition_signer=transition_signer,
            )
            providers[target] = NetworkAuthorityProvider(
                target,
                processes[target].base_url,
                timeout=0.25,
            )
            valid_attestation = make_provider_key_rotation_attestation(
                attestation_signer=key_attestation_signer,
                provider_id=target,
                transition=transition,
                previous_key_fingerprint=(
                    base_signers[target].public_key_fingerprint
                ),
                new_signer=rotated_signer,
                issued_at=issued_at,
                expires_at=issued_at + 100,
                rotation_id=f"rotation:{identity}",
            )
            if scenario == "attested_key_rotation":
                rotation_attestations[target] = valid_attestation
            elif scenario == "forged_rotation_attestation":
                rotation_attestations[target] = attacker.sign(
                    "provider_key_rotation_attestation",
                    valid_attestation.payload,
                )
            elif scenario == "expired_rotation_attestation":
                payload = dataclasses.replace(
                    valid_attestation.payload,
                    expires_at=issued_at,
                )
                rotation_attestations[target] = key_attestation_signer.sign(
                    "provider_key_rotation_attestation", payload
                )
            elif scenario == "wrong_transition_attestation":
                payload = dataclasses.replace(
                    valid_attestation.payload,
                    transition_id=f"other:{identity}",
                )
                rotation_attestations[target] = key_attestation_signer.sign(
                    "provider_key_rotation_attestation", payload
                )
            elif scenario == "wrong_provider_attestation":
                payload = dataclasses.replace(
                    valid_attestation.payload,
                    provider_id=next(
                        item for item in PROVIDER_IDS if item != target
                    ),
                )
                rotation_attestations[target] = key_attestation_signer.sign(
                    "provider_key_rotation_attestation", payload
                )
        elif scenario == "conflicting_signed_ack":
            providers[target] = ConflictingNetworkProvider(
                providers[target],
                base_signers[target],
            )

        permanent_provider = providers[target]

        def repair_provider(provider_id: str, action: str):
            if scenario == "permanent_partition":
                return permanent_provider
            if scenario in {"crash_before_persist", "crash_after_persist"}:
                process = processes[provider_id]
                if process.process is None or not process.process.is_alive():
                    replace_provider(
                        provider_id=provider_id,
                        signer=base_signers[provider_id],
                        databases=databases,
                        processes=processes,
                        transition_signer=transition_signer,
                    )
            return NetworkAuthorityProvider(
                provider_id,
                processes[provider_id].base_url,
                timeout=0.25,
            )

        started = time.perf_counter_ns()
        audit_valid: bool | str = ""
        if mechanism == "bounded_attested_healing":
            controller = SelfHealingAuthorityController(
                trust_store=trust,
                providers=providers,
                barrier_signer=barrier_signer,
                audit_signer=audit_signer,
                repair_provider=repair_provider,
                max_attempts=3,
            )
            result = controller.recover(
                transition_envelope,
                now=issued_at + 1,
                rotation_attestations=rotation_attestations,
            )
            decision = result.decision
            attempts = result.attempts
            barrier_valid = (
                decision.status is RecoveryStatus.AUTHORIZED
                and controller.verify_barrier(decision)
            )
            audit_valid = controller.verify_result(
                result, transition_envelope
            )
        else:
            decision, attempts, coordinator = operational_recover(
                mechanism=mechanism,
                transition_envelope=transition_envelope,
                now=issued_at + 1,
                providers=providers,
                trust=trust,
                barrier_signer=barrier_signer,
                repair_provider=repair_provider,
                rotation_attestations=rotation_attestations,
            )
            barrier_valid = (
                decision.status is RecoveryStatus.AUTHORIZED
                and coordinator.verify_barrier(decision)
            )
        latency = time.perf_counter_ns() - started
        authorized = decision.status is RecoveryStatus.AUTHORIZED

        old_attempts = 0
        old_commits = 0
        successor_effects = 0
        exactly_once: bool | str = ""
        if authorized:
            for provider_id in PROVIDER_IDS:
                client = ProviderClient(
                    processes[provider_id].base_url,
                    timeout=0.25,
                )
                old_attempts += 1
                old = client.execute(
                    effect_request(
                        identity=identity,
                        provider_id=provider_id,
                        workload_id=workload_id,
                        incident_id=incident_id,
                        epoch=old_epoch,
                        phase="ablation-old",
                    )
                )
                old_commits += old.status == "committed"
                successor = client.execute(
                    effect_request(
                        identity=identity,
                        provider_id=provider_id,
                        workload_id=workload_id,
                        incident_id=incident_id,
                        epoch=new_epoch,
                        phase="ablation-successor",
                    )
                )
                successor_effects += successor.status == "committed"
            exactly_once = all(
                databases[provider_id].effect_count(
                    incident_id,
                    f"ablation-successor:{provider_id}",
                )
                == 1
                for provider_id in PROVIDER_IDS
            )

        expected_authorized = scenario in EXPECTED_AUTHORIZED
        expected_recovered = scenario in RECOVERABLE
        recovered = expected_recovered and authorized
        false_recovery = not expected_authorized and authorized
        false_quarantine = expected_authorized and not authorized
        unsafe_release = (
            false_recovery
            or (authorized and not barrier_valid)
            or old_commits > 0
        )
        oracle_match = authorized == expected_authorized
        return {
            "seed": seed,
            "trial": trial,
            "pair_id": pair_id,
            "scenario": scenario,
            "mechanism": mechanism,
            "evaluation_position": position,
            "fault_provider": target,
            "expected_authorized": expected_authorized,
            "expected_recovered": expected_recovered,
            "final_authorized": authorized,
            "recovered": recovered,
            "oracle_match": oracle_match,
            "false_recovery": false_recovery,
            "false_quarantine": false_quarantine,
            "unsafe_release": unsafe_release,
            "barrier_valid": barrier_valid,
            "audit_valid": audit_valid,
            "attempts": attempts,
            "post_barrier_old_attempts": old_attempts,
            "post_barrier_old_commits": old_commits,
            "successor_effects": successor_effects,
            "exactly_once": exactly_once,
            "latency_ns": latency,
        }
    finally:
        ensure_base_provider(
            provider_id=target,
            databases=databases,
            processes=processes,
            base_signers=base_signers,
            transition_signer=transition_signer,
            trust=trust,
        )


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: run_self_healing_ablation.py SEED TRIALS OUTPUT_CSV",
            file=sys.stderr,
        )
        return 2
    seed = int(sys.argv[1])
    trials = int(sys.argv[2])
    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    transition_signer = Ed25519Signer("authority-control")
    barrier_signer = Ed25519Signer("barrier-control")
    audit_signer = Ed25519Signer("healing-control")
    key_attestation_signer = Ed25519Signer("key-attestation-control")
    attacker = Ed25519Signer("attacker")
    base_signers = {
        provider_id: Ed25519Signer(provider_id) for provider_id in PROVIDER_IDS
    }
    trust = TrustStore()
    for role, signer in (
        ("authority_transition_authority", transition_signer),
        ("authority_barrier_authority", barrier_signer),
        ("self_healing_authority", audit_signer),
        ("provider_key_attestation_authority", key_attestation_signer),
    ):
        trust.register(role, signer)
    for signer in base_signers.values():
        trust.register("effect_provider", signer)
    fields = (
        "seed",
        "trial",
        "pair_id",
        "scenario",
        "mechanism",
        "evaluation_position",
        "fault_provider",
        "expected_authorized",
        "expected_recovered",
        "final_authorized",
        "recovered",
        "oracle_match",
        "false_recovery",
        "false_quarantine",
        "unsafe_release",
        "barrier_valid",
        "audit_valid",
        "attempts",
        "post_barrier_old_attempts",
        "post_barrier_old_commits",
        "successor_effects",
        "exactly_once",
        "latency_ns",
    )
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        databases = {
            provider_id: ProviderDatabase(root / f"{provider_id}.sqlite3")
            for provider_id in PROVIDER_IDS
        }
        processes = {
            provider_id: start_provider(
                provider_id=provider_id,
                signer=base_signers[provider_id],
                database=databases[provider_id],
                transition_signer=transition_signer,
            )
            for provider_id in PROVIDER_IDS
        }
        try:
            with output.open("w", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=fields,
                    lineterminator="\n",
                )
                writer.writeheader()
                for trial in range(trials):
                    scenario = SCENARIOS[(trial + seed) % len(SCENARIOS)]
                    target = rng.choice(PROVIDER_IDS)
                    for position, mechanism in enumerate(
                        mechanism_order(trial, seed)
                    ):
                        writer.writerow(
                            run_mechanism(
                                seed=seed,
                                trial=trial,
                                scenario=scenario,
                                mechanism=mechanism,
                                position=position,
                                target=target,
                                databases=databases,
                                processes=processes,
                                base_signers=base_signers,
                                transition_signer=transition_signer,
                                barrier_signer=barrier_signer,
                                audit_signer=audit_signer,
                                key_attestation_signer=(
                                    key_attestation_signer
                                ),
                                attacker=attacker,
                                trust=trust,
                            )
                        )
                        handle.flush()
        finally:
            for process in processes.values():
                process.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
