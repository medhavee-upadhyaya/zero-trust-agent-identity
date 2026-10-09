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
from ztai import (
    AuthorityTransition,
    Ed25519Signer,
    NetworkAuthorityProvider,
    ProviderClient,
    ProviderDatabase,
    ProviderProcess,
    ProviderTransitionResult,
    RecoveryStatus,
    SelfHealingAuthorityController,
    TrustStore,
    make_provider_key_rotation_attestation,
)


SCENARIOS = (
    "clean",
    "delayed_transition",
    "lost_ack_after_persist",
    "crash_before_persist",
    "crash_after_persist",
    "temporary_partition",
    "attested_key_rotation",
    "permanent_partition",
    "missing_rotation_attestation",
    "forged_rotation_attestation",
    "expired_rotation_attestation",
    "wrong_transition_attestation",
    "wrong_provider_attestation",
    "conflicting_signed_ack",
)
RECOVERABLE = {
    "delayed_transition",
    "lost_ack_after_persist",
    "crash_before_persist",
    "crash_after_persist",
    "temporary_partition",
    "attested_key_rotation",
}
EXPECTED_AUTHORIZED = RECOVERABLE | {"clean"}
ROTATION_SCENARIOS = {
    "attested_key_rotation",
    "missing_rotation_attestation",
    "forged_rotation_attestation",
    "expired_rotation_attestation",
    "wrong_transition_attestation",
    "wrong_provider_attestation",
}


class ConflictingNetworkProvider:
    def __init__(
        self,
        inner: NetworkAuthorityProvider,
        signer: Ed25519Signer,
    ) -> None:
        self.provider_id = inner.provider_id
        self.inner = inner
        self.signer = signer

    def apply_transition(self, transition_envelope, *, now: int):
        result = self.inner.apply_transition(transition_envelope, now=now)
        if result.acknowledgement_envelope is None:
            return result
        acknowledgement = dataclasses.replace(
            result.acknowledgement_envelope.payload,
            active_epoch=result.acknowledgement_envelope.payload.active_epoch + 1,
        )
        return ProviderTransitionResult(
            True,
            "conflicting_ack",
            self.signer.sign("authority_transition_ack", acknowledgement),
        )


def run_case(
    *,
    seed: int,
    trial: int,
    scenario: str,
    rng: random.Random,
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
    identity = f"{seed}:{trial}:{scenario}"
    incident_id = f"incident:{identity}"
    workload_id = f"agent:{identity}"
    old_epoch = trial * 2 + 1
    new_epoch = old_epoch + 1
    issued_at = 20_000 + trial * 10
    target = rng.choice(PROVIDER_IDS)
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
    rotated_signer: Ed25519Signer | None = None

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
                expired = dataclasses.replace(
                    valid_attestation.payload,
                    expires_at=issued_at,
                )
                rotation_attestations[target] = key_attestation_signer.sign(
                    "provider_key_rotation_attestation", expired
                )
            elif scenario == "wrong_transition_attestation":
                wrong = dataclasses.replace(
                    valid_attestation.payload,
                    transition_id=f"other:{identity}",
                )
                rotation_attestations[target] = key_attestation_signer.sign(
                    "provider_key_rotation_attestation", wrong
                )
            elif scenario == "wrong_provider_attestation":
                wrong = dataclasses.replace(
                    valid_attestation.payload,
                    provider_id=next(
                        item for item in PROVIDER_IDS if item != target
                    ),
                )
                rotation_attestations[target] = key_attestation_signer.sign(
                    "provider_key_rotation_attestation", wrong
                )
        elif scenario == "conflicting_signed_ack":
            providers[target] = ConflictingNetworkProvider(
                providers[target],
                base_signers[target],
            )

        permanent_provider = providers.get(target)

        def repair_provider(provider_id: str, action: str):
            if scenario == "permanent_partition":
                return permanent_provider
            if scenario in {"crash_before_persist", "crash_after_persist"}:
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

        controller = SelfHealingAuthorityController(
            trust_store=trust,
            providers=providers,
            barrier_signer=barrier_signer,
            audit_signer=audit_signer,
            repair_provider=repair_provider,
            max_attempts=3,
        )
        started = time.perf_counter_ns()
        result = controller.recover(
            transition_envelope,
            now=issued_at + 1,
            rotation_attestations=rotation_attestations,
        )
        latency = time.perf_counter_ns() - started
        authorized = result.decision.status is RecoveryStatus.AUTHORIZED
        barrier_valid = authorized and controller.verify_barrier(result.decision)
        audit_valid = controller.verify_result(result, transition_envelope)
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
                        phase="posthealing-old",
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
                        phase="healed-successor",
                    )
                )
                successor_effects += successor.status == "committed"
            exactly_once = all(
                databases[provider_id].effect_count(
                    incident_id,
                    f"healed-successor:{provider_id}",
                )
                == 1
                for provider_id in PROVIDER_IDS
            )

        expected_authorized = scenario in EXPECTED_AUTHORIZED
        expected_recovered = scenario in RECOVERABLE
        false_recovery = not expected_authorized and authorized
        false_quarantine = expected_authorized and not authorized
        unsafe_release = (
            (authorized and not barrier_valid)
            or (not authorized and successor_effects > 0)
            or old_commits > 0
        )
        correct = (
            authorized == expected_authorized
            and result.recovered == expected_recovered
            and not false_recovery
            and not false_quarantine
            and not unsafe_release
            and audit_valid
            and (not authorized or exactly_once is True)
        )
        if not correct:
            raise AssertionError(
                f"E012 invariant failed: {scenario=} {result=} "
                f"{barrier_valid=} {audit_valid=} {old_commits=}"
            )
        actions = tuple(event.action for event in result.repair_events)
        return {
            "seed": seed,
            "trial": trial,
            "scenario": scenario,
            "fault_provider": target,
            "expected_authorized": expected_authorized,
            "expected_recovered": expected_recovered,
            "final_authorized": authorized,
            "recovered": result.recovered,
            "correct": correct,
            "false_recovery": false_recovery,
            "false_quarantine": false_quarantine,
            "unsafe_release": unsafe_release,
            "barrier_valid": barrier_valid,
            "audit_valid": audit_valid,
            "attempts": result.attempts,
            "repair_events": len(result.repair_events),
            "transport_repairs": actions.count("retry_or_restart_transport"),
            "accepted_key_rotations": actions.count(
                "accept_attested_key_rotation"
            ),
            "rejected_key_rotations": actions.count(
                "reject_unattested_key_rotation"
            ),
            "post_healing_old_attempts": old_attempts,
            "post_healing_old_commits": old_commits,
            "successor_effects": successor_effects,
            "exactly_once": exactly_once,
            "latency_ns": latency,
        }
    finally:
        trust.register("effect_provider", base_signers[target])
        current = processes[target].signer.public_key_fingerprint
        if current != base_signers[target].public_key_fingerprint:
            replace_provider(
                provider_id=target,
                signer=base_signers[target],
                databases=databases,
                processes=processes,
                transition_signer=transition_signer,
            )


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: run_self_healing_faults.py SEED TRIALS OUTPUT_CSV",
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
        "scenario",
        "fault_provider",
        "expected_authorized",
        "expected_recovered",
        "final_authorized",
        "recovered",
        "correct",
        "false_recovery",
        "false_quarantine",
        "unsafe_release",
        "barrier_valid",
        "audit_valid",
        "attempts",
        "repair_events",
        "transport_repairs",
        "accepted_key_rotations",
        "rejected_key_rotations",
        "post_healing_old_attempts",
        "post_healing_old_commits",
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
                    writer.writerow(
                        run_case(
                            seed=seed,
                            trial=trial,
                            scenario=scenario,
                            rng=rng,
                            databases=databases,
                            processes=processes,
                            base_signers=base_signers,
                            transition_signer=transition_signer,
                            barrier_signer=barrier_signer,
                            audit_signer=audit_signer,
                            key_attestation_signer=key_attestation_signer,
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
