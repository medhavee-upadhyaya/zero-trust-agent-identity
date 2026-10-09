from __future__ import annotations

import csv
import random
import sys
import tempfile
import time
from pathlib import Path

from ztai import (
    AuthorityTransition,
    DistributedAuthorityCoordinator,
    Ed25519Signer,
    EffectRequest,
    NetworkAuthorityProvider,
    ProviderClient,
    ProviderDatabase,
    ProviderProcess,
    RecoveryStatus,
    TrustStore,
)


PROVIDER_IDS = ("callback", "inventory", "notification", "payment")
SCENARIOS = (
    "clean",
    "restart_before_transition",
    "delayed_transition_retry",
    "lost_ack_after_persist",
    "crash_before_persist_restart",
    "crash_after_persist_restart",
    "asymmetric_control_partition",
    "trusted_key_rotation",
    "untrusted_key_rotation",
    "stale_key_after_rotation",
    "forged_transition_endpoint",
)
QUARANTINE_THEN_RECOVER = {
    "delayed_transition_retry",
    "lost_ack_after_persist",
    "crash_before_persist_restart",
    "crash_after_persist_restart",
    "asymmetric_control_partition",
    "untrusted_key_rotation",
    "stale_key_after_rotation",
}
FAULT_BY_SCENARIO = {
    "delayed_transition_retry": "drop_before_persist",
    "lost_ack_after_persist": "drop_after_persist",
    "crash_before_persist_restart": "crash_before_persist",
    "crash_after_persist_restart": "crash_after_persist",
}


def start_provider(
    *,
    provider_id: str,
    signer: Ed25519Signer,
    database: ProviderDatabase,
    transition_signer: Ed25519Signer,
) -> ProviderProcess:
    return ProviderProcess(
        database.path,
        signer,
        enable_faults=True,
        authority_transition_keys={
            transition_signer.signer_id: transition_signer.public_key_bytes
        },
    ).start()


def replace_provider(
    *,
    provider_id: str,
    signer: Ed25519Signer,
    databases: dict[str, ProviderDatabase],
    processes: dict[str, ProviderProcess],
    transition_signer: Ed25519Signer,
) -> None:
    processes[provider_id].stop()
    processes[provider_id] = start_provider(
        provider_id=provider_id,
        signer=signer,
        database=databases[provider_id],
        transition_signer=transition_signer,
    )


def network_providers(
    processes: dict[str, ProviderProcess],
    *,
    target: str | None = None,
    fault: str = "none",
    partitioned: bool = False,
) -> dict[str, NetworkAuthorityProvider]:
    providers = {
        provider_id: NetworkAuthorityProvider(
            provider_id,
            process.base_url,
            timeout=0.25,
        )
        for provider_id, process in processes.items()
    }
    if target is not None and fault != "none":
        providers[target] = NetworkAuthorityProvider(
            target,
            processes[target].base_url,
            timeout=0.25,
            fault=fault,
        )
    if target is not None and partitioned:
        providers[target] = NetworkAuthorityProvider(
            target,
            "http://127.0.0.1:1",
            timeout=0.05,
        )
    return providers


def effect_request(
    *,
    identity: str,
    provider_id: str,
    workload_id: str,
    incident_id: str,
    epoch: int,
    phase: str,
) -> EffectRequest:
    return EffectRequest(
        incident_id,
        f"{phase}:{provider_id}",
        workload_id,
        epoch,
        f"op:{phase}:{identity}:{provider_id}",
        f"effect:{phase}:{identity}:{provider_id}:epoch:{epoch}",
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
    trust: TrustStore,
    attacker: Ed25519Signer,
) -> dict[str, object]:
    identity = f"{seed}:{trial}:{scenario}"
    incident_id = f"incident:{identity}"
    workload_id = f"agent:{identity}"
    old_epoch = trial * 2 + 1
    new_epoch = old_epoch + 1
    issued_at = 10_000 + trial * 10
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
    rotated_signer: Ed25519Signer | None = None
    forged_endpoint_rejected: bool | str = ""
    pre_barrier_old_commit: bool | str = ""
    rounds = 1
    started = time.perf_counter_ns()

    try:
        if scenario == "restart_before_transition":
            replace_provider(
                provider_id=target,
                signer=base_signers[target],
                databases=databases,
                processes=processes,
                transition_signer=transition_signer,
            )
        elif scenario in {"trusted_key_rotation", "untrusted_key_rotation"}:
            rotated_signer = Ed25519Signer(target)
            replace_provider(
                provider_id=target,
                signer=rotated_signer,
                databases=databases,
                processes=processes,
                transition_signer=transition_signer,
            )
            if scenario == "trusted_key_rotation":
                trust.register("effect_provider", rotated_signer)
        elif scenario == "stale_key_after_rotation":
            rotated_signer = Ed25519Signer(target)
            trust.register("effect_provider", rotated_signer)

        if scenario == "forged_transition_endpoint":
            forged_envelope = attacker.sign(
                "authority_transition", transition
            )
            direct = NetworkAuthorityProvider(
                target,
                processes[target].base_url,
                timeout=0.25,
            ).apply_transition(forged_envelope, now=issued_at + 1)
            forged_endpoint_rejected = (
                not direct.accepted
                and direct.reason == "invalid_transition_signature"
                and databases[target].active_epoch(workload_id) == old_epoch
            )

        fault = FAULT_BY_SCENARIO.get(scenario, "none")
        providers = network_providers(
            processes,
            target=target,
            fault=fault,
            partitioned=scenario == "asymmetric_control_partition",
        )
        coordinator = DistributedAuthorityCoordinator(
            trust_store=trust,
            providers=providers,
            barrier_signer=barrier_signer,
        )
        first = coordinator.establish_barrier(
            transition_envelope,
            now=issued_at + 1,
        )
        initial_quarantined = first.status is RecoveryStatus.QUARANTINED
        decision = first

        if scenario == "asymmetric_control_partition":
            old_result = ProviderClient(
                processes[target].base_url,
                timeout=0.25,
            ).execute(
                effect_request(
                    identity=identity,
                    provider_id=target,
                    workload_id=workload_id,
                    incident_id=incident_id,
                    epoch=old_epoch,
                    phase="prebarrier-old",
                )
            )
            pre_barrier_old_commit = old_result.status == "committed"

        if scenario in QUARANTINE_THEN_RECOVER:
            rounds = 2
            if scenario in {
                "crash_before_persist_restart",
                "crash_after_persist_restart",
            }:
                replace_provider(
                    provider_id=target,
                    signer=base_signers[target],
                    databases=databases,
                    processes=processes,
                    transition_signer=transition_signer,
                )
            elif scenario == "untrusted_key_rotation":
                assert rotated_signer is not None
                trust.register("effect_provider", rotated_signer)
            elif scenario == "stale_key_after_rotation":
                assert rotated_signer is not None
                replace_provider(
                    provider_id=target,
                    signer=rotated_signer,
                    databases=databases,
                    processes=processes,
                    transition_signer=transition_signer,
                )
            providers = network_providers(processes)
            coordinator = DistributedAuthorityCoordinator(
                trust_store=trust,
                providers=providers,
                barrier_signer=barrier_signer,
            )
            decision = coordinator.establish_barrier(
                transition_envelope,
                now=issued_at + 2,
            )

        latency = time.perf_counter_ns() - started
        authorized = decision.status is RecoveryStatus.AUTHORIZED
        barrier_valid = authorized and coordinator.verify_barrier(decision)
        old_attempts = 0
        old_commits = 0
        successor_replays = 0
        if authorized:
            for provider_id in PROVIDER_IDS:
                client = ProviderClient(
                    processes[provider_id].base_url,
                    timeout=0.25,
                )
                old_attempts += 1
                old_result = client.execute(
                    effect_request(
                        identity=identity,
                        provider_id=provider_id,
                        workload_id=workload_id,
                        incident_id=incident_id,
                        epoch=old_epoch,
                        phase="postbarrier-old",
                    )
                )
                old_commits += old_result.status == "committed"
                successor = effect_request(
                    identity=identity,
                    provider_id=provider_id,
                    workload_id=workload_id,
                    incident_id=incident_id,
                    epoch=new_epoch,
                    phase="successor",
                )
                first_effect = client.execute(successor)
                replay = client.execute(successor)
                if first_effect.status != "committed":
                    raise AssertionError("successor effect did not commit")
                successor_replays += replay.status == "committed" and replay.replayed

        exactly_once = authorized and all(
            databases[provider_id].effect_count(
                incident_id,
                f"successor:{provider_id}",
            )
            == 1
            for provider_id in PROVIDER_IDS
        )
        durable_transition = authorized and all(
            (
                ProviderDatabase(database.path).active_epoch(workload_id)
                == new_epoch
                and ProviderDatabase(database.path).epoch_state(
                    workload_id, old_epoch
                )
                == "retired"
            )
            for database in databases.values()
        )
        expected_quarantine = scenario in QUARANTINE_THEN_RECOVER
        correct = (
            initial_quarantined == expected_quarantine
            and authorized
            and barrier_valid
            and old_commits == 0
            and successor_replays == len(PROVIDER_IDS)
            and exactly_once
            and durable_transition
            and (
                scenario != "asymmetric_control_partition"
                or pre_barrier_old_commit is True
            )
            and (
                scenario != "forged_transition_endpoint"
                or forged_endpoint_rejected is True
            )
        )
        if not correct:
            raise AssertionError(
                f"E011 invariant failed: {scenario=} {first=} {decision=} "
                f"{old_commits=} {successor_replays=} {exactly_once=}"
            )
        return {
            "seed": seed,
            "trial": trial,
            "scenario": scenario,
            "fault_provider": target,
            "expected_initial_quarantine": expected_quarantine,
            "initial_quarantined": initial_quarantined,
            "final_authorized": authorized,
            "correct": correct,
            "barrier_valid": barrier_valid,
            "rounds": rounds,
            "recovered_after_retry": expected_quarantine and authorized,
            "forged_endpoint_rejected": forged_endpoint_rejected,
            "pre_barrier_old_commit": pre_barrier_old_commit,
            "post_barrier_old_attempts": old_attempts,
            "post_barrier_old_commits": old_commits,
            "successor_replays": successor_replays,
            "exactly_once": exactly_once,
            "durable_transition_after_reopen": durable_transition,
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
            "usage: run_networked_authority_faults.py SEED TRIALS OUTPUT_CSV",
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
    attacker = Ed25519Signer("attacker")
    base_signers = {
        provider_id: Ed25519Signer(provider_id) for provider_id in PROVIDER_IDS
    }
    trust = TrustStore()
    trust.register("authority_transition_authority", transition_signer)
    trust.register("authority_barrier_authority", barrier_signer)
    for signer in base_signers.values():
        trust.register("effect_provider", signer)

    fields = (
        "seed",
        "trial",
        "scenario",
        "fault_provider",
        "expected_initial_quarantine",
        "initial_quarantined",
        "final_authorized",
        "correct",
        "barrier_valid",
        "rounds",
        "recovered_after_retry",
        "forged_endpoint_rejected",
        "pre_barrier_old_commit",
        "post_barrier_old_attempts",
        "post_barrier_old_commits",
        "successor_replays",
        "exactly_once",
        "durable_transition_after_reopen",
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
                            trust=trust,
                            attacker=attacker,
                        )
                    )
                    handle.flush()
        finally:
            for process in processes.values():
                process.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
