from __future__ import annotations

import csv
import dataclasses
import random
import sys
import tempfile
import time
from pathlib import Path

from ztai import (
    AuthorityTransition,
    DistributedAuthorityCoordinator,
    DurableAuthorityProvider,
    Ed25519Signer,
    EffectRequest,
    ProviderAuthorityAcknowledgement,
    ProviderDatabase,
    ProviderTransitionResult,
    RecoveryStatus,
    TrustStore,
)
from ztai.model import digest


PROVIDER_IDS = ("callback", "inventory", "notification", "payment")
STEP_BY_PROVIDER = {
    "payment": "charge",
    "inventory": "reserve",
    "notification": "notify",
    "callback": "callback",
}
SCENARIOS = (
    "clean",
    "delayed_propagation",
    "lost_ack_after_persist",
    "restart_before_update",
    "unavailable_provider",
    "conflicting_signed_ack",
    "stale_signed_ack",
    "forged_ack",
    "cross_provider_signer",
    "queued_old_callback",
    "mid_workflow_revocation",
)


class FailFirstProvider:
    def __init__(self, inner: DurableAuthorityProvider, *, persist_first: bool) -> None:
        self.provider_id = inner.provider_id
        self.inner = inner
        self.persist_first = persist_first
        self.failed = False

    def apply_transition(self, transition_envelope, *, now: int):
        if not self.failed:
            self.failed = True
            if self.persist_first:
                self.inner.apply_transition(transition_envelope, now=now)
            raise TimeoutError(self.provider_id)
        return self.inner.apply_transition(transition_envelope, now=now)


class UnavailableProvider:
    def __init__(self, provider_id: str) -> None:
        self.provider_id = provider_id

    def apply_transition(self, transition_envelope, *, now: int):
        raise TimeoutError(self.provider_id)


class MutatedAcknowledgementProvider:
    def __init__(
        self,
        inner: DurableAuthorityProvider,
        signer: Ed25519Signer,
        *,
        mutation: str,
        attacker: Ed25519Signer,
        alternate_signer: Ed25519Signer,
    ) -> None:
        self.provider_id = inner.provider_id
        self.inner = inner
        self.signer = signer
        self.mutation = mutation
        self.attacker = attacker
        self.alternate_signer = alternate_signer

    def apply_transition(self, transition_envelope, *, now: int):
        if self.mutation == "stale":
            transition = transition_envelope.payload
            acknowledgement = ProviderAuthorityAcknowledgement(
                self.provider_id,
                f"previous:{transition.transition_id}",
                transition.incident_id,
                transition.workload_id,
                transition.version - 1,
                transition.retired_epoch - 1,
                transition.retired_epoch,
                digest({"previous": transition.transition_id}),
                now,
            )
            return ProviderTransitionResult(
                True,
                "stale_ack",
                self.signer.sign("authority_transition_ack", acknowledgement),
            )

        result = self.inner.apply_transition(transition_envelope, now=now)
        if result.acknowledgement_envelope is None:
            return result
        acknowledgement = result.acknowledgement_envelope.payload
        if self.mutation == "conflict":
            acknowledgement = dataclasses.replace(
                acknowledgement,
                active_epoch=acknowledgement.active_epoch + 1,
            )
            signer = self.signer
        elif self.mutation == "forged":
            signer = self.attacker
        elif self.mutation == "cross_signer":
            signer = self.alternate_signer
        else:
            raise ValueError(self.mutation)
        return ProviderTransitionResult(
            True,
            f"{self.mutation}_ack",
            signer.sign("authority_transition_ack", acknowledgement),
        )


def effect_request(
    *,
    identity: str,
    provider_id: str,
    workload_id: str,
    incident_id: str,
    epoch: int,
) -> EffectRequest:
    step_id = STEP_BY_PROVIDER[provider_id]
    return EffectRequest(
        incident_id,
        step_id,
        workload_id,
        epoch,
        f"op:{step_id}:{identity}",
        f"effect:{identity}:{step_id}:epoch:{epoch}",
    )


def run_case(
    *,
    seed: int,
    trial: int,
    scenario: str,
    root: Path,
    rng: random.Random,
    trust: TrustStore,
    transition_signer: Ed25519Signer,
    barrier_signer: Ed25519Signer,
    provider_signers: dict[str, Ed25519Signer],
    attacker: Ed25519Signer,
) -> dict[str, object]:
    identity = f"{seed}:{trial}:{scenario}"
    incident_id = f"incident:{identity}"
    workload_id = f"agent:{identity}"
    old_epoch = trial * 2 + 1
    new_epoch = old_epoch + 1
    databases = {
        provider_id: ProviderDatabase(root / f"{identity.replace(':', '_')}:{provider_id}.sqlite3")
        for provider_id in PROVIDER_IDS
    }
    for database in databases.values():
        database.establish_epoch(workload_id, old_epoch, 900)

    precommitted: set[str] = set()
    if scenario == "mid_workflow_revocation":
        precommitted = set(rng.sample(list(PROVIDER_IDS), 2))
        for provider_id in precommitted:
            status, _ = databases[provider_id].apply_effect(
                effect_request(
                    identity=identity,
                    provider_id=provider_id,
                    workload_id=workload_id,
                    incident_id=incident_id,
                    epoch=old_epoch,
                )
            )
            if status != 200:
                raise AssertionError("pre-transition workflow effect did not commit")

    providers = {
        provider_id: DurableAuthorityProvider(
            provider_id,
            databases[provider_id],
            trust,
            provider_signers[provider_id],
        )
        for provider_id in PROVIDER_IDS
    }
    target = rng.choice(PROVIDER_IDS)
    if scenario == "restart_before_update":
        databases[target] = ProviderDatabase(databases[target].path)
        providers[target] = DurableAuthorityProvider(
            target, databases[target], trust, provider_signers[target]
        )
    elif scenario == "delayed_propagation":
        providers[target] = FailFirstProvider(providers[target], persist_first=False)
    elif scenario == "lost_ack_after_persist":
        providers[target] = FailFirstProvider(providers[target], persist_first=True)
    elif scenario == "unavailable_provider":
        providers[target] = UnavailableProvider(target)
    elif scenario in {
        "conflicting_signed_ack",
        "stale_signed_ack",
        "forged_ack",
        "cross_provider_signer",
    }:
        mutation = {
            "conflicting_signed_ack": "conflict",
            "stale_signed_ack": "stale",
            "forged_ack": "forged",
            "cross_provider_signer": "cross_signer",
        }[scenario]
        providers[target] = MutatedAcknowledgementProvider(
            providers[target],
            provider_signers[target],
            mutation=mutation,
            attacker=attacker,
            alternate_signer=provider_signers[
                next(provider_id for provider_id in PROVIDER_IDS if provider_id != target)
            ],
        )

    transition = AuthorityTransition(
        f"transition:{identity}",
        incident_id,
        workload_id,
        1,
        old_epoch,
        new_epoch,
        PROVIDER_IDS,
        1_000,
    )
    transition_envelope = transition_signer.sign("authority_transition", transition)
    coordinator = DistributedAuthorityCoordinator(
        trust_store=trust,
        providers=providers,
        barrier_signer=barrier_signer,
    )
    started = time.perf_counter_ns()
    first = coordinator.establish_barrier(transition_envelope, now=1_001)
    initial_quarantined = first.status is RecoveryStatus.QUARANTINED
    rounds = 1
    decision = first
    healed = scenario in {"delayed_propagation", "lost_ack_after_persist"}
    if healed:
        if scenario == "lost_ack_after_persist":
            providers[target] = DurableAuthorityProvider(
                target,
                ProviderDatabase(databases[target].path),
                trust,
                provider_signers[target],
            )
            coordinator = DistributedAuthorityCoordinator(
                trust_store=trust,
                providers=providers,
                barrier_signer=barrier_signer,
            )
        decision = coordinator.establish_barrier(transition_envelope, now=1_002)
        rounds = 2
    latency = time.perf_counter_ns() - started

    expected_authorized = scenario in {
        "clean",
        "delayed_propagation",
        "lost_ack_after_persist",
        "restart_before_update",
        "queued_old_callback",
        "mid_workflow_revocation",
    }
    authorized = decision.status is RecoveryStatus.AUTHORIZED
    barrier_valid = authorized and coordinator.verify_barrier(decision)
    old_attempts = 0
    old_commits_after_barrier = 0
    queued_old_rejected: bool | str = ""
    exactly_once: bool | str = ""
    successor_effects = 0

    if authorized:
        for provider_id in PROVIDER_IDS:
            old_attempts += 1
            status, _ = databases[provider_id].apply_effect(
                effect_request(
                    identity=f"late:{identity}",
                    provider_id=provider_id,
                    workload_id=workload_id,
                    incident_id=incident_id,
                    epoch=old_epoch,
                )
            )
            old_commits_after_barrier += status == 200
        if scenario == "queued_old_callback":
            status, body = databases["callback"].apply_effect(
                effect_request(
                    identity=identity,
                    provider_id="callback",
                    workload_id=workload_id,
                    incident_id=incident_id,
                    epoch=old_epoch,
                )
            )
            queued_old_rejected = status == 403 and body["reason"] == "inactive_epoch"

        for provider_id in PROVIDER_IDS:
            if provider_id in precommitted:
                continue
            status, _ = databases[provider_id].apply_effect(
                effect_request(
                    identity=identity,
                    provider_id=provider_id,
                    workload_id=workload_id,
                    incident_id=incident_id,
                    epoch=new_epoch,
                )
            )
            successor_effects += status == 200
        exactly_once = all(
            databases[provider_id].effect_count(
                incident_id, STEP_BY_PROVIDER[provider_id]
            )
            == 1
            for provider_id in PROVIDER_IDS
        )

    reopened = {
        provider_id: ProviderDatabase(database.path)
        for provider_id, database in databases.items()
    }
    durable_transition = all(
        (
            reopened[provider_id].authority_transition(workload_id) is not None
            and reopened[provider_id].epoch_state(workload_id, old_epoch) == "retired"
            and reopened[provider_id].active_epoch(workload_id) == new_epoch
        )
        for provider_id in PROVIDER_IDS
    ) if authorized else ""
    unresolved_old_providers = sum(
        database.active_epoch(workload_id) == old_epoch for database in reopened.values()
    )
    successor_without_barrier = not authorized and successor_effects > 0
    correct = (
        authorized == expected_authorized
        and (not authorized or barrier_valid)
        and (not authorized or old_commits_after_barrier == 0)
        and (not authorized or exactly_once is True)
        and not successor_without_barrier
        and (not healed or initial_quarantined)
    )
    if not correct:
        raise AssertionError(
            f"E009 invariant failed: {scenario=} {decision=} {barrier_valid=} "
            f"{old_commits_after_barrier=} {exactly_once=}"
        )
    return {
        "seed": seed,
        "trial": trial,
        "scenario": scenario,
        "fault_provider": target,
        "expected_authorized": expected_authorized,
        "initial_quarantined": initial_quarantined,
        "final_authorized": authorized,
        "correct": correct,
        "barrier_valid": barrier_valid,
        "propagation_rounds": rounds,
        "recovered_after_heal": healed and authorized,
        "old_effect_attempts_after_barrier": old_attempts,
        "old_effect_commits_after_barrier": old_commits_after_barrier,
        "successor_effects": successor_effects,
        "successor_without_barrier": successor_without_barrier,
        "exactly_once": exactly_once,
        "queued_old_rejected": queued_old_rejected,
        "durable_transition_after_reopen": durable_transition,
        "unresolved_old_providers": unresolved_old_providers,
        "reason": "|".join(decision.reasons),
        "latency_ns": latency,
    }


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: run_distributed_authority_faults.py SEED TRIALS OUTPUT_CSV",
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
    provider_signers = {
        provider_id: Ed25519Signer(provider_id) for provider_id in PROVIDER_IDS
    }
    trust = TrustStore()
    trust.register("authority_transition_authority", transition_signer)
    trust.register("authority_barrier_authority", barrier_signer)
    for signer in provider_signers.values():
        trust.register("effect_provider", signer)

    fields = (
        "seed",
        "trial",
        "scenario",
        "fault_provider",
        "expected_authorized",
        "initial_quarantined",
        "final_authorized",
        "correct",
        "barrier_valid",
        "propagation_rounds",
        "recovered_after_heal",
        "old_effect_attempts_after_barrier",
        "old_effect_commits_after_barrier",
        "successor_effects",
        "successor_without_barrier",
        "exactly_once",
        "queued_old_rejected",
        "durable_transition_after_reopen",
        "unresolved_old_providers",
        "reason",
        "latency_ns",
    )
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        with output.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            for trial in range(trials):
                scenario = SCENARIOS[(trial + seed) % len(SCENARIOS)]
                writer.writerow(
                    run_case(
                        seed=seed,
                        trial=trial,
                        scenario=scenario,
                        root=root,
                        rng=rng,
                        trust=trust,
                        transition_signer=transition_signer,
                        barrier_signer=barrier_signer,
                        provider_signers=provider_signers,
                        attacker=attacker,
                    )
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
