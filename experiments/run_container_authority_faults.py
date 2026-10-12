from __future__ import annotations

import base64
import csv
import random
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

from ztai import (
    AuthorityTransition,
    DistributedAuthorityCoordinator,
    Ed25519Signer,
    EffectRequest,
    NetworkAuthorityProvider,
    ProviderClient,
    ProviderTransitionResult,
    RecoveryStatus,
    SignedEnvelope,
    TrustStore,
)


PROVIDER_IDS = ("callback", "inventory", "notification", "payment")
SCENARIOS = (
    "clean",
    "container_restart_before_transition",
    "container_stop_timeout_start",
    "lost_ack_after_persist",
    "crash_before_persist_restart",
    "crash_after_persist_restart",
    "asymmetric_control_partition",
    "forged_transition_endpoint",
)
QUARANTINE_THEN_RECOVER = {
    "container_stop_timeout_start",
    "lost_ack_after_persist",
    "crash_before_persist_restart",
    "crash_after_persist_restart",
    "asymmetric_control_partition",
}
FAULT_BY_SCENARIO = {
    "lost_ack_after_persist": "drop_after_persist",
    "crash_before_persist_restart": "crash_before_persist",
    "crash_after_persist_restart": "crash_after_persist",
}


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("docker", *arguments),
        check=check,
        capture_output=True,
        text=True,
    )


@dataclass
class ContainerProvider:
    provider_id: str
    name: str
    base_url: str
    volume_name: str

    def refresh_base_url(self) -> None:
        result = docker("port", self.name, "8080/tcp", check=False)
        if result.returncode != 0 or not result.stdout.strip():
            return
        port_text = result.stdout.strip().rsplit(":", 1)[-1]
        self.base_url = f"http://127.0.0.1:{int(port_text)}"

    def restart(self) -> None:
        docker("restart", self.name)
        self.refresh_base_url()
        wait_healthy(self.base_url)

    def pause(self) -> None:
        docker("pause", self.name)

    def unpause(self) -> None:
        docker("unpause", self.name)
        wait_healthy(self.base_url)

    def stop(self) -> None:
        docker("stop", "-t", "1", self.name)

    def ensure_running(self) -> None:
        state = docker("inspect", "-f", "{{.State.Running}}", self.name).stdout.strip()
        if state != "true":
            docker("start", self.name)
            self.refresh_base_url()
        wait_healthy(self.base_url)


@dataclass(frozen=True)
class CachedAcknowledgementProvider:
    """Reuses a previously verified durable acknowledgement on a retry round."""

    provider_id: str
    acknowledgement: SignedEnvelope

    def apply_transition(
        self, transition_envelope: SignedEnvelope, *, now: int
    ) -> ProviderTransitionResult:
        del transition_envelope, now
        return ProviderTransitionResult(
            True, "cached_acknowledgement", self.acknowledgement, replayed=True
        )

def wait_healthy(base_url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=0.3) as response:
                if response.status == 200:
                    return
        except Exception as error:  # readiness polling intentionally accepts transport errors
            last_error = error
        time.sleep(0.05)
    raise TimeoutError(f"container provider did not become healthy: {base_url}") from last_error


def create_provider(
    *,
    provider_id: str,
    workload_id: str,
    old_epoch: int,
    changed_at: int,
    signer: Ed25519Signer,
    transition_signer: Ed25519Signer,
    barrier_signer: Ed25519Signer,
    image: str,
    run_id: str,
) -> ContainerProvider:
    name = f"ztai-e014-{run_id}-{provider_id}"
    volume_name = f"{name}-data"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        host_port = int(reservation.getsockname()[1])
    docker("volume", "create", "--label", f"ztai.e014.run={run_id}", volume_name)
    try:
        result = docker(
            "run",
            "-d",
            "--name",
            name,
            "--label",
            f"ztai.e014.run={run_id}",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=16m",
            "-v",
            f"{volume_name}:/data:rw",
            "-p",
            f"127.0.0.1:{host_port}:8080",
            image,
            "--database",
            "/data/provider.sqlite3",
            "--provider-id",
            provider_id,
            f"--private-key={encode(signer.private_key_bytes)}",
            "--transition-signer-id",
            transition_signer.signer_id,
            f"--transition-public-key={encode(transition_signer.public_key_bytes)}",
            "--barrier-signer-id",
            barrier_signer.signer_id,
            f"--barrier-public-key={encode(barrier_signer.public_key_bytes)}",
            "--initial-workload",
            workload_id,
            "--initial-epoch",
            str(old_epoch),
            "--initial-changed-at",
            str(changed_at),
        )
    except Exception:
        docker("volume", "rm", "-f", volume_name, check=False)
        raise
    if not result.stdout.strip():
        raise RuntimeError(f"docker did not return a container id for {provider_id}")
    base_url = f"http://127.0.0.1:{host_port}"
    wait_healthy(base_url)
    return ContainerProvider(provider_id, name, base_url, volume_name)


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


def provider_clients(
    providers: dict[str, ContainerProvider],
    *,
    target: str | None = None,
    fault: str = "none",
    partitioned: bool = False,
) -> dict[str, NetworkAuthorityProvider]:
    for provider in providers.values():
        provider.refresh_base_url()
    clients = {
        provider_id: NetworkAuthorityProvider(
            provider_id,
            provider.base_url,
            timeout=3.0,
        )
        for provider_id, provider in providers.items()
    }
    if target is not None and fault != "none":
        clients[target] = NetworkAuthorityProvider(
            target,
            providers[target].base_url,
            timeout=3.0,
            fault=fault,
        )
    if target is not None and partitioned:
        clients[target] = NetworkAuthorityProvider(target, "http://127.0.0.1:1", timeout=0.05)
    return clients


def execute_with_transport_retry(
    client: ProviderClient,
    request: EffectRequest,
    *,
    barrier_envelope: SignedEnvelope | None = None,
    attempts: int = 5,
) -> tuple[object, int]:
    retries = 0
    result = client.execute(request, barrier_envelope=barrier_envelope)
    while result.status == "ambiguous" and retries < attempts - 1:
        retries += 1
        time.sleep(0.1 * (2 ** (retries - 1)))
        result = client.execute(request, barrier_envelope=barrier_envelope)
    return result, retries


def run_case(
    *,
    seed: int,
    trial: int,
    scenario: str,
    rng: random.Random,
    providers: dict[str, ContainerProvider],
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
    issued_at = 20_000 + trial * 10
    target = rng.choice(PROVIDER_IDS)
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
    envelope = transition_signer.sign("authority_transition", transition)
    forged_endpoint_rejected: bool | str = ""
    pre_barrier_old_commit: bool | str = ""
    pre_barrier_successor_rejected: bool | str = ""
    rounds = 1
    started = time.perf_counter_ns()

    if scenario == "container_restart_before_transition":
        providers[target].restart()
    if scenario == "container_stop_timeout_start":
        providers[target].stop()
    if scenario == "forged_transition_endpoint":
        forged = attacker.sign("authority_transition", transition)
        direct = NetworkAuthorityProvider(target, providers[target].base_url, timeout=3.0)
        result = direct.apply_transition(forged, now=issued_at + 1)
        old_epoch_probe, _ = execute_with_transport_retry(
            ProviderClient(providers[target].base_url, timeout=3.0),
            effect_request(
                identity=identity,
                provider_id=target,
                workload_id=workload_id,
                incident_id=incident_id,
                epoch=old_epoch,
                phase="post-forgery-old-epoch",
            ),
        )
        forged_endpoint_rejected = (
            not result.accepted
            and result.reason == "invalid_transition_signature"
            and old_epoch_probe.status == "committed"
        )

    fault = FAULT_BY_SCENARIO.get(scenario, "none")
    clients = provider_clients(
        providers,
        target=target,
        fault=fault,
        partitioned=scenario == "asymmetric_control_partition",
    )
    coordinator = DistributedAuthorityCoordinator(
        trust_store=trust,
        providers=clients,
        barrier_signer=barrier_signer,
    )
    first = coordinator.establish_barrier(envelope, now=issued_at + 1)
    initial_quarantined = first.status is RecoveryStatus.QUARANTINED
    decision = first

    if initial_quarantined:
        probe_provider_id = (
            first.acknowledgement_envelopes[0].signer_id
            if first.acknowledgement_envelopes
            else target
        )
        successor_probe = ProviderClient(
            providers[probe_provider_id].base_url, timeout=3.0
        ).execute(
            effect_request(
                identity=identity,
                provider_id=probe_provider_id,
                workload_id=workload_id,
                incident_id=incident_id,
                epoch=new_epoch,
                phase="prebarrier-successor",
            )
        )
        pre_barrier_successor_rejected = (
            successor_probe.status == "rejected"
            and successor_probe.reason == "complete_barrier_required"
        )

    if scenario == "asymmetric_control_partition":
        old_result = ProviderClient(providers[target].base_url, timeout=3.0).execute(
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
        if scenario == "container_stop_timeout_start":
            providers[target].ensure_running()
        elif scenario in {"crash_before_persist_restart", "crash_after_persist_restart"}:
            providers[target].ensure_running()
        for provider in providers.values():
            provider.refresh_base_url()
            wait_healthy(provider.base_url)
        clients = provider_clients(providers)
        for acknowledgement in first.acknowledgement_envelopes:
            clients[acknowledgement.signer_id] = CachedAcknowledgementProvider(
                acknowledgement.signer_id, acknowledgement
            )
        coordinator = DistributedAuthorityCoordinator(
            trust_store=trust,
            providers=clients,
            barrier_signer=barrier_signer,
        )
        decision = coordinator.establish_barrier(envelope, now=issued_at + 2)

    latency = time.perf_counter_ns() - started
    authorized = decision.status is RecoveryStatus.AUTHORIZED
    barrier_valid = authorized and coordinator.verify_barrier(decision)
    old_attempts = 0
    old_commits = 0
    unresolved_effect_calls = 0
    transport_retries = 0
    successor_replays = 0
    successor_reconciled = 0
    if authorized:
        for provider in providers.values():
            provider.refresh_base_url()
        for provider_id, provider in providers.items():
            client = ProviderClient(provider.base_url, timeout=3.0)
            old_attempts += 1
            old, retries = execute_with_transport_retry(
                client,
                effect_request(
                    identity=identity,
                    provider_id=provider_id,
                    workload_id=workload_id,
                    incident_id=incident_id,
                    epoch=old_epoch,
                    phase="postbarrier-old",
                ),
            )
            transport_retries += retries
            old_commits += old.status == "committed"
            unresolved_effect_calls += old.status == "ambiguous"
            successor = effect_request(
                identity=identity,
                provider_id=provider_id,
                workload_id=workload_id,
                incident_id=incident_id,
                epoch=new_epoch,
                phase="successor",
            )
            committed, retries = execute_with_transport_retry(
                client,
                successor,
                barrier_envelope=decision.barrier_envelope,
            )
            transport_retries += retries
            unresolved_effect_calls += committed.status == "ambiguous"
            replay, retries = execute_with_transport_retry(
                client,
                successor,
                barrier_envelope=decision.barrier_envelope,
            )
            transport_retries += retries
            unresolved_effect_calls += replay.status == "ambiguous"
            outcome = client.reconcile(successor, create_fence=False)
            if committed.status != "committed":
                raise AssertionError(
                    "successor effect did not commit: "
                    f"{scenario=} {provider_id=} {committed.status=} "
                    f"{committed.reason=}"
                )
            successor_replays += replay.status == "committed" and replay.replayed
            successor_reconciled += outcome.status == "committed"

    exactly_once = (
        authorized
        and successor_replays == len(PROVIDER_IDS)
        and successor_reconciled == len(PROVIDER_IDS)
    )
    durable = (
        authorized
        and len(decision.acknowledgement_envelopes) == len(PROVIDER_IDS)
        and {item.signer_id for item in decision.acknowledgement_envelopes}
        == set(PROVIDER_IDS)
    )
    expected_quarantine = scenario in QUARANTINE_THEN_RECOVER
    correct = (
        initial_quarantined == expected_quarantine
        and authorized
        and barrier_valid
        and old_commits == 0
        and unresolved_effect_calls == 0
        and successor_replays == len(PROVIDER_IDS)
        and exactly_once
        and durable
        and (not initial_quarantined or pre_barrier_successor_rejected is True)
        and (scenario != "asymmetric_control_partition" or pre_barrier_old_commit is True)
        and (scenario != "forged_transition_endpoint" or forged_endpoint_rejected is True)
    )
    if not correct:
        raise AssertionError(
            f"E014 invariant failed: {scenario=} {first=} {decision=} "
            f"{old_commits=} {successor_replays=} {successor_reconciled=} "
            f"{exactly_once=} {barrier_valid=} {durable=} "
            f"{unresolved_effect_calls=} {transport_retries=} "
            f"{pre_barrier_successor_rejected=} {pre_barrier_old_commit=} "
            f"{forged_endpoint_rejected=}"
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
        "pre_barrier_successor_rejected": pre_barrier_successor_rejected,
        "post_barrier_old_attempts": old_attempts,
        "post_barrier_old_commits": old_commits,
        "unresolved_effect_calls": unresolved_effect_calls,
        "transport_retries": transport_retries,
        "successor_replays": successor_replays,
        "successor_reconciled": successor_reconciled,
        "exactly_once": exactly_once,
        "complete_durable_acknowledgement_set": durable,
        "latency_ns": latency,
    }


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: run_container_authority_faults.py SEED TRIALS OUTPUT_CSV IMAGE",
            file=sys.stderr,
        )
        return 2
    seed = int(sys.argv[1])
    trials = int(sys.argv[2])
    output = Path(sys.argv[3])
    image = sys.argv[4]
    output.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    transition_signer = Ed25519Signer("authority-control")
    barrier_signer = Ed25519Signer("barrier-control")
    attacker = Ed25519Signer("attacker")
    signers = {provider_id: Ed25519Signer(provider_id) for provider_id in PROVIDER_IDS}
    trust = TrustStore()
    trust.register("authority_transition_authority", transition_signer)
    trust.register("authority_barrier_authority", barrier_signer)
    for signer in signers.values():
        trust.register("effect_provider", signer)

    fields = (
        "seed", "trial", "scenario", "fault_provider",
        "expected_initial_quarantine", "initial_quarantined", "final_authorized",
        "correct", "barrier_valid", "rounds", "recovered_after_retry",
        "forged_endpoint_rejected", "pre_barrier_old_commit",
        "pre_barrier_successor_rejected",
        "post_barrier_old_attempts", "post_barrier_old_commits",
        "unresolved_effect_calls", "transport_retries", "successor_replays",
        "successor_reconciled",
        "exactly_once", "complete_durable_acknowledgement_set", "latency_ns",
    )
    run_id = uuid.uuid4().hex[:8]
    with tempfile.TemporaryDirectory(prefix="ztai-e014-") as temporary_directory:
        root = Path(temporary_directory)
        with output.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            for trial in range(trials):
                providers: dict[str, ContainerProvider] = {}
                trial_root = root / f"trial-{trial:06d}"
                trial_root.mkdir()
                scenario = SCENARIOS[(trial + seed) % len(SCENARIOS)]
                workload_id = f"agent:{seed}:{trial}:{scenario}"
                old_epoch = trial * 2 + 1
                issued_at = 20_000 + trial * 10
                try:
                    for provider_id in PROVIDER_IDS:
                        providers[provider_id] = create_provider(
                            provider_id=provider_id,
                            workload_id=workload_id,
                            old_epoch=old_epoch,
                            changed_at=issued_at - 1,
                            signer=signers[provider_id],
                            transition_signer=transition_signer,
                            barrier_signer=barrier_signer,
                            image=image,
                            run_id=f"{run_id}-{trial}",
                        )
                    writer.writerow(
                        run_case(
                            seed=seed,
                            trial=trial,
                            scenario=scenario,
                            rng=rng,
                            providers=providers,
                            transition_signer=transition_signer,
                            barrier_signer=barrier_signer,
                            trust=trust,
                            attacker=attacker,
                        )
                    )
                    handle.flush()
                finally:
                    for provider in providers.values():
                        docker("rm", "-f", provider.name, check=False)
                        docker("volume", "rm", "-f", provider.volume_name, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
