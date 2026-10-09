from __future__ import annotations

import csv
import dataclasses
import sys
import tempfile
import time
from pathlib import Path

from ztai import (
    AuthorizedEffectRequest,
    ConsentRegistry,
    DistributedAuthorityCoordinator,
    DurableAuthorityProvider,
    Ed25519Signer,
    EffectRequest,
    ExecutionResult,
    PrincipalBoundAuthorizer,
    PrincipalBoundWorkflowExecutor,
    PrincipalConsent,
    ProviderAuthorizationEnforcer,
    ProviderBinding,
    ProviderClient,
    ProviderDatabase,
    ProviderProcess,
    RecoveryStatus,
    Scope,
    Step,
    StepAuthorization,
    TrustStore,
    WorkflowRecoveryEngine,
    WorkflowStepSpec,
    WorkflowStore,
    make_execution_proof,
)
from ztai.crypto import SignedEnvelope
from ztai.model import RecoveryCertificate, digest
from ztai.recovery import RecoveryDecision


PROVIDER_IDS = ("payment", "inventory", "notification", "callback")
STEP_DEFINITIONS = (
    ("charge", "payment", False, 75),
    ("reserve", "inventory", False, 0),
    ("notify", "notification", True, 0),
    ("callback", "callback", False, 0),
)
SCENARIOS = (
    "valid",
    "retired_epoch_replay",
    "tampered_action",
    "cross_task_replay",
    "stolen_permit_without_instance_key",
    "revoked_consent",
    "permit_identity_substitution",
    "swapped_recovery_certificate",
)
FAULTS = ("crash_before_commit", "crash_after_commit")


def bindings(
    databases: dict[str, ProviderDatabase],
    processes: dict[str, ProviderProcess],
) -> dict[str, ProviderBinding]:
    return {
        provider_id: ProviderBinding(
            provider_id,
            databases[provider_id],
            ProviderClient(processes[provider_id].base_url, timeout=0.25),
        )
        for provider_id in PROVIDER_IDS
    }


class AdversarialSuccessorExecutor(PrincipalBoundWorkflowExecutor):
    def __init__(
        self,
        *,
        scenario: str,
        consent_registry: ConsentRegistry,
        attacker_signer: Ed25519Signer,
        permit_signer: Ed25519Signer,
        recovery_signer: Ed25519Signer,
        provider_clients: dict[str, ProviderClient],
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self.scenario = scenario
        self.consent_registry = consent_registry
        self.attacker_signer = attacker_signer
        self.permit_signer = permit_signer
        self.recovery_signer = recovery_signer
        self.provider_clients = provider_clients
        self.attack_attempted = False
        self.attack_result: ExecutionResult | None = None

    def _mutated_request(
        self,
        request: AuthorizedEffectRequest,
        *,
        now: int,
    ) -> AuthorizedEffectRequest:
        if self.scenario == "tampered_action":
            intent = dataclasses.replace(request.intent, action="delete")
            return dataclasses.replace(
                request,
                intent=intent,
                proof_envelope=make_execution_proof(
                    self.instance_signer, request.permit_envelope, intent, now=now
                ),
            )
        if self.scenario == "cross_task_replay":
            intent = dataclasses.replace(
                request.intent, task_id=f"{request.intent.task_id}:other"
            )
            return dataclasses.replace(
                request,
                intent=intent,
                proof_envelope=make_execution_proof(
                    self.instance_signer, request.permit_envelope, intent, now=now
                ),
            )
        if self.scenario == "stolen_permit_without_instance_key":
            return dataclasses.replace(
                request,
                proof_envelope=make_execution_proof(
                    self.attacker_signer,
                    request.permit_envelope,
                    request.intent,
                    now=now,
                ),
            )
        if self.scenario == "permit_identity_substitution":
            task_id = f"{request.intent.task_id}:substituted"
            permit = dataclasses.replace(
                request.permit_envelope.payload,
                task_id=task_id,
            )
            permit_envelope = self.permit_signer.sign("action_permit", permit)
            intent = dataclasses.replace(request.intent, task_id=task_id)
            return dataclasses.replace(
                request,
                permit_envelope=permit_envelope,
                intent=intent,
                proof_envelope=make_execution_proof(
                    self.instance_signer, permit_envelope, intent, now=now
                ),
            )
        if self.scenario == "swapped_recovery_certificate":
            recovery = request.recovery_envelope.payload
            if not isinstance(recovery, RecoveryCertificate):
                raise TypeError("expected recovery certificate")
            alternate = dataclasses.replace(
                recovery,
                grant=dataclasses.replace(
                    recovery.grant,
                    grant_id=f"{recovery.grant.grant_id}:other",
                ),
            )
            alternate = dataclasses.replace(
                alternate,
                lineage_digest=digest(
                    {
                        "incident": alternate.grant.incident_digest,
                        "closure": alternate.grant.closure_digest,
                        "attestation": alternate.grant.attestation_digest,
                        "grant": digest(alternate.grant),
                        "reconciliation": alternate.reconciliation_digest,
                        "instructions": alternate.instructions,
                    }
                ),
            )
            return dataclasses.replace(
                request,
                recovery_envelope=self.recovery_signer.sign(
                    "recovery_certificate", alternate
                ),
            )
        return request

    def execute(
        self,
        *,
        step: Step,
        request: EffectRequest,
        decision: RecoveryDecision,
        attestation_envelope: SignedEnvelope,
        authority_barrier_envelope: SignedEnvelope,
        now: int,
    ) -> ExecutionResult:
        authorized = self.build_request(
            step=step,
            request=request,
            decision=decision,
            attestation_envelope=attestation_envelope,
            authority_barrier_envelope=authority_barrier_envelope,
            now=now,
        )
        if authorized is None:
            return ExecutionResult("rejected", 403, False, "authorization_issuance_failed")
        self.requests.append(authorized)
        enforcer = self.provider_enforcers[step.provider_id]

        if not self.attack_attempted and self.scenario != "valid":
            self.attack_attempted = True
            if self.scenario == "revoked_consent":
                consent = self.consent_envelope.payload
                if not isinstance(consent, PrincipalConsent):
                    raise TypeError("expected principal consent")
                self.consent_registry.revoke(consent.consent_id)
                self.attack_result = enforcer.execute(authorized, now=now)
                return self.attack_result
            if self.scenario == "retired_epoch_replay":
                old = dataclasses.replace(
                    request,
                    epoch=request.epoch - 1,
                    idempotency_key=f"attack:{request.idempotency_key}:retired",
                )
                self.attack_result = self.provider_clients[step.provider_id].execute(old)
            else:
                attack = self._mutated_request(authorized, now=now)
                self.attack_result = enforcer.execute(attack, now=now)

        return enforcer.execute(authorized, now=now)


def run_case(
    *,
    seed: int,
    trial: int,
    store: WorkflowStore,
    databases: dict[str, ProviderDatabase],
    processes: dict[str, ProviderProcess],
    trust: TrustStore,
    signers: dict[str, Ed25519Signer],
    provider_signers: dict[str, Ed25519Signer],
) -> dict[str, object]:
    scenario = SCENARIOS[trial % len(SCENARIOS)]
    cell = (trial // len(SCENARIOS)) % 6
    crash_position = cell % 3
    fault = FAULTS[cell // 3]
    delayed_duplicates = (trial // (len(SCENARIOS) * 6)) % 2 == 1
    controller_restart = trial % 3 == 0
    workflow_id = f"secure:{seed}:{trial}"
    incident_id = f"incident:{seed}:{trial}"
    workload_id = f"agent:{seed}:{trial}"
    resource = f"order:{seed}:{trial}"
    old_epoch = trial * 2 + 1
    new_epoch = old_epoch + 1
    steps = tuple(
        WorkflowStepSpec(
            position,
            step_id,
            provider_id,
            f"op:{workflow_id}:{step_id}",
            idempotent,
        )
        for position, (step_id, provider_id, idempotent, _) in enumerate(
            STEP_DEFINITIONS
        )
    )
    store.create_workflow(
        workflow_id=workflow_id,
        incident_id=incident_id,
        workload_id=workload_id,
        old_epoch=old_epoch,
        new_epoch=new_epoch,
        steps=steps,
        now=10_000 + trial,
    )
    for database in databases.values():
        database.establish_epoch(workload_id, old_epoch, 9_000 + trial)

    initial = WorkflowRecoveryEngine(
        store=store,
        providers=bindings(databases, processes),
        trust_store=trust,
        incident_signer=signers["incident"],
        closure_signer=signers["closure"],
        attestation_signer=signers["attestation"],
        recovery_signer=signers["recovery"],
    )
    for step in steps[:crash_position]:
        result = initial.providers[step.provider_id].client.execute(
            initial.old_request(workflow_id, step.step_id)
        )
        if result.status != "committed":
            raise AssertionError("prefix execution failed")
        store.set_step_state(workflow_id, step.step_id, "committed")

    crash_step = steps[crash_position]
    crash_request = initial.old_request(workflow_id, crash_step.step_id)
    crash_message = f"{workflow_id}:crash"
    store.enqueue(
        message_id=crash_message,
        workflow_id=workflow_id,
        provider_id=crash_step.provider_id,
        request=crash_request,
        available_at=10_000 + trial,
    )
    attempt = store.deliver(
        crash_message,
        initial.providers[crash_step.provider_id].client,
        now=10_000 + trial,
        fault=fault,
    )
    if attempt.queue_status != "ambiguous":
        raise AssertionError("fault did not create ambiguity")
    processes[crash_step.provider_id].restart()

    for step in steps[crash_position + 1 :]:
        request = initial.old_request(workflow_id, step.step_id)
        copies = 2 if delayed_duplicates else 1
        for copy in range(copies):
            store.enqueue(
                message_id=f"{workflow_id}:{step.step_id}:{copy}",
                workflow_id=workflow_id,
                provider_id=step.provider_id,
                request=request,
                available_at=99_999,
            )
    if controller_restart:
        store.restart_controller(workflow_id, 10_050 + trial)

    consent_registry = ConsentRegistry()
    consent_scope = Scope.of(
        {definition[0] for definition in STEP_DEFINITIONS}, {resource}, 100
    )
    consent = PrincipalConsent(
        f"consent:{workflow_id}",
        signers["principal"].signer_id,
        f"task:{workflow_id}",
        workload_id,
        consent_scope,
        9_900 + trial,
        20_000 + trial,
        f"principal-nonce:{workflow_id}",
    )
    enforcers = {
        provider_id: ProviderAuthorizationEnforcer(
            provider_id=provider_id,
            trust_store=trust,
            consent_registry=consent_registry,
            database=database,
        )
        for provider_id, database in databases.items()
    }
    current_bindings = bindings(databases, processes)
    executor = AdversarialSuccessorExecutor(
        scenario=scenario,
        consent_registry=consent_registry,
        attacker_signer=signers["attacker"],
        permit_signer=signers["permit"],
        recovery_signer=signers["recovery"],
        provider_clients={
            provider_id: binding.client
            for provider_id, binding in current_bindings.items()
        },
        authorizer=PrincipalBoundAuthorizer(
            trust,
            consent_registry,
            signers["delegation"],
            signers["permit"],
        ),
        consent_envelope=signers["principal"].sign("principal_consent", consent),
        instance_signer=signers["instance"],
        provider_enforcers=enforcers,
        step_authorizations={
            step_id: StepAuthorization(step_id, resource, amount)
            for step_id, _, _, amount in STEP_DEFINITIONS
        },
        delegation_scope=consent_scope,
    )
    engine = WorkflowRecoveryEngine(
        store=store,
        providers=current_bindings,
        trust_store=trust,
        incident_signer=signers["incident"],
        closure_signer=signers["closure"],
        attestation_signer=signers["attestation"],
        recovery_signer=signers["recovery"],
        successor_executor=executor,
        authority_gate=DistributedAuthorityCoordinator(
            trust_store=trust,
            providers={
                provider_id: DurableAuthorityProvider(
                    provider_id,
                    databases[provider_id],
                    trust,
                    provider_signers[provider_id],
                )
                for provider_id in PROVIDER_IDS
            },
            barrier_signer=signers["barrier"],
        ),
        authority_transition_signer=signers["transition"],
    )
    started = time.perf_counter_ns()
    result = engine.recover(
        workflow_id=workflow_id,
        previous_scope=Scope.of(
            {definition[0] for definition in STEP_DEFINITIONS} | {"refund"},
            {resource},
            500,
        ),
        current_policy=consent_scope,
        manifest_hash="manifest:approved",
        configuration_hash="config:approved",
        approved_manifest_hashes=frozenset({"manifest:approved"}),
        approved_configuration_hashes=frozenset({"config:approved"}),
        expected_nonce=f"nonce:{workflow_id}",
        instance_id=signers["instance"].signer_id,
        public_key_fingerprint=signers["instance"].public_key_fingerprint,
        now=10_100 + trial,
    )
    latency_ns = time.perf_counter_ns() - started

    stale_deliveries_accepted = 0
    for delivery in store.deliveries(workflow_id):
        delivery_attempt = store.deliver(
            delivery.message_id,
            ProviderClient(processes[delivery.provider_id].base_url, timeout=0.25),
            now=100_000,
        )
        if (
            delivery_attempt.execution is not None
            and delivery_attempt.execution.status == "committed"
        ):
            stale_deliveries_accepted += 1

    counts = [
        databases[step.provider_id].effect_count(incident_id, step.step_id)
        for step in steps
    ]
    exact_once = all(count == 1 for count in counts)
    old_epochs_closed = all(
        database.epoch_state(workload_id, old_epoch) == "retired"
        for database in databases.values()
    )
    attack_accepted = (
        executor.attack_result is not None
        and executor.attack_result.status == "committed"
    )
    attack_blocked = executor.attack_attempted and not attack_accepted
    expected_quarantine = scenario == "revoked_consent"
    workflow_completed = result.status is RecoveryStatus.AUTHORIZED
    safe_outcome = (
        not attack_accepted
        and old_epochs_closed
        and stale_deliveries_accepted == 0
        and (
            (expected_quarantine and result.status is RecoveryStatus.QUARANTINED)
            or (not expected_quarantine and workflow_completed and exact_once)
        )
    )
    if not safe_outcome:
        raise AssertionError(
            f"unsafe E007 outcome: {scenario=} {fault=} {counts=} {result.reasons=}"
        )

    return {
        "seed": seed,
        "trial": trial,
        "scenario": scenario,
        "crash_step": crash_step.step_id,
        "fault": fault,
        "delayed_duplicates": delayed_duplicates,
        "controller_restart": controller_restart,
        "recovery_decision_authorized": result.decision.status is RecoveryStatus.AUTHORIZED,
        "workflow_completed": workflow_completed,
        "expected_quarantine": expected_quarantine,
        "attack_attempted": executor.attack_attempted,
        "attack_blocked": attack_blocked,
        "attack_accepted": attack_accepted,
        "attack_reason": (
            executor.attack_result.reason if executor.attack_result is not None else ""
        ),
        "old_epochs_closed": old_epochs_closed,
        "stale_deliveries_accepted": stale_deliveries_accepted,
        "exact_once_workflow": exact_once,
        "incomplete_steps": sum(count == 0 for count in counts),
        "safe_outcome": safe_outcome,
        "recovery_latency_ns": latency_ns,
    }


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: run_secure_workflow_attacks.py SEED TRIALS OUTPUT_CSV", file=sys.stderr)
        return 2
    seed = int(sys.argv[1])
    trials = int(sys.argv[2])
    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        store = WorkflowStore(root / "workflow.sqlite3")
        provider_signers = {
            provider_id: Ed25519Signer(provider_id) for provider_id in PROVIDER_IDS
        }
        databases = {
            provider_id: ProviderDatabase(root / f"{provider_id}.sqlite3")
            for provider_id in PROVIDER_IDS
        }
        processes = {
            provider_id: ProviderProcess(
                databases[provider_id].path,
                provider_signers[provider_id],
                enable_faults=True,
            ).start()
            for provider_id in PROVIDER_IDS
        }
        signers = {
            "incident": Ed25519Signer("incident-control"),
            "closure": Ed25519Signer("closure-verifier"),
            "attestation": Ed25519Signer("rats-verifier"),
            "recovery": Ed25519Signer("recovery-control"),
            "transition": Ed25519Signer("authority-control"),
            "barrier": Ed25519Signer("barrier-control"),
            "delegation": Ed25519Signer("delegation-control"),
            "permit": Ed25519Signer("permit-control"),
            "principal": Ed25519Signer("principal:alice"),
            "instance": Ed25519Signer("instance:successor"),
            "attacker": Ed25519Signer("instance:attacker"),
        }
        trust = TrustStore()
        for role, name in (
            ("incident_authority", "incident"),
            ("closure_authority", "closure"),
            ("attestation_verifier", "attestation"),
            ("recovery_authority", "recovery"),
            ("authority_transition_authority", "transition"),
            ("authority_barrier_authority", "barrier"),
            ("delegation_authority", "delegation"),
            ("permit_authority", "permit"),
            ("principal", "principal"),
            ("agent_instance", "instance"),
            ("agent_instance", "attacker"),
        ):
            trust.register(role, signers[name])
        for signer in provider_signers.values():
            trust.register("provider", signer)
            trust.register("effect_provider", signer)

        fields = (
            "seed",
            "trial",
            "scenario",
            "crash_step",
            "fault",
            "delayed_duplicates",
            "controller_restart",
            "recovery_decision_authorized",
            "workflow_completed",
            "expected_quarantine",
            "attack_attempted",
            "attack_blocked",
            "attack_accepted",
            "attack_reason",
            "old_epochs_closed",
            "stale_deliveries_accepted",
            "exact_once_workflow",
            "incomplete_steps",
            "safe_outcome",
            "recovery_latency_ns",
        )
        try:
            with output.open("w", newline="") as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=fields, lineterminator="\n"
                )
                writer.writeheader()
                for trial in range(trials):
                    writer.writerow(
                        run_case(
                            seed=seed,
                            trial=trial,
                            store=store,
                            databases=databases,
                            processes=processes,
                            trust=trust,
                            signers=signers,
                            provider_signers=provider_signers,
                        )
                    )
        finally:
            for process in processes.values():
                process.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
