from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol

from .crypto import Ed25519Signer, SignedEnvelope, TrustStore
from .model import (
    Attestation,
    ClosureCertificate,
    ClosureVerdict,
    Incident,
    RecoveryStatus,
    Scope,
    Step,
)
from .provider import EffectRequest, ExecutionResult, ProviderClient, ProviderDatabase
from .recovery import AuthorityRegistry, RecoveryCoordinator, RecoveryDecision
from .workflow import WorkflowStore


@dataclass(frozen=True)
class ProviderBinding:
    provider_id: str
    database: ProviderDatabase
    client: ProviderClient


class SuccessorEffectExecutor(Protocol):
    def execute(
        self,
        *,
        step: Step,
        request: EffectRequest,
        decision: RecoveryDecision,
        attestation_envelope: SignedEnvelope,
        now: int,
    ) -> ExecutionResult: ...


@dataclass(frozen=True)
class WorkflowRecoveryResult:
    status: RecoveryStatus
    reasons: tuple[str, ...]
    decision: RecoveryDecision
    closure_envelope: SignedEnvelope
    reconciliation_envelopes: tuple[SignedEnvelope, ...]
    completed_steps: tuple[str, ...]


class WorkflowRecoveryEngine:
    def __init__(
        self,
        *,
        store: WorkflowStore,
        providers: Mapping[str, ProviderBinding],
        trust_store: TrustStore,
        incident_signer: Ed25519Signer,
        closure_signer: Ed25519Signer,
        attestation_signer: Ed25519Signer,
        recovery_signer: Ed25519Signer,
        successor_executor: SuccessorEffectExecutor | None = None,
    ) -> None:
        self.store = store
        self.providers = dict(providers)
        self.trust_store = trust_store
        self.incident_signer = incident_signer
        self.closure_signer = closure_signer
        self.attestation_signer = attestation_signer
        self.recovery_signer = recovery_signer
        self.successor_executor = successor_executor

    @staticmethod
    def _idempotency_key(workflow_id: str, step_id: str, epoch: int) -> str:
        return f"{workflow_id}:{step_id}:epoch:{epoch}"

    def _request(self, workflow_id: str, step: Step, epoch: int) -> EffectRequest:
        snapshot = self.store.snapshot(workflow_id)
        return EffectRequest(
            incident_id=snapshot.incident_id,
            step_id=step.step_id,
            workload_id=snapshot.workload_id,
            epoch=epoch,
            operation_digest=step.operation_digest,
            idempotency_key=self._idempotency_key(workflow_id, step.step_id, epoch),
        )

    def old_request(self, workflow_id: str, step_id: str) -> EffectRequest:
        snapshot = self.store.snapshot(workflow_id)
        by_id = {step.step_id: step for step in self.store.steps(workflow_id)}
        spec = by_id.get(step_id)
        if spec is None:
            raise KeyError(step_id)
        return EffectRequest(
            incident_id=snapshot.incident_id,
            step_id=spec.step_id,
            workload_id=snapshot.workload_id,
            epoch=snapshot.old_epoch,
            operation_digest=spec.operation_digest,
            idempotency_key=self._idempotency_key(
                workflow_id, spec.step_id, snapshot.old_epoch
            ),
        )

    def _close_old_authority(self, workflow_id: str, now: int) -> SignedEnvelope:
        snapshot = self.store.snapshot(workflow_id)
        queue_carriers = self.store.epoch_carriers(workflow_id, snapshot.old_epoch)
        provider_carriers = tuple(
            f"provider:{provider_id}:epoch:{snapshot.old_epoch}"
            for provider_id in sorted(self.providers)
        )
        credential_carrier = f"credential:{snapshot.old_epoch}"
        inventoried = (credential_carrier, *provider_carriers, *queue_carriers)

        self.store.cancel_epoch(workflow_id, snapshot.old_epoch)
        providers_closed = True
        for binding in self.providers.values():
            state = binding.database.epoch_state(snapshot.workload_id, snapshot.old_epoch)
            if state == "active":
                binding.database.retire_epoch(snapshot.workload_id, snapshot.old_epoch, now)
            if binding.database.epoch_state(snapshot.workload_id, snapshot.old_epoch) != "retired":
                providers_closed = False
        open_queue_carriers = self.store.open_epoch_carriers(
            workflow_id, snapshot.old_epoch
        )
        closed = inventoried if providers_closed and not open_queue_carriers else ()
        closure = ClosureCertificate(
            incident_id=snapshot.incident_id,
            workload_id=snapshot.workload_id,
            retired_epoch=snapshot.old_epoch,
            verdict=(
                ClosureVerdict.QUIESCENT
                if providers_closed and not open_queue_carriers
                else ClosureVerdict.INDETERMINATE
            ),
            inventoried_carriers=inventoried,
            closed_carriers=closed,
            unresolved_carriers=open_queue_carriers,
        )
        return self.closure_signer.sign("closure", closure)

    def recover(
        self,
        *,
        workflow_id: str,
        previous_scope: Scope,
        current_policy: Scope,
        manifest_hash: str,
        configuration_hash: str,
        approved_manifest_hashes: frozenset[str],
        approved_configuration_hashes: frozenset[str],
        expected_nonce: str,
        attestation_nonce: str | None = None,
        instance_id: str | None = None,
        public_key_fingerprint: str | None = None,
        now: int,
    ) -> WorkflowRecoveryResult:
        snapshot = self.store.snapshot(workflow_id)
        self.store.set_status(workflow_id, "recovering", now)
        closure_envelope = self._close_old_authority(workflow_id, now)
        incident = Incident(
            snapshot.incident_id,
            snapshot.workload_id,
            snapshot.old_epoch,
            snapshot.declared_at,
            "runtime_compromise",
        )
        attestation = Attestation(
            workload_id=snapshot.workload_id,
            instance_id=(
                instance_id
                if instance_id is not None
                else f"{workflow_id}:generation:{snapshot.controller_generation}"
            ),
            new_epoch=snapshot.new_epoch,
            public_key_fingerprint=(
                public_key_fingerprint
                if public_key_fingerprint is not None
                else f"pk:{workflow_id}:{snapshot.new_epoch}"
            ),
            manifest_hash=manifest_hash,
            configuration_hash=configuration_hash,
            nonce=attestation_nonce if attestation_nonce is not None else expected_nonce,
            issued_at=now - 1,
            expires_at=now + 60,
        )
        steps = tuple(
            Step(
                spec.step_id,
                spec.provider_id,
                spec.operation_digest,
                spec.idempotent,
            )
            for spec in self.store.steps(workflow_id)
        )
        reconciliation: list[SignedEnvelope] = []
        for step in steps:
            binding = self.providers[step.provider_id]
            outcome = binding.client.reconcile(
                self._request(workflow_id, step, snapshot.old_epoch),
                create_fence=True,
            )
            if outcome.envelope is not None:
                reconciliation.append(outcome.envelope)

        registry = AuthorityRegistry()
        registry.establish(snapshot.workload_id, snapshot.old_epoch)
        registry.retire(snapshot.workload_id, snapshot.old_epoch)
        coordinator = RecoveryCoordinator(self.trust_store, registry, self.recovery_signer)
        attestation_envelope = self.attestation_signer.sign("attestation", attestation)
        decision = coordinator.evaluate(
            incident_envelope=self.incident_signer.sign("incident", incident),
            closure_envelope=closure_envelope,
            attestation_envelope=attestation_envelope,
            reconciliation_envelopes=tuple(reconciliation),
            previous_scope=previous_scope,
            current_policy=current_policy,
            steps=steps,
            expected_nonce=expected_nonce,
            approved_manifest_hashes=approved_manifest_hashes,
            approved_configuration_hashes=approved_configuration_hashes,
            now=now,
            grant_id=f"grant:{workflow_id}:{snapshot.new_epoch}",
        )
        if decision.status is not RecoveryStatus.AUTHORIZED:
            self.store.set_status(workflow_id, "quarantined", now)
            return WorkflowRecoveryResult(
                decision.status,
                decision.reasons,
                decision,
                closure_envelope,
                tuple(reconciliation),
                (),
            )

        for binding in self.providers.values():
            active = binding.database.active_epoch(snapshot.workload_id)
            if active is None:
                if not binding.database.activate_epoch(
                    snapshot.workload_id, snapshot.new_epoch, now + 1
                ):
                    raise RuntimeError("provider refused successor epoch activation")
            elif active != snapshot.new_epoch:
                raise RuntimeError("provider has an unexpected active epoch")
        registry.activate(snapshot.workload_id, snapshot.new_epoch)

        assert decision.certificate is not None
        completed: list[str] = []
        for step, instruction in zip(steps, decision.certificate.instructions, strict=True):
            self.store.set_step_state(
                workflow_id,
                step.step_id,
                "recovering",
                instruction.action,
            )
            if instruction.action == "skip":
                self.store.set_step_state(
                    workflow_id, step.step_id, "completed", instruction.action
                )
                completed.append(step.step_id)
                continue
            request = self._request(workflow_id, step, snapshot.new_epoch)
            if self.successor_executor is None:
                result = self.providers[step.provider_id].client.execute(request)
            else:
                result = self.successor_executor.execute(
                    step=step,
                    request=request,
                    decision=decision,
                    attestation_envelope=attestation_envelope,
                    now=now + 2,
                )
            if result.status != "committed":
                reason = f"resume_execution_failed:{step.step_id}:{result.reason}"
                self.store.set_step_state(
                    workflow_id, step.step_id, "failed", instruction.action
                )
                self.store.set_status(workflow_id, "quarantined", now + 2)
                return WorkflowRecoveryResult(
                    RecoveryStatus.QUARANTINED,
                    (reason,),
                    decision,
                    closure_envelope,
                    tuple(reconciliation),
                    tuple(completed),
                )
            self.store.set_step_state(
                workflow_id, step.step_id, "completed", instruction.action
            )
            completed.append(step.step_id)
        self.store.set_status(workflow_id, "completed", now + 2)
        return WorkflowRecoveryResult(
            RecoveryStatus.AUTHORIZED,
            (),
            decision,
            closure_envelope,
            tuple(reconciliation),
            tuple(completed),
        )
