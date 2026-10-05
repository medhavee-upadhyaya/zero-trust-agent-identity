from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .crypto import Ed25519Signer, SignedEnvelope, TrustStore
from .model import (
    Attestation,
    ClosureCertificate,
    EffectState,
    Grant,
    Incident,
    ReconciliationRecord,
    RecoveryCertificate,
    RecoveryStatus,
    ResumeInstruction,
    Scope,
    Step,
    digest,
)


@dataclass(frozen=True)
class RecoveryDecision:
    status: RecoveryStatus
    reasons: tuple[str, ...]
    certificate: RecoveryCertificate | None = None
    certificate_envelope: SignedEnvelope | None = None


class AuthorityRegistry:
    def __init__(self) -> None:
        self._active: dict[str, int | None] = {}
        self._retired: set[tuple[str, int]] = set()

    def establish(self, workload_id: str, epoch: int) -> None:
        if workload_id in self._active:
            raise ValueError("workload already established")
        self._active[workload_id] = epoch

    def retire(self, workload_id: str, epoch: int) -> None:
        if self._active.get(workload_id) != epoch:
            raise ValueError("only the active epoch can be retired")
        self._retired.add((workload_id, epoch))
        self._active[workload_id] = None

    def activate(self, workload_id: str, epoch: int) -> None:
        if self._active.get(workload_id) is not None:
            raise ValueError("an authority epoch is already active")
        if (workload_id, epoch) in self._retired:
            raise ValueError("a retired epoch cannot be reactivated")
        self._active[workload_id] = epoch

    def is_authorized(self, workload_id: str, epoch: int) -> bool:
        return self._active.get(workload_id) == epoch and (workload_id, epoch) not in self._retired

    def is_retired(self, workload_id: str, epoch: int) -> bool:
        return (workload_id, epoch) in self._retired

    def active_epoch(self, workload_id: str) -> int | None:
        return self._active.get(workload_id)


class RecoveryCoordinator:
    def __init__(
        self,
        trust_store: TrustStore,
        registry: AuthorityRegistry,
        recovery_signer: Ed25519Signer,
    ) -> None:
        self._trust_store = trust_store
        self._registry = registry
        self._recovery_signer = recovery_signer

    def verify_certificate(self, envelope: SignedEnvelope) -> bool:
        return self._trust_store.verify("recovery_authority", envelope, "recovery_certificate")

    def evaluate(
        self,
        *,
        incident_envelope: SignedEnvelope,
        closure_envelope: SignedEnvelope,
        attestation_envelope: SignedEnvelope,
        reconciliation_envelopes: Iterable[SignedEnvelope],
        previous_scope: Scope,
        current_policy: Scope,
        steps: Iterable[Step],
        expected_nonce: str,
        approved_manifest_hashes: frozenset[str],
        approved_configuration_hashes: frozenset[str],
        now: int,
        grant_id: str,
    ) -> RecoveryDecision:
        reasons: list[str] = []
        records_by_step: dict[str, ReconciliationRecord] = {}

        if not self._trust_store.verify("incident_authority", incident_envelope, "incident"):
            reasons.append("invalid_incident_evidence")
        if not self._trust_store.verify("closure_authority", closure_envelope, "closure"):
            reasons.append("invalid_closure_evidence")
        if not self._trust_store.verify("attestation_verifier", attestation_envelope, "attestation"):
            reasons.append("invalid_attestation_evidence")
        if reasons:
            return RecoveryDecision(RecoveryStatus.QUARANTINED, tuple(reasons))

        incident = incident_envelope.payload
        closure = closure_envelope.payload
        attestation = attestation_envelope.payload
        if not isinstance(incident, Incident):
            reasons.append("malformed_incident")
        if not isinstance(closure, ClosureCertificate):
            reasons.append("malformed_closure")
        if not isinstance(attestation, Attestation):
            reasons.append("malformed_attestation")
        if reasons:
            return RecoveryDecision(RecoveryStatus.QUARANTINED, tuple(reasons))

        if (
            incident.incident_id != closure.incident_id
            or incident.workload_id != closure.workload_id
            or incident.retired_epoch != closure.retired_epoch
        ):
            reasons.append("incident_closure_mismatch")
        if not closure.is_positive():
            reasons.append("old_authority_not_proven_closed")
        if not self._registry.is_retired(incident.workload_id, incident.retired_epoch):
            reasons.append("retired_epoch_not_registered")
        if self._registry.active_epoch(incident.workload_id) is not None:
            reasons.append("authority_overlap")
        if attestation.workload_id != incident.workload_id:
            reasons.append("attested_workload_mismatch")
        if attestation.new_epoch <= incident.retired_epoch:
            reasons.append("non_monotonic_epoch")
        if not attestation.is_fresh(now, expected_nonce):
            reasons.append("stale_or_unbound_attestation")
        if attestation.issued_at <= incident.declared_at:
            reasons.append("attestation_not_post_incident")
        if attestation.manifest_hash not in approved_manifest_hashes:
            reasons.append("unapproved_manifest")
        if attestation.configuration_hash not in approved_configuration_hashes:
            reasons.append("unapproved_configuration")
        if not attestation.instance_id or not attestation.public_key_fingerprint:
            reasons.append("incomplete_attested_identity")

        planned_steps = tuple(steps)
        for envelope in reconciliation_envelopes:
            if not self._trust_store.verify("provider", envelope, "reconciliation"):
                reasons.append("invalid_provider_evidence")
                continue
            record = envelope.payload
            if not isinstance(record, ReconciliationRecord):
                reasons.append("malformed_reconciliation_record")
                continue
            if record.provider_id != envelope.signer_id:
                reasons.append("provider_identity_mismatch")
                continue
            if record.incident_id != incident.incident_id:
                reasons.append("reconciliation_incident_mismatch")
                continue
            if record.step_id in records_by_step:
                reasons.append("duplicate_reconciliation_record")
                continue
            records_by_step[record.step_id] = record

        instructions: list[ResumeInstruction] = []
        step_ids = [step.step_id for step in planned_steps]
        if len(step_ids) != len(set(step_ids)):
            reasons.append("duplicate_planned_step")
        for step in planned_steps:
            record = records_by_step.get(step.step_id)
            if record is None:
                reasons.append(f"missing_reconciliation:{step.step_id}")
                continue
            if record.provider_id != step.provider_id or record.operation_digest != step.operation_digest:
                reasons.append(f"reconciliation_binding_mismatch:{step.step_id}")
                continue
            if not record.evidence_ref:
                reasons.append(f"missing_effect_evidence:{step.step_id}")
                continue
            if record.state is EffectState.AMBIGUOUS:
                reasons.append(f"ambiguous_effect:{step.step_id}")
            elif record.state in (EffectState.COMMITTED, EffectState.IRREVERSIBLE):
                instructions.append(ResumeInstruction(step.step_id, "skip", record.state.value))
            elif record.state in (EffectState.NO_EFFECT, EffectState.NOT_STARTED):
                if not step.idempotent and record.state is EffectState.NOT_STARTED:
                    instructions.append(ResumeInstruction(step.step_id, "execute_once", "certified_not_started"))
                else:
                    instructions.append(ResumeInstruction(step.step_id, "execute", record.state.value))
            elif record.state is EffectState.COMPENSATED:
                if step.idempotent:
                    instructions.append(ResumeInstruction(step.step_id, "execute", "compensated"))
                else:
                    reasons.append(f"non_idempotent_compensated_step:{step.step_id}")

        extra_records = set(records_by_step) - {step.step_id for step in planned_steps}
        if extra_records:
            reasons.append("unexpected_reconciliation_records")
        if reasons:
            return RecoveryDecision(RecoveryStatus.QUARANTINED, tuple(sorted(set(reasons))))

        new_scope = previous_scope.intersect(current_policy)
        grant = Grant(
            grant_id=grant_id,
            workload_id=incident.workload_id,
            epoch=attestation.new_epoch,
            scope=new_scope,
            incident_digest=digest(incident),
            closure_digest=digest(closure),
            attestation_digest=digest(attestation),
            policy_digest=digest(current_policy),
        )
        reconciliation_digest = digest(tuple(records_by_step[key] for key in sorted(records_by_step)))
        lineage_digest = digest(
            {
                "incident": grant.incident_digest,
                "closure": grant.closure_digest,
                "attestation": grant.attestation_digest,
                "grant": digest(grant),
                "reconciliation": reconciliation_digest,
                "instructions": tuple(instructions),
            }
        )
        certificate = RecoveryCertificate(
            workload_id=incident.workload_id,
            retired_epoch=incident.retired_epoch,
            active_epoch=attestation.new_epoch,
            grant=grant,
            reconciliation_digest=reconciliation_digest,
            instructions=tuple(instructions),
            lineage_digest=lineage_digest,
        )
        envelope = self._recovery_signer.sign("recovery_certificate", certificate)
        return RecoveryDecision(RecoveryStatus.AUTHORIZED, (), certificate, envelope)
