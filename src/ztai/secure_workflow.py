from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .authorization import (
    AuthorizedEffectRequest,
    DelegationGrant,
    EffectIntent,
    PrincipalBoundAuthorizer,
    PrincipalConsent,
    ProviderAuthorizationEnforcer,
    make_execution_proof,
    make_instance_key_enrollment,
)
from .crypto import Ed25519Signer, SignedEnvelope
from .model import Attestation, Scope, Step
from .provider import EffectRequest, ExecutionResult
from .recovery import RecoveryDecision


@dataclass(frozen=True)
class StepAuthorization:
    action: str
    resource: str
    amount: int | None = None


class PrincipalBoundWorkflowExecutor:
    def __init__(
        self,
        *,
        authorizer: PrincipalBoundAuthorizer,
        consent_envelope: SignedEnvelope,
        instance_signer: Ed25519Signer,
        provider_enforcers: Mapping[str, ProviderAuthorizationEnforcer],
        step_authorizations: Mapping[str, StepAuthorization],
        delegation_scope: Scope,
        key_enrollment_signer: Ed25519Signer | None = None,
    ) -> None:
        self.authorizer = authorizer
        self.consent_envelope = consent_envelope
        self.instance_signer = instance_signer
        self.provider_enforcers = dict(provider_enforcers)
        self.step_authorizations = dict(step_authorizations)
        self.delegation_scope = delegation_scope
        self.key_enrollment_signer = key_enrollment_signer
        self.delegation_envelope: SignedEnvelope | None = None
        self.key_enrollment_envelope: SignedEnvelope | None = None
        self.requests: list[AuthorizedEffectRequest] = []

    def _delegation(
        self,
        *,
        decision: RecoveryDecision,
        attestation_envelope: SignedEnvelope,
        authority_barrier_envelope: SignedEnvelope,
        now: int,
    ) -> SignedEnvelope | None:
        if self.delegation_envelope is not None:
            return self.delegation_envelope
        if decision.certificate_envelope is None or decision.certificate is None:
            return None
        issued = self.authorizer.issue_delegation(
            consent_envelope=self.consent_envelope,
            attestation_envelope=attestation_envelope,
            recovery_envelope=decision.certificate_envelope,
            authority_barrier_envelope=authority_barrier_envelope,
            requested_scope=self.delegation_scope,
            now=now,
            grant_id=(
                f"delegation:{decision.certificate.workload_id}:"
                f"{decision.certificate.active_epoch}"
            ),
        )
        if issued.issued:
            self.delegation_envelope = issued.envelope
        return self.delegation_envelope

    def build_request(
        self,
        *,
        step: Step,
        request: EffectRequest,
        decision: RecoveryDecision,
        attestation_envelope: SignedEnvelope,
        authority_barrier_envelope: SignedEnvelope,
        now: int,
    ) -> AuthorizedEffectRequest | None:
        consent = self.consent_envelope.payload
        if not isinstance(consent, PrincipalConsent):
            return None
        delegation_envelope = self._delegation(
            decision=decision,
            attestation_envelope=attestation_envelope,
            authority_barrier_envelope=authority_barrier_envelope,
            now=now,
        )
        if delegation_envelope is None or decision.certificate_envelope is None:
            return None
        grant = delegation_envelope.payload
        if not isinstance(grant, DelegationGrant):
            return None
        authorization = self.step_authorizations.get(step.step_id)
        if authorization is None:
            return None
        permit = self.authorizer.issue_permit(
            delegation_envelope=delegation_envelope,
            provider_id=step.provider_id,
            step_id=step.step_id,
            action=authorization.action,
            resource=authorization.resource,
            amount=authorization.amount,
            operation_digest=request.operation_digest,
            idempotency_key=request.idempotency_key,
            now=now,
            permit_id=f"permit:{consent.task_id}:{step.step_id}:epoch:{request.epoch}",
        )
        if not permit.issued or permit.envelope is None:
            return None
        intent = EffectIntent(
            principal_id=consent.principal_id,
            task_id=consent.task_id,
            instance_id=grant.instance_id,
            provider_id=step.provider_id,
            action=authorization.action,
            resource=authorization.resource,
            amount=authorization.amount,
            effect=request,
        )
        proof = make_execution_proof(
            self.instance_signer,
            permit.envelope,
            intent,
            now=now,
        )
        if self.key_enrollment_signer is not None and self.key_enrollment_envelope is None:
            attestation = attestation_envelope.payload
            if not isinstance(attestation, Attestation):
                return None
            self.key_enrollment_envelope = make_instance_key_enrollment(
                self.key_enrollment_signer,
                attestation,
                self.instance_signer,
                now=now,
            )
        return AuthorizedEffectRequest(
            intent=intent,
            consent_envelope=self.consent_envelope,
            attestation_envelope=attestation_envelope,
            recovery_envelope=decision.certificate_envelope,
            delegation_envelope=delegation_envelope,
            permit_envelope=permit.envelope,
            proof_envelope=proof,
            key_enrollment_envelope=self.key_enrollment_envelope,
            authority_barrier_envelope=authority_barrier_envelope,
        )

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
        enforcer = self.provider_enforcers.get(step.provider_id)
        if enforcer is None:
            return ExecutionResult("rejected", 403, False, "missing_provider_enforcer")
        return enforcer.execute(authorized, now=now)
