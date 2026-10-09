from __future__ import annotations

import threading
from dataclasses import dataclass

from .crypto import (
    Ed25519Signer,
    SignedEnvelope,
    TrustStore,
    decode_public_key,
    encode_public_key,
    fingerprint_public_key,
    verify_with_public_key,
)
from .distributed import AuthorityBarrierCertificate
from .model import Attestation, RecoveryCertificate, Scope, digest
from .provider import EffectRequest, ExecutionResult, ProviderDatabase


@dataclass(frozen=True)
class PrincipalConsent:
    consent_id: str
    principal_id: str
    task_id: str
    workload_id: str
    scope: Scope
    issued_at: int
    expires_at: int
    nonce: str

    def is_fresh(self, now: int) -> bool:
        return bool(self.nonce) and self.issued_at <= now < self.expires_at


@dataclass(frozen=True)
class DelegationGrant:
    grant_id: str
    principal_id: str
    consent_id: str
    task_id: str
    workload_id: str
    instance_id: str
    public_key_fingerprint: str
    epoch: int
    scope: Scope
    consent_digest: str
    recovery_certificate_digest: str
    attestation_digest: str
    authority_barrier_digest: str
    issued_at: int
    expires_at: int

    def is_fresh(self, now: int) -> bool:
        return self.issued_at <= now < self.expires_at


@dataclass(frozen=True)
class ActionPermit:
    permit_id: str
    delegation_digest: str
    authority_barrier_digest: str
    principal_id: str
    consent_id: str
    task_id: str
    workload_id: str
    instance_id: str
    epoch: int
    provider_id: str
    step_id: str
    action: str
    resource: str
    amount: int | None
    operation_digest: str
    idempotency_key: str
    issued_at: int
    expires_at: int

    def is_fresh(self, now: int) -> bool:
        return self.issued_at <= now < self.expires_at


@dataclass(frozen=True)
class EffectIntent:
    principal_id: str
    task_id: str
    instance_id: str
    provider_id: str
    action: str
    resource: str
    amount: int | None
    effect: EffectRequest


@dataclass(frozen=True)
class ExecutionProof:
    instance_id: str
    permit_digest: str
    intent_digest: str
    issued_at: int


@dataclass(frozen=True)
class InstanceKeyEnrollment:
    workload_id: str
    instance_id: str
    epoch: int
    public_key: str
    public_key_fingerprint: str
    attestation_digest: str
    issued_at: int
    expires_at: int

    def is_fresh(self, now: int) -> bool:
        return self.issued_at <= now < self.expires_at


@dataclass(frozen=True)
class AuthorizedEffectRequest:
    intent: EffectIntent
    consent_envelope: SignedEnvelope
    attestation_envelope: SignedEnvelope
    recovery_envelope: SignedEnvelope
    delegation_envelope: SignedEnvelope
    permit_envelope: SignedEnvelope
    proof_envelope: SignedEnvelope
    key_enrollment_envelope: SignedEnvelope | None = None
    authority_barrier_envelope: SignedEnvelope | None = None


@dataclass(frozen=True)
class AuthorizationDecision:
    authorized: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class IssuanceDecision:
    issued: bool
    reasons: tuple[str, ...]
    envelope: SignedEnvelope | None = None


class ConsentRegistry:
    def __init__(self) -> None:
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    def revoke(self, consent_id: str) -> None:
        with self._lock:
            self._revoked.add(consent_id)

    def is_revoked(self, consent_id: str) -> bool:
        with self._lock:
            return consent_id in self._revoked


class SQLiteConsentRegistry(ConsentRegistry):
    def __init__(self, database: ProviderDatabase) -> None:
        self.database = database

    def revoke(self, consent_id: str) -> None:
        self.database.revoke_consent(consent_id)

    def is_revoked(self, consent_id: str) -> bool:
        return self.database.consent_revoked_at(consent_id) is not None


def _within_scope(action: str, resource: str, amount: int | None, scope: Scope) -> bool:
    if action not in scope.actions or resource not in scope.resources:
        return False
    if amount is not None and amount < 0:
        return False
    if scope.max_amount is not None:
        return amount is not None and amount <= scope.max_amount
    return True


def _recovery_lineage_is_self_consistent(certificate: RecoveryCertificate) -> bool:
    expected = digest(
        {
            "incident": certificate.grant.incident_digest,
            "closure": certificate.grant.closure_digest,
            "attestation": certificate.grant.attestation_digest,
            "grant": digest(certificate.grant),
            "reconciliation": certificate.reconciliation_digest,
            "instructions": certificate.instructions,
        }
    )
    return certificate.lineage_digest == expected


def _barrier_structure_reasons(
    barrier: AuthorityBarrierCertificate,
    recovery: RecoveryCertificate,
    now: int,
) -> list[str]:
    reasons: list[str] = []
    if barrier.workload_id != recovery.workload_id:
        reasons.append("authority_barrier_workload_mismatch")
    if (
        barrier.retired_epoch != recovery.retired_epoch
        or barrier.active_epoch != recovery.active_epoch
    ):
        reasons.append("authority_barrier_epoch_mismatch")
    if barrier.formed_at > now:
        reasons.append("authority_barrier_from_future")
    if tuple(sorted(set(barrier.provider_ids))) != barrier.provider_ids:
        reasons.append("invalid_authority_barrier_provider_set")
    if (
        not barrier.transition_id
        or not barrier.incident_id
        or not barrier.transition_digest
        or not barrier.provider_ids
        or len(barrier.acknowledgement_digests) != len(barrier.provider_ids)
        or len(set(barrier.acknowledgement_digests)) != len(
            barrier.acknowledgement_digests
        )
    ):
        reasons.append("incomplete_authority_barrier")
    return reasons


class PrincipalBoundAuthorizer:
    def __init__(
        self,
        trust_store: TrustStore,
        consent_registry: ConsentRegistry,
        delegation_signer: Ed25519Signer,
        permit_signer: Ed25519Signer,
    ) -> None:
        self._trust = trust_store
        self._consents = consent_registry
        self._delegation_signer = delegation_signer
        self._permit_signer = permit_signer

    def issue_delegation(
        self,
        *,
        consent_envelope: SignedEnvelope,
        attestation_envelope: SignedEnvelope,
        recovery_envelope: SignedEnvelope,
        authority_barrier_envelope: SignedEnvelope | None,
        requested_scope: Scope,
        now: int,
        grant_id: str,
        lifetime: int = 300,
    ) -> IssuanceDecision:
        reasons: list[str] = []
        if not self._trust.verify("principal", consent_envelope, "principal_consent"):
            reasons.append("invalid_principal_consent")
        if not self._trust.verify("attestation_verifier", attestation_envelope, "attestation"):
            reasons.append("invalid_attestation")
        if not self._trust.verify(
            "recovery_authority", recovery_envelope, "recovery_certificate"
        ):
            reasons.append("invalid_recovery_certificate")
        if authority_barrier_envelope is None:
            reasons.append("missing_authority_barrier")
        elif not self._trust.verify(
            "authority_barrier_authority",
            authority_barrier_envelope,
            "authority_barrier",
        ):
            reasons.append("invalid_authority_barrier")
        if reasons:
            return IssuanceDecision(False, tuple(reasons))

        consent = consent_envelope.payload
        attestation = attestation_envelope.payload
        recovery = recovery_envelope.payload
        barrier = (
            authority_barrier_envelope.payload
            if authority_barrier_envelope is not None
            else None
        )
        if not isinstance(consent, PrincipalConsent):
            reasons.append("malformed_principal_consent")
        if not isinstance(attestation, Attestation):
            reasons.append("malformed_attestation")
        if not isinstance(recovery, RecoveryCertificate):
            reasons.append("malformed_recovery_certificate")
        if not isinstance(barrier, AuthorityBarrierCertificate):
            reasons.append("malformed_authority_barrier")
        if reasons:
            return IssuanceDecision(False, tuple(reasons))
        assert isinstance(consent, PrincipalConsent)
        assert isinstance(attestation, Attestation)
        assert isinstance(recovery, RecoveryCertificate)
        assert isinstance(barrier, AuthorityBarrierCertificate)

        if consent.principal_id != consent_envelope.signer_id:
            reasons.append("principal_signer_mismatch")
        if not consent.is_fresh(now):
            reasons.append("stale_principal_consent")
        if not all(
            (
                consent.consent_id,
                consent.principal_id,
                consent.task_id,
                consent.workload_id,
                grant_id,
            )
        ):
            reasons.append("incomplete_delegation_identity")
        if self._consents.is_revoked(consent.consent_id):
            reasons.append("revoked_principal_consent")
        if consent.workload_id != recovery.workload_id:
            reasons.append("consent_workload_mismatch")
        if attestation.workload_id != recovery.workload_id:
            reasons.append("attestation_workload_mismatch")
        if attestation.new_epoch != recovery.active_epoch:
            reasons.append("attestation_epoch_mismatch")
        if not attestation.nonce or not (
            attestation.issued_at <= now < attestation.expires_at
        ):
            reasons.append("stale_attestation")
        if digest(attestation) != recovery.grant.attestation_digest:
            reasons.append("attestation_recovery_mismatch")
        if not _recovery_lineage_is_self_consistent(recovery):
            reasons.append("invalid_recovery_lineage")
        reasons.extend(_barrier_structure_reasons(barrier, recovery, now))
        barrier_digest = digest(barrier)
        if (
            not recovery.grant.authority_barrier_digest
            or recovery.grant.authority_barrier_digest != barrier_digest
        ):
            reasons.append("recovery_authority_barrier_mismatch")
        if (
            recovery.grant.workload_id != recovery.workload_id
            or recovery.grant.epoch != recovery.active_epoch
            or recovery.active_epoch <= recovery.retired_epoch
        ):
            reasons.append("invalid_recovery_epoch_binding")
        if not requested_scope.is_subset_of(consent.scope):
            reasons.append("requested_scope_exceeds_consent")
        if not requested_scope.is_subset_of(recovery.grant.scope):
            reasons.append("requested_scope_exceeds_recovery_grant")
        if lifetime <= 0:
            reasons.append("invalid_delegation_lifetime")
        if reasons:
            return IssuanceDecision(False, tuple(sorted(set(reasons))))

        expires_at = min(consent.expires_at, attestation.expires_at, now + lifetime)
        if expires_at <= now:
            return IssuanceDecision(False, ("empty_delegation_lifetime",))
        grant = DelegationGrant(
            grant_id=grant_id,
            principal_id=consent.principal_id,
            consent_id=consent.consent_id,
            task_id=consent.task_id,
            workload_id=consent.workload_id,
            instance_id=attestation.instance_id,
            public_key_fingerprint=attestation.public_key_fingerprint,
            epoch=attestation.new_epoch,
            scope=requested_scope,
            consent_digest=digest(consent),
            recovery_certificate_digest=digest(recovery),
            attestation_digest=digest(attestation),
            authority_barrier_digest=barrier_digest,
            issued_at=now,
            expires_at=expires_at,
        )
        return IssuanceDecision(
            True, (), self._delegation_signer.sign("delegation_grant", grant)
        )

    def issue_permit(
        self,
        *,
        delegation_envelope: SignedEnvelope,
        provider_id: str,
        step_id: str,
        action: str,
        resource: str,
        amount: int | None,
        operation_digest: str,
        idempotency_key: str,
        now: int,
        permit_id: str,
        lifetime: int = 60,
    ) -> IssuanceDecision:
        if not self._trust.verify(
            "delegation_authority", delegation_envelope, "delegation_grant"
        ):
            return IssuanceDecision(False, ("invalid_delegation_grant",))
        grant = delegation_envelope.payload
        if not isinstance(grant, DelegationGrant):
            return IssuanceDecision(False, ("malformed_delegation_grant",))

        reasons: list[str] = []
        if not grant.is_fresh(now):
            reasons.append("stale_delegation_grant")
        if not grant.authority_barrier_digest:
            reasons.append("missing_authority_barrier_binding")
        if self._consents.is_revoked(grant.consent_id):
            reasons.append("revoked_principal_consent")
        if not _within_scope(action, resource, amount, grant.scope):
            reasons.append("action_outside_delegated_scope")
        if not all((permit_id, provider_id, step_id, operation_digest, idempotency_key)):
            reasons.append("incomplete_effect_binding")
        if lifetime <= 0:
            reasons.append("invalid_permit_lifetime")
        if reasons:
            return IssuanceDecision(False, tuple(sorted(set(reasons))))

        permit = ActionPermit(
            permit_id=permit_id,
            delegation_digest=digest(grant),
            authority_barrier_digest=grant.authority_barrier_digest,
            principal_id=grant.principal_id,
            consent_id=grant.consent_id,
            task_id=grant.task_id,
            workload_id=grant.workload_id,
            instance_id=grant.instance_id,
            epoch=grant.epoch,
            provider_id=provider_id,
            step_id=step_id,
            action=action,
            resource=resource,
            amount=amount,
            operation_digest=operation_digest,
            idempotency_key=idempotency_key,
            issued_at=now,
            expires_at=min(grant.expires_at, now + lifetime),
        )
        return IssuanceDecision(True, (), self._permit_signer.sign("action_permit", permit))


class ProviderAuthorizationEnforcer:
    def __init__(
        self,
        *,
        provider_id: str,
        trust_store: TrustStore,
        consent_registry: ConsentRegistry,
        database: ProviderDatabase | None = None,
        require_dynamic_key_enrollment: bool = False,
    ) -> None:
        self.provider_id = provider_id
        self._trust = trust_store
        self._consents = consent_registry
        self._database = database
        self._require_dynamic_key_enrollment = require_dynamic_key_enrollment

    def verify_signed_permit(
        self, request: AuthorizedEffectRequest, *, now: int, active_epoch: int | None
    ) -> AuthorizationDecision:
        if not self._trust.verify("permit_authority", request.permit_envelope, "action_permit"):
            return AuthorizationDecision(False, ("invalid_action_permit",))
        permit = request.permit_envelope.payload
        if not isinstance(permit, ActionPermit):
            return AuthorizationDecision(False, ("malformed_action_permit",))
        reasons = self._permit_binding_reasons(permit, request.intent, now, active_epoch)
        return AuthorizationDecision(not reasons, tuple(sorted(set(reasons))))

    def verify_full_chain(
        self, request: AuthorizedEffectRequest, *, now: int, active_epoch: int | None
    ) -> AuthorizationDecision:
        reasons: list[str] = []
        checks = (
            (
                "principal",
                request.consent_envelope,
                "principal_consent",
                "invalid_principal_consent",
            ),
            (
                "attestation_verifier",
                request.attestation_envelope,
                "attestation",
                "invalid_attestation",
            ),
            (
                "recovery_authority",
                request.recovery_envelope,
                "recovery_certificate",
                "invalid_recovery_certificate",
            ),
            (
                "delegation_authority",
                request.delegation_envelope,
                "delegation_grant",
                "invalid_delegation_grant",
            ),
            ("permit_authority", request.permit_envelope, "action_permit", "invalid_action_permit"),
        )
        for role, envelope, kind, reason in checks:
            if not self._trust.verify(role, envelope, kind):
                reasons.append(reason)
        barrier_envelope = request.authority_barrier_envelope
        if barrier_envelope is None:
            reasons.append("missing_authority_barrier")
        elif not self._trust.verify(
            "authority_barrier_authority",
            barrier_envelope,
            "authority_barrier",
        ):
            reasons.append("invalid_authority_barrier")
        enrollment = request.key_enrollment_envelope
        if enrollment is None:
            if self._require_dynamic_key_enrollment:
                reasons.append("missing_instance_key_enrollment")
            elif not self._trust.verify(
                "agent_instance", request.proof_envelope, "execution_proof"
            ):
                reasons.append("invalid_instance_proof")
        else:
            if not self._trust.verify(
                "attestation_verifier", enrollment, "instance_key_enrollment"
            ):
                reasons.append("invalid_instance_key_enrollment")
        if reasons:
            return AuthorizationDecision(False, tuple(sorted(set(reasons))))

        consent = request.consent_envelope.payload
        attestation = request.attestation_envelope.payload
        recovery = request.recovery_envelope.payload
        grant = request.delegation_envelope.payload
        permit = request.permit_envelope.payload
        proof = request.proof_envelope.payload
        key_enrollment = enrollment.payload if enrollment is not None else None
        barrier = barrier_envelope.payload if barrier_envelope is not None else None
        types = (
            (consent, PrincipalConsent, "malformed_principal_consent"),
            (attestation, Attestation, "malformed_attestation"),
            (recovery, RecoveryCertificate, "malformed_recovery_certificate"),
            (grant, DelegationGrant, "malformed_delegation_grant"),
            (permit, ActionPermit, "malformed_action_permit"),
            (proof, ExecutionProof, "malformed_instance_proof"),
            (barrier, AuthorityBarrierCertificate, "malformed_authority_barrier"),
        )
        if enrollment is not None:
            types = (
                *types,
                (
                    key_enrollment,
                    InstanceKeyEnrollment,
                    "malformed_instance_key_enrollment",
                ),
            )
        for value, expected, reason in types:
            if not isinstance(value, expected):
                reasons.append(reason)
        if reasons:
            return AuthorizationDecision(False, tuple(sorted(set(reasons))))
        assert isinstance(consent, PrincipalConsent)
        assert isinstance(attestation, Attestation)
        assert isinstance(recovery, RecoveryCertificate)
        assert isinstance(grant, DelegationGrant)
        assert isinstance(permit, ActionPermit)
        assert isinstance(proof, ExecutionProof)
        assert isinstance(barrier, AuthorityBarrierCertificate)

        reasons.extend(self._permit_binding_reasons(permit, request.intent, now, active_epoch))
        if consent.principal_id != request.consent_envelope.signer_id:
            reasons.append("principal_signer_mismatch")
        if not consent.is_fresh(now):
            reasons.append("stale_principal_consent")
        if self._consents.is_revoked(consent.consent_id):
            reasons.append("revoked_principal_consent")
        if not grant.is_fresh(now):
            reasons.append("stale_delegation_grant")
        if not (attestation.issued_at <= now < attestation.expires_at):
            reasons.append("stale_attestation")
        if digest(consent) != grant.consent_digest:
            reasons.append("consent_delegation_mismatch")
        if digest(attestation) != grant.attestation_digest:
            reasons.append("attestation_delegation_mismatch")
        if digest(recovery) != grant.recovery_certificate_digest:
            reasons.append("recovery_delegation_mismatch")
        barrier_digest = digest(barrier)
        reasons.extend(_barrier_structure_reasons(barrier, recovery, now))
        if barrier_digest != recovery.grant.authority_barrier_digest:
            reasons.append("recovery_authority_barrier_mismatch")
        if barrier_digest != grant.authority_barrier_digest:
            reasons.append("delegation_authority_barrier_mismatch")
        if barrier_digest != permit.authority_barrier_digest:
            reasons.append("permit_authority_barrier_mismatch")
        if self.provider_id not in barrier.provider_ids:
            reasons.append("provider_absent_from_authority_barrier")
        if digest(grant) != permit.delegation_digest:
            reasons.append("delegation_permit_mismatch")
        if digest(attestation) != recovery.grant.attestation_digest:
            reasons.append("attestation_recovery_mismatch")
        if not _recovery_lineage_is_self_consistent(recovery):
            reasons.append("invalid_recovery_lineage")
        if recovery.workload_id != grant.workload_id or recovery.active_epoch != grant.epoch:
            reasons.append("recovery_authority_mismatch")
        if (
            recovery.grant.workload_id != recovery.workload_id
            or recovery.grant.epoch != recovery.active_epoch
            or recovery.active_epoch <= recovery.retired_epoch
        ):
            reasons.append("invalid_recovery_epoch_binding")
        if not grant.scope.is_subset_of(consent.scope):
            reasons.append("delegation_exceeds_consent")
        if not grant.scope.is_subset_of(recovery.grant.scope):
            reasons.append("delegation_exceeds_recovery_grant")
        if not _within_scope(permit.action, permit.resource, permit.amount, grant.scope):
            reasons.append("permit_exceeds_delegation")
        if (
            consent.principal_id != grant.principal_id
            or consent.consent_id != grant.consent_id
            or consent.task_id != grant.task_id
            or consent.workload_id != grant.workload_id
        ):
            reasons.append("consent_lineage_mismatch")
        if (
            permit.principal_id != grant.principal_id
            or permit.consent_id != grant.consent_id
            or permit.task_id != grant.task_id
            or permit.workload_id != grant.workload_id
            or permit.instance_id != grant.instance_id
            or permit.epoch != grant.epoch
        ):
            reasons.append("permit_delegation_identity_mismatch")
        if (
            grant.issued_at < consent.issued_at
            or grant.issued_at < barrier.formed_at
            or permit.issued_at < grant.issued_at
            or permit.expires_at > grant.expires_at
        ):
            reasons.append("invalid_delegation_time_chain")
        if (
            attestation.workload_id != grant.workload_id
            or attestation.instance_id != grant.instance_id
            or attestation.new_epoch != grant.epoch
            or attestation.public_key_fingerprint != grant.public_key_fingerprint
        ):
            reasons.append("attested_instance_mismatch")
        if isinstance(key_enrollment, InstanceKeyEnrollment):
            try:
                enrolled_public_key = decode_public_key(key_enrollment.public_key)
            except (ValueError, TypeError):
                enrolled_public_key = b""
                reasons.append("invalid_enrolled_public_key")
            if fingerprint_public_key(enrolled_public_key) != key_enrollment.public_key_fingerprint:
                reasons.append("enrolled_key_fingerprint_mismatch")
            if key_enrollment.public_key_fingerprint != grant.public_key_fingerprint:
                reasons.append("enrolled_key_delegation_mismatch")
            if enrollment is not None and (
                enrollment.signer_id != request.attestation_envelope.signer_id
            ):
                reasons.append("key_enrollment_verifier_mismatch")
            if (
                key_enrollment.workload_id != grant.workload_id
                or key_enrollment.instance_id != grant.instance_id
                or key_enrollment.epoch != grant.epoch
                or key_enrollment.attestation_digest != digest(attestation)
            ):
                reasons.append("key_enrollment_lineage_mismatch")
            if not key_enrollment.is_fresh(now):
                reasons.append("stale_instance_key_enrollment")
            if not (
                attestation.issued_at <= key_enrollment.issued_at
                and key_enrollment.expires_at <= attestation.expires_at
            ):
                reasons.append("invalid_key_enrollment_time_chain")
            if not verify_with_public_key(
                enrolled_public_key,
                request.proof_envelope,
                "execution_proof",
            ):
                reasons.append("invalid_instance_proof")
        else:
            registered_fingerprint = self._trust.public_key_fingerprint(
                "agent_instance", grant.instance_id
            )
            if registered_fingerprint != grant.public_key_fingerprint:
                reasons.append("instance_key_fingerprint_mismatch")
        if (
            proof.instance_id != grant.instance_id
            or request.proof_envelope.signer_id != grant.instance_id
        ):
            reasons.append("instance_proof_identity_mismatch")
        if proof.permit_digest != digest(permit) or proof.intent_digest != digest(request.intent):
            reasons.append("instance_proof_binding_mismatch")
        if not (permit.issued_at <= proof.issued_at <= now):
            reasons.append("instance_proof_time_invalid")
        return AuthorizationDecision(not reasons, tuple(sorted(set(reasons))))

    def _permit_binding_reasons(
        self,
        permit: ActionPermit,
        intent: EffectIntent,
        now: int,
        active_epoch: int | None,
    ) -> list[str]:
        reasons: list[str] = []
        effect = intent.effect
        if not permit.is_fresh(now):
            reasons.append("stale_action_permit")
        if permit.provider_id != self.provider_id or intent.provider_id != self.provider_id:
            reasons.append("provider_binding_mismatch")
        if permit.epoch != active_epoch or effect.epoch != active_epoch:
            reasons.append("inactive_authority_epoch")
        pairs = (
            (permit.principal_id, intent.principal_id, "principal_binding_mismatch"),
            (permit.task_id, intent.task_id, "task_binding_mismatch"),
            (permit.instance_id, intent.instance_id, "instance_binding_mismatch"),
            (permit.workload_id, effect.workload_id, "workload_binding_mismatch"),
            (permit.epoch, effect.epoch, "epoch_binding_mismatch"),
            (permit.step_id, effect.step_id, "step_binding_mismatch"),
            (permit.action, intent.action, "action_binding_mismatch"),
            (permit.resource, intent.resource, "resource_binding_mismatch"),
            (permit.amount, intent.amount, "amount_binding_mismatch"),
            (permit.operation_digest, effect.operation_digest, "operation_binding_mismatch"),
            (permit.idempotency_key, effect.idempotency_key, "delivery_binding_mismatch"),
        )
        for expected, observed, reason in pairs:
            if expected != observed:
                reasons.append(reason)
        return reasons

    def execute(self, request: AuthorizedEffectRequest, *, now: int) -> ExecutionResult:
        if self._database is None:
            raise RuntimeError("provider database is required for execution")
        active_epoch = self._database.active_epoch(request.intent.effect.workload_id)
        decision = self.verify_full_chain(request, now=now, active_epoch=active_epoch)
        if not decision.authorized:
            return ExecutionResult("rejected", 403, False, ",".join(decision.reasons))
        permit = request.permit_envelope.payload
        assert isinstance(permit, ActionPermit)
        status, payload = self._database.apply_authorized_effect(
            request.intent.effect,
            consent_id=permit.consent_id,
            permit_id=permit.permit_id,
            request_digest=digest(request.intent),
        )
        return ExecutionResult(
            payload["status"], status, bool(payload.get("replayed")), payload.get("reason", "")
        )


def make_execution_proof(
    signer: Ed25519Signer,
    permit_envelope: SignedEnvelope,
    intent: EffectIntent,
    *,
    now: int,
) -> SignedEnvelope:
    permit = permit_envelope.payload
    if not isinstance(permit, ActionPermit):
        raise TypeError("permit envelope payload must be an ActionPermit")
    proof = ExecutionProof(signer.signer_id, digest(permit), digest(intent), now)
    return signer.sign("execution_proof", proof)


def make_instance_key_enrollment(
    attestation_signer: Ed25519Signer,
    attestation: Attestation,
    instance_signer: Ed25519Signer,
    *,
    now: int,
) -> SignedEnvelope:
    if attestation.instance_id != instance_signer.signer_id:
        raise ValueError("attestation does not identify the supplied instance signer")
    if attestation.public_key_fingerprint != instance_signer.public_key_fingerprint:
        raise ValueError("attestation does not bind the supplied instance key")
    if not (attestation.issued_at <= now < attestation.expires_at):
        raise ValueError("attestation is not fresh")
    enrollment = InstanceKeyEnrollment(
        workload_id=attestation.workload_id,
        instance_id=attestation.instance_id,
        epoch=attestation.new_epoch,
        public_key=encode_public_key(instance_signer.public_key_bytes),
        public_key_fingerprint=instance_signer.public_key_fingerprint,
        attestation_digest=digest(attestation),
        issued_at=now,
        expires_at=attestation.expires_at,
    )
    return attestation_signer.sign("instance_key_enrollment", enrollment)
