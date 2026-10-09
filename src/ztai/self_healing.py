from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from .crypto import (
    Ed25519Signer,
    SignedEnvelope,
    TrustStore,
    decode_public_key,
    encode_public_key,
    fingerprint_public_key,
)
from .distributed import (
    AuthorityBarrierDecision,
    AuthorityProvider,
    AuthorityTransition,
    DistributedAuthorityCoordinator,
)
from .model import RecoveryStatus, digest


@dataclass(frozen=True)
class ProviderKeyRotationAttestation:
    rotation_id: str
    provider_id: str
    transition_id: str
    workload_id: str
    previous_key_fingerprint: str
    new_key_fingerprint: str
    new_public_key: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class RepairEvent:
    attempt: int
    provider_id: str
    trigger_reason: str
    action: str
    evidence_digest: str


@dataclass(frozen=True)
class SelfHealingCertificate:
    transition_digest: str
    initial_reasons: tuple[str, ...]
    final_reasons: tuple[str, ...]
    repair_events: tuple[RepairEvent, ...]
    attempts: int
    final_status: str
    barrier_digest: str
    completed_at: int


@dataclass(frozen=True)
class SelfHealingResult:
    decision: AuthorityBarrierDecision
    repair_events: tuple[RepairEvent, ...]
    attempts: int
    initial_reasons: tuple[str, ...]
    certificate_envelope: SignedEnvelope

    @property
    def recovered(self) -> bool:
        return (
            bool(self.repair_events)
            and self.decision.status is RecoveryStatus.AUTHORIZED
        )


ProviderRepair = Callable[[str, str], AuthorityProvider | None]


def make_provider_key_rotation_attestation(
    *,
    attestation_signer: Ed25519Signer,
    provider_id: str,
    transition: AuthorityTransition,
    previous_key_fingerprint: str,
    new_signer: Ed25519Signer,
    issued_at: int,
    expires_at: int,
    rotation_id: str,
) -> SignedEnvelope:
    attestation = ProviderKeyRotationAttestation(
        rotation_id=rotation_id,
        provider_id=provider_id,
        transition_id=transition.transition_id,
        workload_id=transition.workload_id,
        previous_key_fingerprint=previous_key_fingerprint,
        new_key_fingerprint=new_signer.public_key_fingerprint,
        new_public_key=encode_public_key(new_signer.public_key_bytes),
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return attestation_signer.sign(
        "provider_key_rotation_attestation", attestation
    )


class SelfHealingAuthorityController:
    """Retries only bounded repairs and never bypasses barrier verification."""

    def __init__(
        self,
        *,
        trust_store: TrustStore,
        providers: Mapping[str, AuthorityProvider],
        barrier_signer: Ed25519Signer,
        audit_signer: Ed25519Signer,
        repair_provider: ProviderRepair | None = None,
        max_attempts: int = 3,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self.trust_store = trust_store
        self.providers = dict(providers)
        self.barrier_signer = barrier_signer
        self.audit_signer = audit_signer
        self.repair_provider = repair_provider
        self.max_attempts = max_attempts

    def _coordinator(self) -> DistributedAuthorityCoordinator:
        return DistributedAuthorityCoordinator(
            trust_store=self.trust_store,
            providers=self.providers,
            barrier_signer=self.barrier_signer,
        )

    def _valid_rotation_key(
        self,
        *,
        provider_id: str,
        envelope: SignedEnvelope | None,
        transition: AuthorityTransition,
        now: int,
    ) -> bytes | None:
        if envelope is None or not self.trust_store.verify(
            "provider_key_attestation_authority",
            envelope,
            "provider_key_rotation_attestation",
        ):
            return None
        attestation = envelope.payload
        if not isinstance(attestation, ProviderKeyRotationAttestation):
            return None
        if (
            not attestation.rotation_id
            or attestation.provider_id != provider_id
            or attestation.transition_id != transition.transition_id
            or attestation.workload_id != transition.workload_id
            or not attestation.issued_at <= now <= attestation.expires_at
        ):
            return None
        current_fingerprint = self.trust_store.public_key_fingerprint(
            "effect_provider", provider_id
        )
        if (
            current_fingerprint is None
            or current_fingerprint != attestation.previous_key_fingerprint
            or attestation.new_key_fingerprint == current_fingerprint
        ):
            return None
        try:
            public_key = decode_public_key(attestation.new_public_key)
        except (TypeError, ValueError):
            return None
        if fingerprint_public_key(public_key) != attestation.new_key_fingerprint:
            return None
        return public_key

    def _repair(
        self,
        *,
        decision: AuthorityBarrierDecision,
        transition: AuthorityTransition,
        rotation_attestations: Mapping[str, SignedEnvelope],
        attempt: int,
        now: int,
    ) -> tuple[list[RepairEvent], bool]:
        events: list[RepairEvent] = []
        changed = False
        for reason in decision.reasons:
            if reason.startswith("unavailable_provider:"):
                provider_id = reason.split(":", 1)[1]
                replacement = (
                    self.repair_provider(provider_id, "transport_failure")
                    if self.repair_provider is not None
                    else None
                )
                if replacement is not None:
                    self.providers[provider_id] = replacement
                events.append(
                    RepairEvent(
                        attempt,
                        provider_id,
                        reason,
                        "retry_or_restart_transport",
                        "",
                    )
                )
                changed = True
                continue
            if reason.startswith("invalid_ack_signature:"):
                provider_id = reason.split(":", 1)[1]
                attestation_envelope = rotation_attestations.get(provider_id)
                public_key = self._valid_rotation_key(
                    provider_id=provider_id,
                    envelope=attestation_envelope,
                    transition=transition,
                    now=now,
                )
                evidence_digest = (
                    digest(attestation_envelope)
                    if attestation_envelope is not None
                    else ""
                )
                if public_key is None:
                    events.append(
                        RepairEvent(
                            attempt,
                            provider_id,
                            reason,
                            "reject_unattested_key_rotation",
                            evidence_digest,
                        )
                    )
                    continue
                self.trust_store.register_public_key(
                    "effect_provider", provider_id, public_key
                )
                replacement = (
                    self.repair_provider(provider_id, "attested_key_rotation")
                    if self.repair_provider is not None
                    else None
                )
                if replacement is not None:
                    self.providers[provider_id] = replacement
                events.append(
                    RepairEvent(
                        attempt,
                        provider_id,
                        reason,
                        "accept_attested_key_rotation",
                        evidence_digest,
                    )
                )
                changed = True
        return events, changed

    def recover(
        self,
        transition_envelope: SignedEnvelope,
        *,
        now: int,
        rotation_attestations: Mapping[str, SignedEnvelope] | None = None,
    ) -> SelfHealingResult:
        transition = transition_envelope.payload
        attestations = dict(rotation_attestations or {})
        events: list[RepairEvent] = []
        attempts = 1
        decision = self._coordinator().establish_barrier(
            transition_envelope,
            now=now,
        )
        initial_reasons = decision.reasons
        if isinstance(transition, AuthorityTransition):
            while (
                decision.status is RecoveryStatus.QUARANTINED
                and attempts < self.max_attempts
            ):
                repairs, changed = self._repair(
                    decision=decision,
                    transition=transition,
                    rotation_attestations=attestations,
                    attempt=attempts,
                    now=now + attempts,
                )
                events.extend(repairs)
                if not changed:
                    break
                attempts += 1
                decision = self._coordinator().establish_barrier(
                    transition_envelope,
                    now=now + attempts - 1,
                )

        certificate = SelfHealingCertificate(
            transition_digest=digest(transition_envelope),
            initial_reasons=initial_reasons,
            final_reasons=decision.reasons,
            repair_events=tuple(events),
            attempts=attempts,
            final_status=decision.status.value,
            barrier_digest=(
                digest(decision.barrier_envelope)
                if decision.barrier_envelope is not None
                else ""
            ),
            completed_at=now + attempts - 1,
        )
        return SelfHealingResult(
            decision,
            tuple(events),
            attempts,
            initial_reasons,
            self.audit_signer.sign("self_healing_certificate", certificate),
        )

    def verify_result(
        self,
        result: SelfHealingResult,
        transition_envelope: SignedEnvelope,
    ) -> bool:
        envelope = result.certificate_envelope
        if not self.trust_store.verify(
            "self_healing_authority", envelope, "self_healing_certificate"
        ):
            return False
        certificate = envelope.payload
        if not isinstance(certificate, SelfHealingCertificate):
            return False
        expected_barrier_digest = (
            digest(result.decision.barrier_envelope)
            if result.decision.barrier_envelope is not None
            else ""
        )
        return (
            certificate.transition_digest == digest(transition_envelope)
            and certificate.initial_reasons == result.initial_reasons
            and certificate.repair_events == result.repair_events
            and certificate.attempts == result.attempts
            and certificate.final_status == result.decision.status.value
            and certificate.final_reasons == result.decision.reasons
            and certificate.barrier_digest == expected_barrier_digest
        )

    def verify_barrier(self, decision: AuthorityBarrierDecision) -> bool:
        return self._coordinator().verify_barrier(decision)
