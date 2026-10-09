from __future__ import annotations

import dataclasses
import unittest

from ztai import (
    Attestation,
    AuthorityBarrierCertificate,
    AuthorityRegistry,
    ClosureCertificate,
    ClosureVerdict,
    Ed25519Signer,
    EffectState,
    Incident,
    ReconciliationRecord,
    RecoveryCoordinator,
    RecoveryStatus,
    Scope,
    Step,
    TrustStore,
)
from ztai.model import digest


class RecoveryProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.incident_signer = Ed25519Signer("incident-control")
        self.closure_signer = Ed25519Signer("closure-verifier")
        self.attestation_signer = Ed25519Signer("rats-verifier")
        self.provider_a = Ed25519Signer("provider-a")
        self.provider_b = Ed25519Signer("provider-b")
        self.recovery_signer = Ed25519Signer("recovery-control")
        self.barrier_signer = Ed25519Signer("barrier-control")
        self.untrusted = Ed25519Signer("untrusted")

        trust = TrustStore()
        trust.register("incident_authority", self.incident_signer)
        trust.register("closure_authority", self.closure_signer)
        trust.register("attestation_verifier", self.attestation_signer)
        trust.register("provider", self.provider_a)
        trust.register("provider", self.provider_b)
        trust.register("recovery_authority", self.recovery_signer)
        trust.register("authority_barrier_authority", self.barrier_signer)

        self.registry = AuthorityRegistry()
        self.registry.establish("agent/payments", 7)
        self.registry.retire("agent/payments", 7)
        self.trust = trust
        self.coordinator = RecoveryCoordinator(trust, self.registry, self.recovery_signer)

        self.incident = Incident("inc-001", "agent/payments", 7, 1_000, "runtime_compromise")
        self.closure = ClosureCertificate(
            incident_id="inc-001",
            workload_id="agent/payments",
            retired_epoch=7,
            verdict=ClosureVerdict.QUIESCENT,
            inventoried_carriers=("credential:7", "queue:q1", "callback:c1"),
            closed_carriers=("credential:7", "queue:q1", "callback:c1"),
        )
        self.attestation = Attestation(
            workload_id="agent/payments",
            instance_id="instance-repaired-1",
            new_epoch=8,
            public_key_fingerprint="pk:8",
            manifest_hash="manifest:approved",
            configuration_hash="config:approved",
            nonce="nonce-001",
            issued_at=1_010,
            expires_at=1_100,
        )
        self.steps = (
            Step("charge", "provider-a", "op:charge:42", False),
            Step("email", "provider-b", "op:email:42", True),
        )
        self.records = (
            ReconciliationRecord(
                "inc-001", "charge", "provider-a", "op:charge:42", EffectState.COMMITTED, "receipt:1"
            ),
            ReconciliationRecord(
                "inc-001", "email", "provider-b", "op:email:42", EffectState.NO_EFFECT, "lookup:2"
            ),
        )
        self.previous_scope = Scope.of({"charge", "email", "refund"}, {"acct:42"}, 500)
        self.current_policy = Scope.of({"charge", "email"}, {"acct:42", "acct:99"}, 200)

    def decide(self, **overrides):
        values = {
            "incident_envelope": self.incident_signer.sign("incident", self.incident),
            "closure_envelope": self.closure_signer.sign("closure", self.closure),
            "attestation_envelope": self.attestation_signer.sign("attestation", self.attestation),
            "reconciliation_envelopes": (
                self.provider_a.sign("reconciliation", self.records[0]),
                self.provider_b.sign("reconciliation", self.records[1]),
            ),
            "previous_scope": self.previous_scope,
            "current_policy": self.current_policy,
            "steps": self.steps,
            "expected_nonce": "nonce-001",
            "approved_manifest_hashes": frozenset({"manifest:approved"}),
            "approved_configuration_hashes": frozenset({"config:approved"}),
            "now": 1_020,
            "grant_id": "grant-008",
        }
        values.update(overrides)
        return self.coordinator.evaluate(**values)

    def barrier(self, **changes):
        barrier = AuthorityBarrierCertificate(
            transition_id="transition:inc-001",
            incident_id=self.incident.incident_id,
            workload_id=self.incident.workload_id,
            version=8,
            retired_epoch=7,
            active_epoch=8,
            transition_digest=digest({"transition": "inc-001"}),
            provider_ids=("provider-a", "provider-b"),
            acknowledgement_digests=(
                digest({"provider": "provider-a"}),
                digest({"provider": "provider-b"}),
            ),
            formed_at=1_019,
        )
        return self.barrier_signer.sign(
            "authority_barrier", dataclasses.replace(barrier, **changes)
        )

    def test_authorizes_only_after_all_evidence_verifies(self) -> None:
        decision = self.decide()
        self.assertEqual(decision.status, RecoveryStatus.AUTHORIZED)
        self.assertIsNotNone(decision.certificate)
        certificate = decision.certificate
        assert certificate is not None
        self.assertEqual([item.action for item in certificate.instructions], ["skip", "execute"])

    def test_new_scope_is_intersection_not_privilege_rebound(self) -> None:
        certificate = self.decide().certificate
        assert certificate is not None
        self.assertEqual(certificate.grant.scope.actions, frozenset({"charge", "email"}))
        self.assertEqual(certificate.grant.scope.resources, frozenset({"acct:42"}))
        self.assertEqual(certificate.grant.scope.max_amount, 200)
        self.assertTrue(certificate.grant.scope.is_subset_of(self.previous_scope))
        self.assertTrue(certificate.grant.scope.is_subset_of(self.current_policy))

    def test_recovery_certificate_is_signed_and_publicly_verifiable(self) -> None:
        decision = self.decide()
        assert decision.certificate_envelope is not None
        self.assertTrue(self.coordinator.verify_certificate(decision.certificate_envelope))
        tampered = dataclasses.replace(
            decision.certificate_envelope,
            payload=dataclasses.replace(decision.certificate, active_epoch=999),
        )
        self.assertFalse(self.coordinator.verify_certificate(tampered))

    def test_recovery_certificate_binds_a_matching_distributed_barrier(self) -> None:
        barrier_envelope = self.barrier()
        decision = self.decide(authority_barrier_envelope=barrier_envelope)
        self.assertEqual(decision.status, RecoveryStatus.AUTHORIZED)
        assert decision.certificate is not None
        self.assertEqual(
            decision.certificate.grant.authority_barrier_digest,
            digest(barrier_envelope.payload),
        )

        attacks = {
            "wrong_incident": self.barrier(incident_id="inc-other"),
            "missing_provider": self.barrier(
                provider_ids=("provider-a",),
                acknowledgement_digests=(digest({"provider": "provider-a"}),),
            ),
            "wrong_epoch": self.barrier(active_epoch=9),
            "future": self.barrier(formed_at=1_021),
            "forged": self.untrusted.sign(
                "authority_barrier", barrier_envelope.payload
            ),
        }
        for name, attack in attacks.items():
            with self.subTest(attack=name):
                rejected = self.decide(authority_barrier_envelope=attack)
                self.assertEqual(rejected.status, RecoveryStatus.QUARANTINED)

    def test_unresolved_carrier_fails_closed(self) -> None:
        closure = dataclasses.replace(
            self.closure,
            closed_carriers=("credential:7", "queue:q1"),
            unresolved_carriers=("callback:c1",),
        )
        decision = self.decide(closure_envelope=self.closure_signer.sign("closure", closure))
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("old_authority_not_proven_closed", decision.reasons)

    def test_indeterminate_closure_fails_closed(self) -> None:
        closure = dataclasses.replace(self.closure, verdict=ClosureVerdict.INDETERMINATE)
        decision = self.decide(closure_envelope=self.closure_signer.sign("closure", closure))
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)

    def test_stale_attestation_fails_closed(self) -> None:
        decision = self.decide(now=self.attestation.expires_at)
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("stale_or_unbound_attestation", decision.reasons)

    def test_nonce_mismatch_fails_closed(self) -> None:
        decision = self.decide(expected_nonce="different")
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)

    def test_preincident_attestation_fails_closed(self) -> None:
        attestation = dataclasses.replace(self.attestation, issued_at=self.incident.declared_at)
        decision = self.decide(
            attestation_envelope=self.attestation_signer.sign("attestation", attestation)
        )
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("attestation_not_post_incident", decision.reasons)

    def test_unapproved_manifest_fails_closed(self) -> None:
        attestation = dataclasses.replace(self.attestation, manifest_hash="manifest:unknown")
        decision = self.decide(
            attestation_envelope=self.attestation_signer.sign("attestation", attestation)
        )
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("unapproved_manifest", decision.reasons)

    def test_ambiguous_effect_blocks_resume(self) -> None:
        ambiguous = dataclasses.replace(self.records[1], state=EffectState.AMBIGUOUS)
        decision = self.decide(
            reconciliation_envelopes=(
                self.provider_a.sign("reconciliation", self.records[0]),
                self.provider_b.sign("reconciliation", ambiguous),
            )
        )
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("ambiguous_effect:email", decision.reasons)

    def test_missing_provider_record_blocks_resume(self) -> None:
        decision = self.decide(
            reconciliation_envelopes=(self.provider_a.sign("reconciliation", self.records[0]),)
        )
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("missing_reconciliation:email", decision.reasons)

    def test_forged_provider_record_is_rejected(self) -> None:
        decision = self.decide(
            reconciliation_envelopes=(
                self.provider_a.sign("reconciliation", self.records[0]),
                self.untrusted.sign("reconciliation", self.records[1]),
            )
        )
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("invalid_provider_evidence", decision.reasons)

    def test_provider_cannot_sign_for_another_provider(self) -> None:
        decision = self.decide(
            reconciliation_envelopes=(
                self.provider_a.sign("reconciliation", self.records[0]),
                self.provider_a.sign("reconciliation", self.records[1]),
            )
        )
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("provider_identity_mismatch", decision.reasons)

    def test_non_monotonic_epoch_is_rejected(self) -> None:
        attestation = dataclasses.replace(self.attestation, new_epoch=7)
        decision = self.decide(
            attestation_envelope=self.attestation_signer.sign("attestation", attestation)
        )
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("non_monotonic_epoch", decision.reasons)

    def test_tampering_after_signature_is_rejected(self) -> None:
        envelope = self.closure_signer.sign("closure", self.closure)
        tampered = dataclasses.replace(
            envelope,
            payload=dataclasses.replace(self.closure, closed_carriers=()),
        )
        decision = self.decide(closure_envelope=tampered)
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("invalid_closure_evidence", decision.reasons)

    def test_old_and_new_epochs_never_overlap(self) -> None:
        decision = self.decide()
        certificate = decision.certificate
        assert certificate is not None
        self.assertFalse(self.registry.is_authorized("agent/payments", 7))
        self.registry.activate("agent/payments", certificate.active_epoch)
        self.assertFalse(self.registry.is_authorized("agent/payments", 7))
        self.assertTrue(self.registry.is_authorized("agent/payments", 8))

    def test_recovery_is_rejected_while_old_epoch_remains_active(self) -> None:
        registry = AuthorityRegistry()
        registry.establish("agent/payments", 7)
        coordinator = RecoveryCoordinator(self.trust, registry, self.recovery_signer)
        original = self.coordinator
        self.coordinator = coordinator
        try:
            decision = self.decide()
        finally:
            self.coordinator = original
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("authority_overlap", decision.reasons)

    def test_retired_epoch_cannot_be_reactivated(self) -> None:
        with self.assertRaises(ValueError):
            self.registry.activate("agent/payments", 7)

    def test_decision_is_deterministic(self) -> None:
        first = self.decide()
        second = self.decide()
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
