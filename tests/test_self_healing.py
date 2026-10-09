from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

from ztai import (
    AuthorityTransition,
    DurableAuthorityProvider,
    Ed25519Signer,
    ProviderDatabase,
    ProviderTransitionResult,
    RecoveryStatus,
    SelfHealingAuthorityController,
    TrustStore,
    make_provider_key_rotation_attestation,
)


class UnavailableProvider:
    provider_id = "payment"

    def apply_transition(self, transition_envelope, *, now: int):
        raise TimeoutError(self.provider_id)


class ConflictingProvider:
    def __init__(self, inner: DurableAuthorityProvider, signer: Ed25519Signer) -> None:
        self.provider_id = inner.provider_id
        self.inner = inner
        self.signer = signer

    def apply_transition(self, transition_envelope, *, now: int):
        result = self.inner.apply_transition(transition_envelope, now=now)
        assert result.acknowledgement_envelope is not None
        acknowledgement = dataclasses.replace(
            result.acknowledgement_envelope.payload,
            active_epoch=result.acknowledgement_envelope.payload.active_epoch + 1,
        )
        return ProviderTransitionResult(
            True,
            "conflicting_ack",
            self.signer.sign("authority_transition_ack", acknowledgement),
        )


class SelfHealingAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = ProviderDatabase(
            Path(self.temporary_directory.name) / "payment.sqlite3"
        )
        self.database.establish_epoch("agent/healing", 7, 900)
        self.transition_signer = Ed25519Signer("authority-control")
        self.barrier_signer = Ed25519Signer("barrier-control")
        self.audit_signer = Ed25519Signer("healing-control")
        self.key_attestation_signer = Ed25519Signer("key-attestation-control")
        self.provider_signer = Ed25519Signer("payment")
        self.trust = TrustStore()
        for role, signer in (
            ("authority_transition_authority", self.transition_signer),
            ("authority_barrier_authority", self.barrier_signer),
            ("self_healing_authority", self.audit_signer),
            ("provider_key_attestation_authority", self.key_attestation_signer),
            ("effect_provider", self.provider_signer),
        ):
            self.trust.register(role, signer)
        self.transition = AuthorityTransition(
            "transition-healing",
            "incident-healing",
            "agent/healing",
            1,
            7,
            8,
            ("payment",),
            1_000,
        )
        self.transition_envelope = self.transition_signer.sign(
            "authority_transition", self.transition
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def durable(self, signer: Ed25519Signer | None = None):
        return DurableAuthorityProvider(
            "payment",
            self.database,
            self.trust,
            signer or self.provider_signer,
        )

    def controller(self, provider, **changes):
        values = {
            "trust_store": self.trust,
            "providers": {"payment": provider},
            "barrier_signer": self.barrier_signer,
            "audit_signer": self.audit_signer,
        }
        values.update(changes)
        return SelfHealingAuthorityController(**values)

    def test_transport_failure_restarts_provider_and_records_signed_audit(self) -> None:
        durable = self.durable()
        controller = self.controller(
            UnavailableProvider(),
            repair_provider=lambda provider_id, action: durable,
        )
        result = controller.recover(self.transition_envelope, now=1_001)

        self.assertEqual(result.decision.status, RecoveryStatus.AUTHORIZED)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(
            tuple(event.action for event in result.repair_events),
            ("retry_or_restart_transport",),
        )
        self.assertTrue(controller.verify_result(result, self.transition_envelope))
        tampered_certificate = dataclasses.replace(
            result.certificate_envelope.payload,
            attempts=result.attempts + 1,
        )
        tampered_result = dataclasses.replace(
            result,
            certificate_envelope=dataclasses.replace(
                result.certificate_envelope,
                payload=tampered_certificate,
            ),
        )
        self.assertFalse(
            controller.verify_result(tampered_result, self.transition_envelope)
        )

    def test_fresh_attested_key_rotation_is_the_only_auto_trusted_rotation(self) -> None:
        rotated = Ed25519Signer("payment")
        attestation = make_provider_key_rotation_attestation(
            attestation_signer=self.key_attestation_signer,
            provider_id="payment",
            transition=self.transition,
            previous_key_fingerprint=self.provider_signer.public_key_fingerprint,
            new_signer=rotated,
            issued_at=1_000,
            expires_at=1_100,
            rotation_id="rotation-001",
        )
        controller = self.controller(self.durable(rotated))
        result = controller.recover(
            self.transition_envelope,
            now=1_001,
            rotation_attestations={"payment": attestation},
        )

        self.assertEqual(result.decision.status, RecoveryStatus.AUTHORIZED)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(
            result.repair_events[0].action,
            "accept_attested_key_rotation",
        )
        self.assertEqual(
            self.trust.public_key_fingerprint("effect_provider", "payment"),
            rotated.public_key_fingerprint,
        )
        self.assertTrue(controller.verify_result(result, self.transition_envelope))

    def test_invalid_rotation_attestations_remain_quarantined(self) -> None:
        rotated = Ed25519Signer("payment")
        valid = make_provider_key_rotation_attestation(
            attestation_signer=self.key_attestation_signer,
            provider_id="payment",
            transition=self.transition,
            previous_key_fingerprint=self.provider_signer.public_key_fingerprint,
            new_signer=rotated,
            issued_at=1_000,
            expires_at=1_100,
            rotation_id="rotation-001",
        )
        attacker = Ed25519Signer("attacker")
        attacks = {
            "missing": None,
            "forged": attacker.sign(
                "provider_key_rotation_attestation", valid.payload
            ),
            "expired": self.key_attestation_signer.sign(
                "provider_key_rotation_attestation",
                dataclasses.replace(valid.payload, expires_at=1_000),
            ),
            "wrong_transition": self.key_attestation_signer.sign(
                "provider_key_rotation_attestation",
                dataclasses.replace(valid.payload, transition_id="other"),
            ),
        }
        for name, attestation in attacks.items():
            with self.subTest(attack=name):
                controller = self.controller(self.durable(rotated))
                evidence = {} if attestation is None else {"payment": attestation}
                result = controller.recover(
                    self.transition_envelope,
                    now=1_001,
                    rotation_attestations=evidence,
                )
                self.assertEqual(
                    result.decision.status, RecoveryStatus.QUARANTINED
                )
                self.assertEqual(
                    result.repair_events[0].action,
                    "reject_unattested_key_rotation",
                )
                self.assertEqual(
                    self.trust.public_key_fingerprint(
                        "effect_provider", "payment"
                    ),
                    self.provider_signer.public_key_fingerprint,
                )

    def test_conflicting_evidence_and_permanent_outage_do_not_release(self) -> None:
        conflicting = self.controller(
            ConflictingProvider(self.durable(), self.provider_signer)
        ).recover(self.transition_envelope, now=1_001)
        self.assertEqual(
            conflicting.decision.status, RecoveryStatus.QUARANTINED
        )
        self.assertEqual(conflicting.repair_events, ())

        permanent = UnavailableProvider()
        controller = self.controller(
            permanent,
            repair_provider=lambda provider_id, action: permanent,
            max_attempts=3,
        )
        result = controller.recover(self.transition_envelope, now=1_001)
        self.assertEqual(result.decision.status, RecoveryStatus.QUARANTINED)
        self.assertEqual(result.attempts, 3)
        self.assertEqual(len(result.repair_events), 2)
        self.assertTrue(controller.verify_result(result, self.transition_envelope))


if __name__ == "__main__":
    unittest.main()
