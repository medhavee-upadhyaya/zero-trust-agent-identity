from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

from ztai import (
    AuthorityTransition,
    DistributedAuthorityCoordinator,
    DurableAuthorityProvider,
    Ed25519Signer,
    EffectRequest,
    ProviderDatabase,
    ProviderTransitionResult,
    RecoveryStatus,
    TrustStore,
)


class UnavailableProvider:
    def __init__(self, provider_id: str) -> None:
        self.provider_id = provider_id

    def apply_transition(self, transition_envelope, *, now: int):
        raise TimeoutError(self.provider_id)


class ConflictingAcknowledgementProvider:
    def __init__(self, inner: DurableAuthorityProvider, signer: Ed25519Signer) -> None:
        self.provider_id = inner.provider_id
        self.inner = inner
        self.signer = signer

    def apply_transition(self, transition_envelope, *, now: int):
        result = self.inner.apply_transition(transition_envelope, now=now)
        assert result.acknowledgement_envelope is not None
        acknowledgement = dataclasses.replace(
            result.acknowledgement_envelope.payload,
            version=result.acknowledgement_envelope.payload.version + 1,
        )
        return ProviderTransitionResult(
            True,
            "forged_conflict",
            self.signer.sign("authority_transition_ack", acknowledgement),
        )


class WrongProviderSigner:
    def __init__(self, inner: DurableAuthorityProvider, signer: Ed25519Signer) -> None:
        self.provider_id = inner.provider_id
        self.inner = inner
        self.signer = signer

    def apply_transition(self, transition_envelope, *, now: int):
        result = self.inner.apply_transition(transition_envelope, now=now)
        assert result.acknowledgement_envelope is not None
        return ProviderTransitionResult(
            True,
            "wrong_provider_signer",
            self.signer.sign(
                "authority_transition_ack",
                result.acknowledgement_envelope.payload,
            ),
        )


class DistributedAuthorityTests(unittest.TestCase):
    PROVIDERS = ("callback", "inventory", "notification", "payment")

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        self.workload_id = "agent/orders"
        self.old_epoch = 7
        self.new_epoch = 8
        self.transition_signer = Ed25519Signer("authority-control")
        self.barrier_signer = Ed25519Signer("barrier-control")
        self.provider_signers = {
            provider_id: Ed25519Signer(provider_id) for provider_id in self.PROVIDERS
        }
        self.trust = TrustStore()
        self.trust.register("authority_transition_authority", self.transition_signer)
        self.trust.register("authority_barrier_authority", self.barrier_signer)
        for signer in self.provider_signers.values():
            self.trust.register("effect_provider", signer)

        self.databases = {
            provider_id: ProviderDatabase(root / f"{provider_id}.sqlite3")
            for provider_id in self.PROVIDERS
        }
        for database in self.databases.values():
            database.establish_epoch(self.workload_id, self.old_epoch, 900)
        self.providers = {
            provider_id: DurableAuthorityProvider(
                provider_id,
                self.databases[provider_id],
                self.trust,
                self.provider_signers[provider_id],
            )
            for provider_id in self.PROVIDERS
        }

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def transition(self, **changes):
        value = AuthorityTransition(
            "transition-001",
            "incident-001",
            self.workload_id,
            1,
            self.old_epoch,
            self.new_epoch,
            self.PROVIDERS,
            1_000,
        )
        return self.transition_signer.sign(
            "authority_transition", dataclasses.replace(value, **changes)
        )

    def coordinator(self, providers=None) -> DistributedAuthorityCoordinator:
        return DistributedAuthorityCoordinator(
            trust_store=self.trust,
            providers=self.providers if providers is None else providers,
            barrier_signer=self.barrier_signer,
        )

    def old_request(self, provider_id: str) -> EffectRequest:
        return EffectRequest(
            "incident-001",
            f"old-{provider_id}",
            self.workload_id,
            self.old_epoch,
            f"op:old:{provider_id}",
            f"old:{provider_id}:epoch:{self.old_epoch}",
        )

    def test_complete_signed_barrier_closes_old_authority_at_every_provider(self) -> None:
        coordinator = self.coordinator()
        decision = coordinator.establish_barrier(self.transition(), now=1_001)

        self.assertEqual(decision.status, RecoveryStatus.AUTHORIZED)
        self.assertEqual(len(decision.acknowledgement_envelopes), 4)
        self.assertTrue(coordinator.verify_barrier(decision))
        for provider_id, database in self.databases.items():
            self.assertEqual(database.epoch_state(self.workload_id, self.old_epoch), "retired")
            self.assertEqual(database.active_epoch(self.workload_id), self.new_epoch)
            status, body = database.apply_effect(self.old_request(provider_id))
            self.assertEqual(status, 403)
            self.assertEqual(body["reason"], "inactive_epoch")

    def test_missing_or_unavailable_provider_quarantines_without_barrier(self) -> None:
        for mode in ("missing", "unavailable"):
            with self.subTest(mode=mode):
                providers = dict(self.providers)
                if mode == "missing":
                    del providers["callback"]
                else:
                    providers["callback"] = UnavailableProvider("callback")
                decision = self.coordinator(providers).establish_barrier(
                    self.transition(transition_id=f"transition-{mode}"),
                    now=1_001,
                )
                self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
                self.assertIsNone(decision.barrier_envelope)
                self.assertTrue(
                    any("callback" in reason for reason in decision.reasons),
                    decision.reasons,
                )

    def test_signed_but_conflicting_acknowledgement_is_rejected(self) -> None:
        providers = dict(self.providers)
        providers["payment"] = ConflictingAcknowledgementProvider(
            self.providers["payment"], self.provider_signers["payment"]
        )
        decision = self.coordinator(providers).establish_barrier(
            self.transition(), now=1_001
        )
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("conflicting_ack:payment", decision.reasons)
        self.assertIsNone(decision.barrier_envelope)

    def test_registered_provider_cannot_acknowledge_for_another_provider(self) -> None:
        providers = dict(self.providers)
        providers["payment"] = WrongProviderSigner(
            self.providers["payment"], self.provider_signers["inventory"]
        )
        decision = self.coordinator(providers).establish_barrier(
            self.transition(), now=1_001
        )
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("invalid_ack_signer:payment", decision.reasons)
        self.assertIsNone(decision.barrier_envelope)

    def test_transition_survives_restart_and_replay_is_idempotent(self) -> None:
        transition = self.transition()
        first = self.coordinator().establish_barrier(transition, now=1_001)
        self.assertEqual(first.status, RecoveryStatus.AUTHORIZED)

        restarted = {
            provider_id: DurableAuthorityProvider(
                provider_id,
                ProviderDatabase(database.path),
                self.trust,
                self.provider_signers[provider_id],
            )
            for provider_id, database in self.databases.items()
        }
        second = self.coordinator(restarted).establish_barrier(transition, now=1_100)
        self.assertEqual(second.status, RecoveryStatus.AUTHORIZED)
        self.assertTrue(self.coordinator(restarted).verify_barrier(second))
        for provider in restarted.values():
            result = provider.apply_transition(transition, now=1_101)
            self.assertTrue(result.accepted)
            self.assertTrue(result.replayed)

    def test_stale_and_conflicting_transitions_cannot_replace_current_state(self) -> None:
        first = self.coordinator().establish_barrier(self.transition(), now=1_001)
        self.assertEqual(first.status, RecoveryStatus.AUTHORIZED)

        conflicting = self.transition(transition_id="different-transition")
        conflict = self.coordinator().establish_barrier(conflicting, now=1_002)
        self.assertEqual(conflict.status, RecoveryStatus.QUARANTINED)
        self.assertEqual(len(conflict.acknowledgement_envelopes), 0)
        self.assertTrue(
            all("conflicting_transition" in reason for reason in conflict.reasons)
        )

        next_transition = self.transition(
            transition_id="transition-002",
            incident_id="incident-002",
            version=2,
            retired_epoch=8,
            active_epoch=9,
            issued_at=1_010,
        )
        second = self.coordinator().establish_barrier(next_transition, now=1_011)
        self.assertEqual(second.status, RecoveryStatus.AUTHORIZED)
        stale = self.coordinator().establish_barrier(self.transition(), now=1_012)
        self.assertEqual(stale.status, RecoveryStatus.QUARANTINED)
        self.assertTrue(all("stale_transition" in reason for reason in stale.reasons))
        for database in self.databases.values():
            self.assertEqual(database.active_epoch(self.workload_id), 9)

    def test_invalid_transition_signature_and_noncanonical_provider_set_fail_closed(self) -> None:
        attacker = Ed25519Signer("attacker")
        forged = attacker.sign("authority_transition", self.transition().payload)
        decision = self.coordinator().establish_barrier(forged, now=1_001)
        self.assertEqual(decision.reasons, ("invalid_transition_signature",))

        malformed = self.transition(provider_ids=("payment", "payment"))
        decision = self.coordinator().establish_barrier(malformed, now=1_001)
        self.assertEqual(decision.status, RecoveryStatus.QUARANTINED)
        self.assertIn("noncanonical_provider_set", decision.reasons)


if __name__ == "__main__":
    unittest.main()
