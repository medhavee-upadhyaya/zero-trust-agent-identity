from __future__ import annotations

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ztai import (
    Attestation,
    AuthorityRegistry,
    ClosureCertificate,
    ClosureVerdict,
    Ed25519Signer,
    EffectRequest,
    EffectState,
    ProviderClient,
    ProviderDatabase,
    ProviderProcess,
    Incident,
    RecoveryCoordinator,
    RecoveryStatus,
    Scope,
    Step,
    TrustStore,
)


class DurableProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "provider.sqlite3"
        self.signer = Ed25519Signer("provider-a")
        self.trust = TrustStore()
        self.trust.register("provider", self.signer)
        self.database = ProviderDatabase(self.database_path)
        self.database.establish_epoch("agent/payments", 7, 1_000)
        self.provider = ProviderProcess(
            self.database_path, self.signer, enable_faults=True
        ).start()
        self.client = ProviderClient(self.provider.base_url)

    def tearDown(self) -> None:
        self.provider.stop()
        self.temporary_directory.cleanup()

    def request(
        self,
        *,
        epoch: int = 7,
        step_id: str = "charge",
        operation_digest: str = "op:charge:42",
        idempotency_key: str = "inc-001:charge:epoch-7",
    ) -> EffectRequest:
        return EffectRequest(
            incident_id="inc-001",
            step_id=step_id,
            workload_id="agent/payments",
            epoch=epoch,
            operation_digest=operation_digest,
            idempotency_key=idempotency_key,
        )

    def assert_valid_outcome(self, outcome, state: EffectState) -> None:
        self.assertEqual(outcome.status, state.value)
        self.assertIsNotNone(outcome.envelope)
        assert outcome.envelope is not None
        self.assertEqual(outcome.envelope.payload.state, state)
        self.assertTrue(self.trust.verify("provider", outcome.envelope, "reconciliation"))

    def test_normal_commit_has_signed_committed_outcome(self) -> None:
        result = self.client.execute(self.request())
        self.assertEqual(result.status, "committed")
        self.assertFalse(result.replayed)
        self.assert_valid_outcome(
            self.client.reconcile(self.request(), create_fence=True), EffectState.COMMITTED
        )
        self.assertEqual(self.database.effect_count(), 1)

    def test_idempotent_transport_replay_does_not_duplicate_effect(self) -> None:
        first = self.client.execute(self.request())
        second = self.client.execute(self.request())
        self.assertEqual(first.status, "committed")
        self.assertEqual(second.status, "committed")
        self.assertTrue(second.replayed)
        self.assertEqual(self.database.effect_count(), 1)

    def test_same_key_with_different_operation_is_rejected(self) -> None:
        self.assertEqual(self.client.execute(self.request()).status, "committed")
        collision = self.client.execute(self.request(operation_digest="op:charge:99"))
        self.assertEqual(collision.http_status, 409)
        self.assertEqual(collision.reason, "idempotency_collision")
        self.assertEqual(self.database.effect_count(), 1)

    def test_fault_injection_is_disabled_by_default(self) -> None:
        self.provider.stop()
        self.provider = ProviderProcess(self.database_path, self.signer).start()
        self.client = ProviderClient(self.provider.base_url)
        result = self.client.execute(self.request(), fault="crash_before_commit")
        self.assertEqual(result.http_status, 403)
        self.assertEqual(result.reason, "fault_injection_disabled")
        assert self.provider.process is not None
        self.assertTrue(self.provider.process.is_alive())
        self.assertEqual(self.database.effect_count(), 0)

    def test_crash_after_commit_reconciles_as_committed(self) -> None:
        result = self.client.execute(self.request(), fault="crash_after_commit")
        self.assertEqual(result.status, "ambiguous")
        self.provider.process.join(2)
        self.assertFalse(self.provider.process.is_alive())
        self.provider.restart()
        self.client = ProviderClient(self.provider.base_url)
        self.assert_valid_outcome(
            self.client.reconcile(self.request(), create_fence=True), EffectState.COMMITTED
        )
        self.assertEqual(self.database.effect_count(), 1)

    def test_crash_before_commit_creates_durable_no_effect_fence(self) -> None:
        result = self.client.execute(self.request(), fault="crash_before_commit")
        self.assertEqual(result.status, "ambiguous")
        self.provider.process.join(2)
        self.assertFalse(self.provider.process.is_alive())
        self.provider.restart()
        self.client = ProviderClient(self.provider.base_url)
        outcome = self.client.reconcile(self.request(), create_fence=True)
        self.assert_valid_outcome(outcome, EffectState.NO_EFFECT)

        self.provider.restart()
        self.client = ProviderClient(self.provider.base_url)
        retry = self.client.execute(self.request())
        self.assertEqual(retry.http_status, 409)
        self.assertEqual(retry.reason, "delivery_fenced")
        self.assertEqual(self.database.effect_count(), 0)

    def test_recovery_uses_new_epoch_and_new_delivery_identity(self) -> None:
        self.assertEqual(
            self.client.execute(self.request(), fault="drop_before_commit").status,
            "ambiguous",
        )
        self.assert_valid_outcome(
            self.client.reconcile(self.request(), create_fence=True), EffectState.NO_EFFECT
        )
        self.assertTrue(self.database.retire_epoch("agent/payments", 7, 1_010))
        self.assertTrue(self.database.activate_epoch("agent/payments", 8, 1_020))

        successor = self.request(epoch=8, idempotency_key="inc-001:charge:epoch-8")
        self.assertEqual(self.client.execute(successor).status, "committed")
        self.assertEqual(self.database.effect_count(), 1)

        rejected_old = self.client.execute(
            self.request(step_id="later", idempotency_key="inc-001:later:epoch-7")
        )
        self.assertEqual(rejected_old.http_status, 403)
        self.assertEqual(rejected_old.reason, "inactive_epoch")

    def test_provider_evidence_drives_end_to_end_recovery(self) -> None:
        old_request = self.request()
        self.assertEqual(
            self.client.execute(old_request, fault="crash_before_commit").status,
            "ambiguous",
        )
        self.provider.restart()
        self.client = ProviderClient(self.provider.base_url)
        outcome = self.client.reconcile(old_request, create_fence=True)
        self.assert_valid_outcome(outcome, EffectState.NO_EFFECT)
        assert outcome.envelope is not None

        incident_signer = Ed25519Signer("incident-control")
        closure_signer = Ed25519Signer("closure-verifier")
        attestation_signer = Ed25519Signer("rats-verifier")
        recovery_signer = Ed25519Signer("recovery-control")
        for role, signer in (
            ("incident_authority", incident_signer),
            ("closure_authority", closure_signer),
            ("attestation_verifier", attestation_signer),
            ("recovery_authority", recovery_signer),
        ):
            self.trust.register(role, signer)

        registry = AuthorityRegistry()
        registry.establish("agent/payments", 7)
        registry.retire("agent/payments", 7)
        self.assertTrue(self.database.retire_epoch("agent/payments", 7, 1_010))
        coordinator = RecoveryCoordinator(self.trust, registry, recovery_signer)
        incident = Incident("inc-001", "agent/payments", 7, 1_000, "runtime_compromise")
        closure = ClosureCertificate(
            "inc-001",
            "agent/payments",
            7,
            ClosureVerdict.QUIESCENT,
            ("credential:7", "provider-delivery:7"),
            ("credential:7", "provider-delivery:7"),
        )
        attestation = Attestation(
            "agent/payments",
            "instance-repaired-1",
            8,
            "pk:8",
            "manifest:approved",
            "config:approved",
            "nonce-001",
            1_020,
            1_100,
        )
        decision = coordinator.evaluate(
            incident_envelope=incident_signer.sign("incident", incident),
            closure_envelope=closure_signer.sign("closure", closure),
            attestation_envelope=attestation_signer.sign("attestation", attestation),
            reconciliation_envelopes=(outcome.envelope,),
            previous_scope=Scope.of({"charge", "refund"}, {"acct:42"}, 500),
            current_policy=Scope.of({"charge"}, {"acct:42"}, 200),
            steps=(Step("charge", "provider-a", "op:charge:42", False),),
            expected_nonce="nonce-001",
            approved_manifest_hashes=frozenset({"manifest:approved"}),
            approved_configuration_hashes=frozenset({"config:approved"}),
            now=1_030,
            grant_id="grant-008",
        )
        self.assertEqual(decision.status, RecoveryStatus.AUTHORIZED)
        assert decision.certificate is not None
        self.assertEqual(decision.certificate.instructions[0].action, "execute")
        self.assertTrue(self.database.activate_epoch("agent/payments", 8, 1_040))
        registry.activate("agent/payments", 8)

        successor = self.request(epoch=8, idempotency_key="inc-001:charge:epoch-8")
        self.assertEqual(self.client.execute(successor).status, "committed")
        self.assertEqual(self.database.effect_count("inc-001", "charge"), 1)

    def test_reconciliation_binding_mismatch_returns_no_evidence(self) -> None:
        self.assertEqual(self.client.execute(self.request()).status, "committed")
        mismatched = self.client.reconcile(
            self.request(operation_digest="different-operation"), create_fence=True
        )
        self.assertEqual(mismatched.status, "unknown")
        self.assertIsNone(mismatched.envelope)

    def test_reconciliation_fence_linearizes_against_concurrent_delivery(self) -> None:
        for trial in range(50):
            request = self.request(
                step_id=f"race-{trial}",
                operation_digest=f"op:race:{trial}",
                idempotency_key=f"inc-001:race:{trial}:epoch-7",
            )
            with ThreadPoolExecutor(max_workers=2) as executor:
                execute_future = executor.submit(self.client.execute, request)
                reconcile_future = executor.submit(self.client.reconcile, request, True)
                execution = execute_future.result(timeout=3)
                outcome = reconcile_future.result(timeout=3)

            self.assertIn(outcome.status, {"committed", "no_effect"})
            self.assert_valid_outcome(outcome, EffectState(outcome.status))
            if outcome.status == "committed":
                self.assertEqual(execution.status, "committed")
                self.assertEqual(self.database.effect_count("inc-001", request.step_id), 1)
            else:
                self.assertEqual(execution.reason, "delivery_fenced")
                self.assertEqual(self.database.effect_count("inc-001", request.step_id), 0)
                late = self.client.execute(request)
                self.assertEqual(late.reason, "delivery_fenced")


if __name__ == "__main__":
    unittest.main()
