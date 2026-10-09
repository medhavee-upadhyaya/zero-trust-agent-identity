from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

from ztai import (
    ClosureCertificate,
    DistributedAuthorityCoordinator,
    DurableAuthorityProvider,
    Ed25519Signer,
    ProviderBinding,
    ProviderClient,
    ProviderDatabase,
    ProviderProcess,
    RecoveryStatus,
    Scope,
    TrustStore,
    WorkflowRecoveryEngine,
    WorkflowStepSpec,
    WorkflowStore,
)


class MultiProviderWorkflowTests(unittest.TestCase):
    PROVIDERS = ("payment", "inventory", "notification", "callback")

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        self.workflow_id = "workflow-001"
        self.incident_id = "incident-001"
        self.workload_id = "agent/orders"
        self.old_epoch = 7
        self.new_epoch = 8
        self.store_path = root / "workflow.sqlite3"
        self.store = WorkflowStore(self.store_path)
        self.steps = tuple(
            WorkflowStepSpec(position, step_id, provider_id, f"op:{step_id}:42", idempotent)
            for position, (step_id, provider_id, idempotent) in enumerate(
                (
                    ("charge", "payment", False),
                    ("reserve", "inventory", False),
                    ("notify", "notification", True),
                    ("callback", "callback", False),
                )
            )
        )
        self.store.create_workflow(
            workflow_id=self.workflow_id,
            incident_id=self.incident_id,
            workload_id=self.workload_id,
            old_epoch=self.old_epoch,
            new_epoch=self.new_epoch,
            steps=self.steps,
            now=1_000,
        )

        self.provider_signers: dict[str, Ed25519Signer] = {}
        self.provider_databases: dict[str, ProviderDatabase] = {}
        self.provider_processes: dict[str, ProviderProcess] = {}
        for provider_id in self.PROVIDERS:
            signer = Ed25519Signer(provider_id)
            database = ProviderDatabase(root / f"{provider_id}.sqlite3")
            database.establish_epoch(self.workload_id, self.old_epoch, 900)
            process = ProviderProcess(database.path, signer, enable_faults=True).start()
            self.provider_signers[provider_id] = signer
            self.provider_databases[provider_id] = database
            self.provider_processes[provider_id] = process

        self.incident_signer = Ed25519Signer("incident-control")
        self.closure_signer = Ed25519Signer("closure-verifier")
        self.attestation_signer = Ed25519Signer("rats-verifier")
        self.recovery_signer = Ed25519Signer("recovery-control")
        self.trust = TrustStore()
        for role, signer in (
            ("incident_authority", self.incident_signer),
            ("closure_authority", self.closure_signer),
            ("attestation_verifier", self.attestation_signer),
            ("recovery_authority", self.recovery_signer),
        ):
            self.trust.register(role, signer)
        for signer in self.provider_signers.values():
            self.trust.register("provider", signer)

    def tearDown(self) -> None:
        for process in self.provider_processes.values():
            process.stop()
        self.temporary_directory.cleanup()

    def engine(self, **options) -> WorkflowRecoveryEngine:
        bindings = {
            provider_id: ProviderBinding(
                provider_id,
                self.provider_databases[provider_id],
                ProviderClient(self.provider_processes[provider_id].base_url, timeout=0.25),
            )
            for provider_id in self.PROVIDERS
        }
        return WorkflowRecoveryEngine(
            store=self.store,
            providers=bindings,
            trust_store=self.trust,
            incident_signer=self.incident_signer,
            closure_signer=self.closure_signer,
            attestation_signer=self.attestation_signer,
            recovery_signer=self.recovery_signer,
            **options,
        )

    def recover(self, engine: WorkflowRecoveryEngine | None = None):
        return (engine or self.engine()).recover(
            workflow_id=self.workflow_id,
            previous_scope=Scope.of(
                {"charge", "reserve", "notify", "callback", "refund"},
                {"order:42"},
                500,
            ),
            current_policy=Scope.of(
                {"charge", "reserve", "notify", "callback"},
                {"order:42"},
                200,
            ),
            manifest_hash="manifest:approved",
            configuration_hash="config:approved",
            approved_manifest_hashes=frozenset({"manifest:approved"}),
            approved_configuration_hashes=frozenset({"config:approved"}),
            expected_nonce="nonce-001",
            now=1_100,
        )

    def enqueue_old(self, step_id: str, message_id: str, *, available_at: int = 1_000) -> None:
        step = {item.step_id: item for item in self.steps}[step_id]
        engine = self.engine()
        self.store.enqueue(
            message_id=message_id,
            workflow_id=self.workflow_id,
            provider_id=step.provider_id,
            request=engine.old_request(self.workflow_id, step_id),
            available_at=available_at,
        )

    def assert_exactly_once(self) -> None:
        for step in self.steps:
            count = self.provider_databases[step.provider_id].effect_count(
                self.incident_id, step.step_id
            )
            self.assertEqual(count, 1, step.step_id)

    def assert_old_epoch_rejected(self) -> None:
        engine = self.engine()
        for step in self.steps:
            result = ProviderClient(
                self.provider_processes[step.provider_id].base_url
            ).execute(engine.old_request(self.workflow_id, step.step_id))
            self.assertEqual(result.reason, "inactive_epoch", step.step_id)

    def test_recovers_full_workflow_after_postcommit_crash(self) -> None:
        engine = self.engine()
        charge = engine.old_request(self.workflow_id, "charge")
        self.assertEqual(
            engine.providers["payment"].client.execute(charge).status, "committed"
        )
        self.store.set_step_state(self.workflow_id, "charge", "committed")

        self.enqueue_old("reserve", "message-reserve")
        attempt = self.store.deliver(
            "message-reserve",
            engine.providers["inventory"].client,
            now=1_001,
            fault="crash_after_commit",
        )
        self.assertEqual(attempt.queue_status, "ambiguous")
        self.provider_processes["inventory"].restart()

        self.enqueue_old("notify", "message-notify-a", available_at=9_999)
        self.enqueue_old("notify", "message-notify-b", available_at=9_999)
        self.enqueue_old("callback", "message-callback", available_at=9_999)
        self.assertEqual(self.store.restart_controller(self.workflow_id, 1_050), 1)
        self.store = WorkflowStore(self.store_path)

        result = self.recover()
        self.assertEqual(result.status, RecoveryStatus.AUTHORIZED)
        self.assertEqual(
            result.completed_steps,
            ("charge", "reserve", "notify", "callback"),
        )
        assert result.decision.certificate_envelope is not None
        self.assertTrue(
            self.trust.verify(
                "recovery_authority",
                result.decision.certificate_envelope,
                "recovery_certificate",
            )
        )
        self.assertIsInstance(result.closure_envelope.payload, ClosureCertificate)
        closure = result.closure_envelope.payload
        assert isinstance(closure, ClosureCertificate)
        self.assertTrue(closure.is_positive())
        self.assertIn("queue:message-notify-a", closure.inventoried_carriers)
        self.assertIn("queue:message-callback", closure.closed_carriers)
        self.assert_exactly_once()
        self.assert_old_epoch_rejected()
        for delivery in self.store.deliveries(self.workflow_id):
            if delivery.message_id != "message-reserve":
                self.assertEqual(delivery.state, "canceled")

    def test_recovers_full_workflow_after_precommit_crash(self) -> None:
        self.enqueue_old("charge", "message-charge")
        engine = self.engine()
        attempt = self.store.deliver(
            "message-charge",
            engine.providers["payment"].client,
            now=1_001,
            fault="crash_before_commit",
        )
        self.assertEqual(attempt.queue_status, "ambiguous")
        self.provider_processes["payment"].restart()
        result = self.recover()
        self.assertEqual(result.status, RecoveryStatus.AUTHORIZED)
        self.assert_exactly_once()

    def test_provider_outage_quarantines_then_recovers_after_restart(self) -> None:
        engine = self.engine()
        self.provider_processes["inventory"].stop()
        first = self.recover(engine)
        self.assertEqual(first.status, RecoveryStatus.QUARANTINED)
        self.assertIn("missing_reconciliation:reserve", first.reasons)
        for database in self.provider_databases.values():
            self.assertIsNone(database.active_epoch(self.workload_id))

        self.provider_processes["inventory"].start()
        self.assertEqual(self.store.restart_controller(self.workflow_id, 1_101), 1)
        second = self.recover()
        self.assertEqual(second.status, RecoveryStatus.AUTHORIZED)
        self.assert_exactly_once()

    def test_distributed_barrier_gates_successor_activation_and_survives_retry(self) -> None:
        transition_signer = Ed25519Signer("authority-control")
        barrier_signer = Ed25519Signer("barrier-control")
        self.trust.register("authority_transition_authority", transition_signer)
        self.trust.register("authority_barrier_authority", barrier_signer)
        for signer in self.provider_signers.values():
            self.trust.register("effect_provider", signer)

        available = {
            provider_id: DurableAuthorityProvider(
                provider_id,
                self.provider_databases[provider_id],
                self.trust,
                self.provider_signers[provider_id],
            )
            for provider_id in self.PROVIDERS
            if provider_id != "callback"
        }
        incomplete_gate = DistributedAuthorityCoordinator(
            trust_store=self.trust,
            providers=available,
            barrier_signer=barrier_signer,
        )
        first = self.recover(
            self.engine(
                authority_gate=incomplete_gate,
                authority_transition_signer=transition_signer,
            )
        )
        self.assertEqual(first.status, RecoveryStatus.QUARANTINED)
        self.assertIn("missing_provider:callback", first.reasons)
        self.assertIsNone(first.authority_barrier_envelope)
        self.assertIsNone(self.provider_databases["callback"].active_epoch(self.workload_id))

        complete = dict(available)
        complete["callback"] = DurableAuthorityProvider(
            "callback",
            self.provider_databases["callback"],
            self.trust,
            self.provider_signers["callback"],
        )
        complete_gate = DistributedAuthorityCoordinator(
            trust_store=self.trust,
            providers=complete,
            barrier_signer=barrier_signer,
        )
        self.store.restart_controller(self.workflow_id, 1_101)
        second = self.recover(
            self.engine(
                authority_gate=complete_gate,
                authority_transition_signer=transition_signer,
            )
        )
        self.assertEqual(second.status, RecoveryStatus.AUTHORIZED)
        self.assertIsNotNone(second.authority_barrier_envelope)
        self.assert_exactly_once()

    def test_canceled_delayed_and_duplicate_messages_cannot_execute(self) -> None:
        self.enqueue_old("notify", "message-notify-a", available_at=9_999)
        self.enqueue_old("notify", "message-notify-b", available_at=9_999)
        result = self.recover()
        self.assertEqual(result.status, RecoveryStatus.AUTHORIZED)
        client = ProviderClient(self.provider_processes["notification"].base_url)
        for message_id in ("message-notify-a", "message-notify-b"):
            attempt = self.store.deliver(message_id, client, now=10_000)
            self.assertEqual(attempt.queue_status, "canceled")
            self.assertIsNone(attempt.execution)
        self.assertEqual(
            self.provider_databases["notification"].effect_count(
                self.incident_id, "notify"
            ),
            1,
        )

    def test_workflow_journal_validates_step_binding_and_persists_generation(self) -> None:
        with self.assertRaises(ValueError):
            self.store.enqueue(
                message_id="bad-message",
                workflow_id=self.workflow_id,
                provider_id="callback",
                request=self.engine().old_request(self.workflow_id, "charge"),
                available_at=1_000,
            )
        canonical = self.engine().old_request(self.workflow_id, "charge")
        with self.assertRaises(ValueError):
            self.store.enqueue(
                message_id="wrong-epoch",
                workflow_id=self.workflow_id,
                provider_id="payment",
                request=dataclasses.replace(canonical, epoch=self.new_epoch),
                available_at=1_000,
            )
        with self.assertRaises(ValueError):
            self.store.enqueue(
                message_id="wrong-delivery-key",
                workflow_id=self.workflow_id,
                provider_id="payment",
                request=dataclasses.replace(canonical, idempotency_key="alternate-key"),
                available_at=1_000,
            )
        self.assertEqual(self.store.restart_controller(self.workflow_id, 1_010), 1)
        reopened = WorkflowStore(self.store_path)
        snapshot = reopened.snapshot(self.workflow_id)
        self.assertEqual(snapshot.controller_generation, 1)
        self.assertEqual(snapshot.declared_at, 1_000)

    def _compensation_case(self, case_number: int, fault: str, *, outage: bool = False) -> None:
        workflow_id = f"compensation-{case_number}"
        incident_id = f"compensation-incident-{case_number}"
        workload_id = f"agent/compensation/{case_number}"
        old_epoch = 100 + case_number * 2
        new_epoch = old_epoch + 1
        steps = (
            WorkflowStepSpec(0, "charge", "payment", f"op:charge:{case_number}", False),
            WorkflowStepSpec(1, "refund", "payment", f"op:refund:{case_number}", False),
        )
        self.store.create_workflow(
            workflow_id=workflow_id,
            incident_id=incident_id,
            workload_id=workload_id,
            old_epoch=old_epoch,
            new_epoch=new_epoch,
            steps=steps,
            now=2_000 + case_number,
        )
        database = self.provider_databases["payment"]
        database.establish_epoch(workload_id, old_epoch, 1_900 + case_number)

        def compensation_engine() -> WorkflowRecoveryEngine:
            process = self.provider_processes["payment"]
            return WorkflowRecoveryEngine(
                store=self.store,
                providers={
                    "payment": ProviderBinding(
                        "payment",
                        database,
                        ProviderClient(process.base_url, timeout=0.25),
                    )
                },
                trust_store=self.trust,
                incident_signer=self.incident_signer,
                closure_signer=self.closure_signer,
                attestation_signer=self.attestation_signer,
                recovery_signer=self.recovery_signer,
            )

        engine = compensation_engine()
        charge = engine.old_request(workflow_id, "charge")
        self.assertEqual(engine.providers["payment"].client.execute(charge).status, "committed")
        refund = engine.old_request(workflow_id, "refund")
        result = engine.providers["payment"].client.execute(refund, fault=fault)
        self.assertEqual(result.status, "ambiguous")
        self.provider_processes["payment"].restart()
        self.store.set_status(workflow_id, "compensating", 2_010 + case_number)
        previous_scope = Scope.of(
            {"charge", "refund"}, {f"order:{case_number}"}, 500
        )
        current_policy = Scope.of({"refund"}, {f"order:{case_number}"}, 500)
        if outage:
            unavailable_engine = compensation_engine()
            self.provider_processes["payment"].stop()
            first = unavailable_engine.recover(
                workflow_id=workflow_id,
                previous_scope=previous_scope,
                current_policy=current_policy,
                manifest_hash="manifest:approved",
                configuration_hash="config:approved",
                approved_manifest_hashes=frozenset({"manifest:approved"}),
                approved_configuration_hashes=frozenset({"config:approved"}),
                expected_nonce=f"compensation-nonce-{case_number}:first",
                now=2_090 + case_number,
            )
            self.assertEqual(first.status, RecoveryStatus.QUARANTINED)
            self.provider_processes["payment"].start()
            self.store.restart_controller(workflow_id, 2_091 + case_number)

        recovery = compensation_engine().recover(
            workflow_id=workflow_id,
            previous_scope=previous_scope,
            current_policy=current_policy,
            manifest_hash="manifest:approved",
            configuration_hash="config:approved",
            approved_manifest_hashes=frozenset({"manifest:approved"}),
            approved_configuration_hashes=frozenset({"config:approved"}),
            expected_nonce=f"compensation-nonce-{case_number}",
            now=2_100 + case_number,
        )
        self.assertEqual(recovery.status, RecoveryStatus.AUTHORIZED)
        self.assertEqual(database.effect_count(incident_id, "charge"), 1)
        self.assertEqual(database.effect_count(incident_id, "refund"), 1)

    def test_compensation_is_exactly_once_across_both_crash_boundaries(self) -> None:
        for case_number, fault in enumerate(
            ("crash_before_commit", "crash_after_commit"), start=1
        ):
            with self.subTest(fault=fault):
                self._compensation_case(case_number, fault)

    def test_compensation_provider_outage_fails_closed_then_recovers(self) -> None:
        self._compensation_case(3, "crash_before_commit", outage=True)

    def test_signed_but_unapproved_runtime_is_quarantined(self) -> None:
        result = self.engine().recover(
            workflow_id=self.workflow_id,
            previous_scope=Scope.of({"charge"}, {"order:42"}, 500),
            current_policy=Scope.of({"charge"}, {"order:42"}, 200),
            manifest_hash="manifest:unapproved",
            configuration_hash="config:approved",
            approved_manifest_hashes=frozenset({"manifest:approved"}),
            approved_configuration_hashes=frozenset({"config:approved"}),
            expected_nonce="nonce-001",
            now=1_100,
        )
        self.assertEqual(result.status, RecoveryStatus.QUARANTINED)
        self.assertIn("unapproved_manifest", result.reasons)


if __name__ == "__main__":
    unittest.main()
