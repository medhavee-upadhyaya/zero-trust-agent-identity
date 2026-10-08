from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ztai import (
    ConsentRegistry,
    Ed25519Signer,
    PrincipalBoundAuthorizer,
    PrincipalBoundWorkflowExecutor,
    PrincipalConsent,
    ProviderAuthorizationEnforcer,
    ProviderBinding,
    ProviderClient,
    ProviderDatabase,
    ProviderProcess,
    RecoveryStatus,
    Scope,
    StepAuthorization,
    TrustStore,
    WorkflowRecoveryEngine,
    WorkflowStepSpec,
    WorkflowStore,
)


class SecureWorkflowIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        self.store = WorkflowStore(root / "workflow.sqlite3")
        self.provider_signers = {
            provider_id: Ed25519Signer(provider_id)
            for provider_id in ("payment", "inventory")
        }
        self.databases = {
            provider_id: ProviderDatabase(root / f"{provider_id}.sqlite3")
            for provider_id in self.provider_signers
        }
        self.processes = {
            provider_id: ProviderProcess(
                self.databases[provider_id].path,
                signer,
                enable_faults=True,
            ).start()
            for provider_id, signer in self.provider_signers.items()
        }
        self.incident_signer = Ed25519Signer("incident-control")
        self.closure_signer = Ed25519Signer("closure-verifier")
        self.attestation_signer = Ed25519Signer("rats-verifier")
        self.recovery_signer = Ed25519Signer("recovery-control")
        self.delegation_signer = Ed25519Signer("delegation-control")
        self.permit_signer = Ed25519Signer("permit-control")
        self.principal_signer = Ed25519Signer("principal:alice")
        self.instance_signer = Ed25519Signer("instance:successor")
        self.trust = TrustStore()
        for role, signer in (
            ("incident_authority", self.incident_signer),
            ("closure_authority", self.closure_signer),
            ("attestation_verifier", self.attestation_signer),
            ("recovery_authority", self.recovery_signer),
            ("delegation_authority", self.delegation_signer),
            ("permit_authority", self.permit_signer),
            ("principal", self.principal_signer),
            ("agent_instance", self.instance_signer),
        ):
            self.trust.register(role, signer)
        for signer in self.provider_signers.values():
            self.trust.register("provider", signer)

    def tearDown(self) -> None:
        for process in self.processes.values():
            process.stop()
        self.temporary_directory.cleanup()

    def _bindings(self) -> dict[str, ProviderBinding]:
        return {
            provider_id: ProviderBinding(
                provider_id,
                self.databases[provider_id],
                ProviderClient(process.base_url, timeout=0.25),
            )
            for provider_id, process in self.processes.items()
        }

    def test_recovered_effects_require_principal_and_successor_proof(self) -> None:
        workflow_id = "workflow:secure:42"
        incident_id = "incident:secure:42"
        workload_id = "agent:checkout"
        old_epoch = 7
        new_epoch = 8
        steps = (
            WorkflowStepSpec(0, "charge", "payment", "op:charge:42", False),
            WorkflowStepSpec(1, "reserve", "inventory", "op:reserve:42", False),
        )
        self.store.create_workflow(
            workflow_id=workflow_id,
            incident_id=incident_id,
            workload_id=workload_id,
            old_epoch=old_epoch,
            new_epoch=new_epoch,
            steps=steps,
            now=1_000,
        )
        for database in self.databases.values():
            database.establish_epoch(workload_id, old_epoch, 900)

        initial = WorkflowRecoveryEngine(
            store=self.store,
            providers=self._bindings(),
            trust_store=self.trust,
            incident_signer=self.incident_signer,
            closure_signer=self.closure_signer,
            attestation_signer=self.attestation_signer,
            recovery_signer=self.recovery_signer,
        )
        crash = initial.providers["payment"].client.execute(
            initial.old_request(workflow_id, "charge"),
            fault="crash_before_commit",
        )
        self.assertEqual(crash.status, "ambiguous")
        self.processes["payment"].restart()

        consent_registry = ConsentRegistry()
        authorizer = PrincipalBoundAuthorizer(
            self.trust,
            consent_registry,
            self.delegation_signer,
            self.permit_signer,
        )
        consent_scope = Scope.of({"charge", "reserve"}, {"order:42"}, 100)
        consent = PrincipalConsent(
            "consent:secure:42",
            self.principal_signer.signer_id,
            "task:checkout:42",
            workload_id,
            consent_scope,
            950,
            2_000,
            "principal-nonce:42",
        )
        executor = PrincipalBoundWorkflowExecutor(
            authorizer=authorizer,
            consent_envelope=self.principal_signer.sign("principal_consent", consent),
            instance_signer=self.instance_signer,
            provider_enforcers={
                provider_id: ProviderAuthorizationEnforcer(
                    provider_id=provider_id,
                    trust_store=self.trust,
                    consent_registry=consent_registry,
                    database=self.databases[provider_id],
                )
                for provider_id in self.databases
            },
            step_authorizations={
                "charge": StepAuthorization("charge", "order:42", 75),
                "reserve": StepAuthorization("reserve", "order:42", 0),
            },
            delegation_scope=consent_scope,
        )
        engine = WorkflowRecoveryEngine(
            store=self.store,
            providers=self._bindings(),
            trust_store=self.trust,
            incident_signer=self.incident_signer,
            closure_signer=self.closure_signer,
            attestation_signer=self.attestation_signer,
            recovery_signer=self.recovery_signer,
            successor_executor=executor,
        )
        result = engine.recover(
            workflow_id=workflow_id,
            previous_scope=Scope.of(
                {"charge", "reserve", "refund"}, {"order:42"}, 500
            ),
            current_policy=Scope.of({"charge", "reserve"}, {"order:42"}, 100),
            manifest_hash="manifest:approved",
            configuration_hash="config:approved",
            approved_manifest_hashes=frozenset({"manifest:approved"}),
            approved_configuration_hashes=frozenset({"config:approved"}),
            expected_nonce="nonce:secure:42",
            instance_id=self.instance_signer.signer_id,
            public_key_fingerprint=self.instance_signer.public_key_fingerprint,
            now=1_100,
        )
        self.assertEqual(result.status, RecoveryStatus.AUTHORIZED, result.reasons)
        self.assertEqual(result.completed_steps, ("charge", "reserve"))
        self.assertEqual(len(executor.requests), 2)
        self.assertEqual(self.databases["payment"].effect_count(incident_id, "charge"), 1)
        self.assertEqual(self.databases["inventory"].effect_count(incident_id, "reserve"), 1)

        stale = initial.providers["inventory"].client.execute(
            initial.old_request(workflow_id, "reserve")
        )
        self.assertEqual(stale.http_status, 403)
        self.assertEqual(stale.reason, "inactive_epoch")


if __name__ == "__main__":
    unittest.main()
