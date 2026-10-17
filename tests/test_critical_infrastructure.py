from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

from ztai import (
    AuthorityBarrierCertificate,
    CloudAuthorityBinding,
    CloudEffectTarget,
    CriticalInfrastructureAuthorizer,
    CriticalInfrastructurePolicy,
    DelegationChainVerifier,
    Ed25519Signer,
    FederatedIdentityBinding,
    FederatedIdentityVerifier,
    GridMaintenanceDigitalTwin,
    InfrastructureAuthorizationBundle,
    InfrastructureCommand,
    OperatorApproval,
    OrganizationDelegation,
    Scope,
    TrustStore,
    WorkloadIdentityEvidence,
)
from ztai.model import digest


class CriticalInfrastructureDigitalTwinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.twin = GridMaintenanceDigitalTwin(
            Path(self.temporary_directory.name) / "grid-digital-twin.sqlite3"
        )
        self.now = 20_000
        self.providers = (
            "crew-access",
            "notification",
            "switch-gateway",
            "work-order",
        )
        self.issuer = Ed25519Signer("spire:utility")
        self.federation = Ed25519Signer("federation:utility")
        self.utility = Ed25519Signer("authority:utility")
        self.contractor = Ed25519Signer("authority:contractor")
        self.barrier_signer = Ed25519Signer("barrier:utility")
        self.cloud_signer = Ed25519Signer("cloud-binding:utility")
        self.instance = Ed25519Signer("instance:restoration:7")
        self.supervisor = Ed25519Signer("operator:supervisor")
        self.safety_officer = Ed25519Signer("operator:safety")
        self.attacker = Ed25519Signer("attacker")
        self.trust = TrustStore()
        for role, signer in (
            ("workload_identity_issuer", self.issuer),
            ("federation_authority", self.federation),
            ("organization_authority", self.utility),
            ("organization_authority", self.contractor),
            ("authority_barrier_authority", self.barrier_signer),
            ("cloud_binding_authority", self.cloud_signer),
            ("agent_instance", self.instance),
            ("operator", self.supervisor),
            ("operator", self.safety_officer),
        ):
            self.trust.register(role, signer)
        self.evidence = WorkloadIdentityEvidence(
            "spiffe://utility.example/agent/restoration/instance-7",
            "https://spire.utility.example",
            "spiffe://utility.example/agent/restoration/instance-7",
            "switch-gateway",
            "utility",
            "restoration-agent",
            self.instance.signer_id,
            self.instance.public_key_fingerprint,
            self.now - 100,
            self.now + 600,
            "nonce:instance-7",
        )
        self.identity_binding = FederatedIdentityBinding(
            "identity-binding-7",
            "operator:alice",
            "agent/restoration",
            "restoration-agent",
            self.instance.signer_id,
            "utility",
            "delegation-child",
            7,
            "switch-gateway",
            self.providers,
            digest(self.evidence),
            self.now - 90,
            self.now + 500,
        )
        self.root = OrganizationDelegation(
            "delegation-root",
            "utility",
            "utility.example",
            "operator:alice",
            "agent:coordinator",
            "switch-gateway",
            Scope.of(
                {"create_work_order", "grant_crew_access", "isolate", "notify", "restore"},
                {"feeder:7"},
            ),
            "",
            0,
            self.now - 80,
            self.now + 400,
            "nonce:root",
        )
        self.child = OrganizationDelegation(
            "delegation-child",
            "contractor",
            "contractor.example",
            "agent:coordinator",
            "restoration-agent",
            "switch-gateway",
            self.root.scope,
            digest(self.root),
            1,
            self.now - 70,
            self.now + 300,
            "nonce:child",
        )
        self.barrier = AuthorityBarrierCertificate(
            "transition-7",
            "incident-7",
            "agent/restoration",
            1,
            6,
            7,
            "transition-digest",
            self.providers,
            tuple(f"ack-{provider}" for provider in self.providers),
            self.now - 60,
        )
        identity_verifier = FederatedIdentityVerifier(
            self.trust,
            issuer_trust_domains={self.issuer.signer_id: "utility.example"},
            issuer_urls={self.issuer.signer_id: "https://spire.utility.example"},
        )
        delegation_verifier = DelegationChainVerifier(
            self.trust,
            signer_domains={
                self.utility.signer_id: "utility.example",
                self.contractor.signer_id: "contractor.example",
            },
            signer_organizations={
                self.utility.signer_id: "utility",
                self.contractor.signer_id: "contractor",
            },
            allowed_domain_edges=frozenset(
                {("utility.example", "contractor.example")}
            ),
        )
        policy = CriticalInfrastructurePolicy(
            "switch-gateway",
            self.providers,
            frozenset(
                {"create_work_order", "grant_crew_access", "isolate", "notify", "restore"}
            ),
            frozenset({"feeder:7"}),
            frozenset({"isolate", "restore"}),
            ("switching_supervisor", "safety_officer"),
        )
        self.authorizer = CriticalInfrastructureAuthorizer(
            trust_store=self.trust,
            identity_verifier=identity_verifier,
            delegation_verifier=delegation_verifier,
            policy=policy,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _command(self, operation: str, index: int) -> InfrastructureCommand:
        target = CloudEffectTarget(
            "azure",
            "tenant-test",
            "grid-digital-twin",
            "feeder:7",
            operation,
        )
        return InfrastructureCommand(
            f"command:{operation}:{index}",
            "maintenance-case-7",
            "operator:alice",
            "agent/restoration",
            "utility",
            "restoration-agent",
            self.instance.signer_id,
            7,
            operation,
            "feeder:7",
            target,
            f"maintenance-case-7:{operation}:{index}",
            "safety-case:approved:7",
            self.now + index,
            self.now + 200,
        )

    def _bundle(
        self,
        command: InfrastructureCommand,
        *,
        barrier=None,
        child=None,
        cloud_target=None,
        approvals: int | None = None,
        approval_signer=None,
    ) -> InfrastructureAuthorizationBundle:
        barrier = barrier or self.barrier
        child = child or self.child
        cloud_binding = CloudAuthorityBinding(
            f"cloud:{command.command_id}",
            command.principal_id,
            command.agent_id,
            command.instance_id,
            command.workload_id,
            command.organization_id,
            command.authority_epoch,
            digest(child),
            digest(self.evidence),
            digest(barrier),
            cloud_target or command.target,
            command.issued_at,
            command.expires_at,
        )
        approval_count = (
            approvals
            if approvals is not None
            else (2 if command.operation in {"isolate", "restore"} else 1)
        )
        roles = ("switching_supervisor", "safety_officer")
        signers = (self.supervisor, self.safety_officer)
        approval_envelopes = []
        for index in range(approval_count):
            signer = approval_signer or signers[index]
            approval = OperatorApproval(
                f"approval:{command.command_id}:{index}",
                signer.signer_id,
                roles[index],
                digest(command),
                command.issued_at,
                command.expires_at,
            )
            approval_envelopes.append(signer.sign("operator_approval", approval))
        return InfrastructureAuthorizationBundle(
            self.instance.sign("infrastructure_command", command),
            self.issuer.sign("workload_identity_evidence", self.evidence),
            self.federation.sign("federated_identity_binding", self.identity_binding),
            (
                self.utility.sign("organization_delegation", self.root),
                self.contractor.sign("organization_delegation", child),
            ),
            self.barrier_signer.sign("authority_barrier", barrier),
            self.cloud_signer.sign("cloud_authority_binding", cloud_binding),
            tuple(approval_envelopes),
        )

    def test_valid_workflow_commits_exactly_once(self) -> None:
        operations = (
            "create_work_order",
            "grant_crew_access",
            "isolate",
            "notify",
            "restore",
        )
        final = None
        for index, operation in enumerate(operations):
            command = self._command(operation, index)
            decision = self.authorizer.authorize(
                self._bundle(command), now=command.issued_at
            )
            self.assertTrue(decision.authorized, decision.reasons)
            final = self.twin.execute(command, decision)
            self.assertEqual(final.status, "committed")
            self.assertFalse(final.replayed)
        self.assertEqual(final.state, "restored")
        self.assertEqual(self.twin.effect_count("maintenance-case-7"), 5)

        command = self._command("restore", 4)
        decision = self.authorizer.authorize(
            self._bundle(command), now=command.issued_at
        )
        replay = self.twin.execute(command, decision)
        self.assertTrue(replay.replayed)
        self.assertEqual(self.twin.effect_count("maintenance-case-7"), 5)

    def test_high_risk_command_requires_two_independent_roles(self) -> None:
        command = self._command("isolate", 2)
        decision = self.authorizer.authorize(
            self._bundle(command, approvals=1), now=command.issued_at
        )
        self.assertFalse(decision.authorized)
        self.assertIn("missing_operator_approval:safety_officer", decision.reasons)

        duplicate = self.authorizer.authorize(
            self._bundle(command, approvals=2, approval_signer=self.supervisor),
            now=command.issued_at,
        )
        self.assertFalse(duplicate.authorized)
        self.assertIn("duplicate_operator_approval", duplicate.reasons)

    def test_incomplete_barrier_and_cloud_target_substitution_are_rejected(self) -> None:
        command = self._command("create_work_order", 0)
        incomplete = dataclasses.replace(
            self.barrier,
            provider_ids=("switch-gateway", "work-order"),
            acknowledgement_digests=("ack-switch", "ack-work"),
        )
        decision = self.authorizer.authorize(
            self._bundle(command, barrier=incomplete), now=command.issued_at
        )
        self.assertFalse(decision.authorized)
        self.assertIn("incomplete_critical_provider_barrier", decision.reasons)

        substituted_target = dataclasses.replace(command.target, resource="feeder:99")
        decision = self.authorizer.authorize(
            self._bundle(command, cloud_target=substituted_target),
            now=command.issued_at,
        )
        self.assertFalse(decision.authorized)
        self.assertIn("cloud_effect_target_mismatch", decision.reasons)

    def test_scope_widening_and_unsafe_workflow_order_fail_closed(self) -> None:
        command = self._command("isolate", 0)
        widened = dataclasses.replace(
            self.child,
            scope=Scope.of(
                {"create_work_order", "grant_crew_access", "isolate", "notify", "restore"},
                {"feeder:7", "feeder:99"},
            ),
        )
        decision = self.authorizer.authorize(
            self._bundle(command, child=widened), now=command.issued_at
        )
        self.assertFalse(decision.authorized)
        self.assertIn("delegation_scope_widening:1", decision.reasons)

        valid_decision = self.authorizer.authorize(
            self._bundle(command), now=command.issued_at
        )
        self.assertTrue(valid_decision.authorized, valid_decision.reasons)
        result = self.twin.execute(command, valid_decision)
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.reason, "unsafe_workflow_order")
        self.assertEqual(self.twin.effect_count("maintenance-case-7"), 0)


if __name__ == "__main__":
    unittest.main()
