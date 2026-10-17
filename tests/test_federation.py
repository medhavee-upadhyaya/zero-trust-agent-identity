from __future__ import annotations

import dataclasses
import unittest

from ztai import (
    AwsWebIdentityConfig,
    CloudAuthorityBinding,
    CloudEffectTarget,
    DelegationChainVerifier,
    Ed25519Signer,
    FederatedIdentityBinding,
    FederatedIdentityVerifier,
    GoogleWorkloadFederationConfig,
    MicrosoftEntraFederationConfig,
    OrganizationDelegation,
    Scope,
    SpiffeIdentity,
    TrustStore,
    WorkloadIdentityEvidence,
    redact_token_fields,
)
from ztai.model import digest


class FederatedIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 10_000
        self.issuer = Ed25519Signer("spire:utility")
        self.federation = Ed25519Signer("federation:utility")
        self.trust = TrustStore()
        self.trust.register("workload_identity_issuer", self.issuer)
        self.trust.register("federation_authority", self.federation)
        self.evidence = WorkloadIdentityEvidence(
            spiffe_id="spiffe://utility.example/agent/restoration/instance-7",
            issuer="https://spire.utility.example",
            subject="spiffe://utility.example/agent/restoration/instance-7",
            audience="cloud-sts",
            organization_id="utility",
            agent_id="restoration-agent",
            instance_id="instance-7",
            public_key_fingerprint="sha256:instance-7",
            issued_at=self.now - 10,
            expires_at=self.now + 300,
            nonce="nonce-7",
        )
        self.binding = FederatedIdentityBinding(
            binding_id="binding-7",
            principal_id="operator:alice",
            workload_id="agent/restoration",
            agent_id="restoration-agent",
            instance_id="instance-7",
            organization_id="utility",
            delegation_id="delegation-7",
            authority_epoch=7,
            audience="cloud-sts",
            provider_ids=("crew-access", "switch-gateway", "work-order"),
            evidence_digest=digest(self.evidence),
            issued_at=self.now - 5,
            expires_at=self.now + 200,
        )
        self.verifier = FederatedIdentityVerifier(
            self.trust,
            issuer_trust_domains={self.issuer.signer_id: "utility.example"},
            issuer_urls={self.issuer.signer_id: "https://spire.utility.example"},
        )

    def _verify(self, evidence=None, binding=None):
        evidence = evidence or self.evidence
        binding = binding or self.binding
        return self.verifier.verify(
            self.issuer.sign("workload_identity_evidence", evidence),
            self.federation.sign("federated_identity_binding", binding),
            expected_audience="cloud-sts",
            expected_principal_id="operator:alice",
            expected_workload_id="agent/restoration",
            expected_organization_id="utility",
            expected_agent_id="restoration-agent",
            expected_instance_id="instance-7",
            expected_epoch=7,
            required_provider_ids=("switch-gateway", "work-order"),
            now=self.now,
        )

    def test_valid_spiffe_identity_and_binding_are_accepted(self) -> None:
        decision = self._verify()
        self.assertTrue(decision.accepted, decision.reasons)
        self.assertEqual(decision.identity.trust_domain, "utility.example")

    def test_spiffe_parser_rejects_unsafe_components(self) -> None:
        invalid = (
            "https://utility.example/agent/a",
            "spiffe:///agent/a",
            "spiffe://user@utility.example/agent/a",
            "spiffe://utility.example:443/agent/a",
            "spiffe://utility.example/agent/a?epoch=7",
            "spiffe://utility.example/agent/a#fragment",
            "spiffe://Utility.example/agent/a",
            "spiffe://utility.example/agent/a/",
            "spiffe://utility.example/agent//instance",
            "spiffe://utility.example/agent/../admin",
            "spiffe://utility.example/agent/%2e%2e/admin",
            "spiffe://utility.example/agent name",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises((UnicodeError, ValueError)):
                SpiffeIdentity.parse(value)

    def test_cross_context_and_stale_evidence_are_rejected(self) -> None:
        wrong_audience = dataclasses.replace(self.evidence, audience="other-sts")
        decision = self._verify(evidence=wrong_audience)
        self.assertFalse(decision.accepted)
        self.assertIn("federation_audience_mismatch", decision.reasons)
        self.assertIn("workload_evidence_binding_mismatch", decision.reasons)

        stale = dataclasses.replace(self.evidence, expires_at=self.now)
        binding = dataclasses.replace(
            self.binding,
            evidence_digest=digest(stale),
            expires_at=self.now,
        )
        decision = self._verify(evidence=stale, binding=binding)
        self.assertFalse(decision.accepted)
        self.assertIn("stale_workload_identity", decision.reasons)
        self.assertIn("stale_federation_binding", decision.reasons)

    def test_agent_epoch_and_provider_binding_attacks_are_rejected(self) -> None:
        modified = dataclasses.replace(
            self.binding,
            instance_id="attacker-instance",
            authority_epoch=8,
            provider_ids=("switch-gateway",),
        )
        decision = self._verify(binding=modified)
        self.assertFalse(decision.accepted)
        self.assertIn("agent_instance_mismatch", decision.reasons)
        self.assertIn("authority_epoch_mismatch", decision.reasons)
        self.assertIn("incomplete_federated_provider_set", decision.reasons)

    def test_unexpected_issuer_url_is_rejected(self) -> None:
        evidence = dataclasses.replace(
            self.evidence,
            issuer="https://attacker.example",
        )
        binding = dataclasses.replace(
            self.binding,
            evidence_digest=digest(evidence),
        )
        decision = self._verify(evidence=evidence, binding=binding)
        self.assertFalse(decision.accepted)
        self.assertIn("workload_issuer_url_mismatch", decision.reasons)


class CloudIdentityAdapterTests(unittest.TestCase):
    def test_google_request_uses_rfc8693_fields(self) -> None:
        config = GoogleWorkloadFederationConfig("123456", "agents", "spire")
        request = config.token_exchange("signed-jwt-svid")
        fields = request.form_fields()
        self.assertEqual(
            fields["grant_type"],
            "urn:ietf:params:oauth:grant-type:token-exchange",
        )
        self.assertEqual(
            fields["subject_token_type"],
            "urn:ietf:params:oauth:token-type:jwt",
        )
        self.assertIn("workloadIdentityPools/agents/providers/spire", fields["audience"])
        self.assertIn(b"subject_token=signed-jwt-svid", request.encoded_body())

    def test_microsoft_request_uses_jwt_client_assertion(self) -> None:
        config = MicrosoftEntraFederationConfig(
            "tenant-7", "client-7", "https://storage.azure.com/.default"
        )
        fields = config.client_assertion_fields("signed-jwt-svid")
        self.assertIn("tenant-7", config.token_url)
        self.assertEqual(fields["grant_type"], "client_credentials")
        self.assertEqual(fields["client_assertion"], "signed-jwt-svid")

    def test_aws_request_uses_short_lived_web_identity_session(self) -> None:
        config = AwsWebIdentityConfig(
            "arn:aws:iam::123456789012:role/agent-role",
            "agent-instance-7",
        )
        fields = config.query_fields("signed-oidc-token")
        self.assertEqual(fields["Action"], "AssumeRoleWithWebIdentity")
        self.assertEqual(fields["DurationSeconds"], "900")
        self.assertNotIn("AccessKeyId", fields)

    def test_token_material_is_redacted_from_logs(self) -> None:
        fields = {
            "subject_token": "secret-1",
            "client_assertion": "secret-2",
            "WebIdentityToken": "secret-3",
            "audience": "safe",
        }
        self.assertEqual(
            redact_token_fields(fields),
            {
                "subject_token": "<redacted>",
                "client_assertion": "<redacted>",
                "WebIdentityToken": "<redacted>",
                "audience": "safe",
            },
        )

    def test_cloud_effect_binding_fails_closed_on_target_or_epoch_change(self) -> None:
        target = CloudEffectTarget(
            "azure", "tenant-7", "blob", "container/restoration", "write"
        )
        binding = CloudAuthorityBinding(
            "cloud-binding-7",
            "operator:alice",
            "restoration-agent",
            "instance-7",
            "agent/restoration",
            "utility",
            7,
            "delegation-digest",
            "identity-digest",
            "barrier-digest",
            target,
            100,
            200,
        )
        self.assertEqual(
            binding.validation_errors(expected=target, expected_epoch=7, now=150),
            (),
        )
        other = dataclasses.replace(target, resource="container/other")
        reasons = binding.validation_errors(expected=other, expected_epoch=8, now=150)
        self.assertIn("cloud_effect_target_mismatch", reasons)
        self.assertIn("cloud_authority_epoch_mismatch", reasons)


class CrossOrganizationDelegationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 5_000
        self.utility = Ed25519Signer("authority:utility")
        self.contractor = Ed25519Signer("authority:contractor")
        self.trust = TrustStore()
        self.trust.register("organization_authority", self.utility)
        self.trust.register("organization_authority", self.contractor)
        self.root = OrganizationDelegation(
            "delegation-root",
            "utility",
            "utility.example",
            "operator:alice",
            "agent:coordinator",
            "switch-gateway",
            Scope.of({"inspect", "isolate", "notify"}, {"feeder:7"}),
            "",
            0,
            self.now - 20,
            self.now + 300,
            "nonce-root",
        )
        self.child = OrganizationDelegation(
            "delegation-child",
            "contractor",
            "contractor.example",
            "agent:coordinator",
            "agent:inspection",
            "switch-gateway",
            Scope.of({"inspect"}, {"feeder:7"}),
            digest(self.root),
            1,
            self.now - 10,
            self.now + 100,
            "nonce-child",
        )
        self.verifier = DelegationChainVerifier(
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

    def _verify(self, root=None, child=None):
        root = root or self.root
        child = child or self.child
        return self.verifier.verify(
            (
                self.utility.sign("organization_delegation", root),
                self.contractor.sign("organization_delegation", child),
            ),
            expected_audience="switch-gateway",
            expected_final_delegatee="agent:inspection",
            now=self.now,
        )

    def test_valid_cross_domain_chain_attenuates_scope(self) -> None:
        decision = self._verify()
        self.assertTrue(decision.accepted, decision.reasons)
        self.assertEqual(decision.effective_scope, self.child.scope)

    def test_scope_widening_and_parent_substitution_are_rejected(self) -> None:
        widened = dataclasses.replace(
            self.child,
            scope=Scope.of({"inspect", "isolate", "export"}, {"feeder:7"}),
        )
        decision = self._verify(child=widened)
        self.assertFalse(decision.accepted)
        self.assertIn("delegation_scope_widening:1", decision.reasons)

        substituted = dataclasses.replace(self.child, parent_delegation_digest="other")
        decision = self._verify(child=substituted)
        self.assertFalse(decision.accepted)
        self.assertIn("delegation_parent_mismatch:1", decision.reasons)

    def test_untrusted_cross_domain_edge_is_rejected(self) -> None:
        verifier = DelegationChainVerifier(
            self.trust,
            signer_domains={
                self.utility.signer_id: "utility.example",
                self.contractor.signer_id: "contractor.example",
            },
            signer_organizations={
                self.utility.signer_id: "utility",
                self.contractor.signer_id: "contractor",
            },
            allowed_domain_edges=frozenset(),
        )
        decision = verifier.verify(
            (
                self.utility.sign("organization_delegation", self.root),
                self.contractor.sign("organization_delegation", self.child),
            ),
            expected_audience="switch-gateway",
            expected_final_delegatee="agent:inspection",
            now=self.now,
        )
        self.assertFalse(decision.accepted)
        self.assertIn("untrusted_domain_edge:1", decision.reasons)

    def test_missing_signer_organization_mapping_fails_closed(self) -> None:
        verifier = DelegationChainVerifier(
            self.trust,
            signer_domains={
                self.utility.signer_id: "utility.example",
                self.contractor.signer_id: "contractor.example",
            },
            allowed_domain_edges=frozenset(
                {("utility.example", "contractor.example")}
            ),
        )
        decision = verifier.verify(
            (
                self.utility.sign("organization_delegation", self.root),
                self.contractor.sign("organization_delegation", self.child),
            ),
            expected_audience="switch-gateway",
            expected_final_delegatee="agent:inspection",
            now=self.now,
        )
        self.assertFalse(decision.accepted)
        self.assertIn("untrusted_organization_signer:0", decision.reasons)
        self.assertIn("untrusted_organization_signer:1", decision.reasons)

    def test_signer_cannot_claim_another_organization_in_same_domain(self) -> None:
        child = dataclasses.replace(self.child, organization_id="attacker")
        decision = self._verify(child=child)
        self.assertFalse(decision.accepted)
        self.assertIn("organization_signer_identity_mismatch:1", decision.reasons)


if __name__ == "__main__":
    unittest.main()
