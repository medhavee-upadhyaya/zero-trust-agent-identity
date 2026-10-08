from __future__ import annotations

import dataclasses
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ztai import (
    Attestation,
    AuthorityRegistry,
    AuthorizedEffectRequest,
    ClosureCertificate,
    ClosureVerdict,
    ConsentRegistry,
    Ed25519Signer,
    EffectIntent,
    EffectRequest,
    EffectState,
    Incident,
    PrincipalBoundAuthorizer,
    PrincipalConsent,
    ProviderAuthorizationEnforcer,
    ProviderDatabase,
    ReconciliationRecord,
    RecoveryCoordinator,
    RecoveryStatus,
    Scope,
    SQLiteConsentRegistry,
    Step,
    TrustStore,
    make_execution_proof,
    make_instance_key_enrollment,
)
from ztai.crypto import encode_public_key
from ztai.model import digest


class PrincipalBoundAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = ProviderDatabase(
            Path(self.temporary_directory.name) / "authorized-provider.sqlite3"
        )
        self.workload_id = "agent/payments"
        self.old_epoch = 7
        self.new_epoch = 8
        self.now = 2_000
        self.database.establish_epoch(self.workload_id, self.new_epoch, self.now - 10)

        self.principal = Ed25519Signer("principal:alice")
        self.instance = Ed25519Signer("instance:repaired:8")
        self.attacker = Ed25519Signer("instance:attacker")
        self.incident_signer = Ed25519Signer("incident-control")
        self.closure_signer = Ed25519Signer("closure-verifier")
        self.attestation_signer = Ed25519Signer("rats-verifier")
        self.provider_signer = Ed25519Signer("payment")
        self.recovery_signer = Ed25519Signer("recovery-control")
        self.delegation_signer = Ed25519Signer("delegation-control")
        self.permit_signer = Ed25519Signer("permit-control")
        self.trust = TrustStore()
        for role, signer in (
            ("principal", self.principal),
            ("agent_instance", self.instance),
            ("agent_instance", self.attacker),
            ("incident_authority", self.incident_signer),
            ("closure_authority", self.closure_signer),
            ("attestation_verifier", self.attestation_signer),
            ("provider", self.provider_signer),
            ("recovery_authority", self.recovery_signer),
            ("delegation_authority", self.delegation_signer),
            ("permit_authority", self.permit_signer),
        ):
            self.trust.register(role, signer)
        self.consents = ConsentRegistry()
        self.authorizer = PrincipalBoundAuthorizer(
            self.trust,
            self.consents,
            self.delegation_signer,
            self.permit_signer,
        )
        self.enforcer = ProviderAuthorizationEnforcer(
            provider_id="payment",
            trust_store=self.trust,
            consent_registry=self.consents,
            database=self.database,
        )
        self.request = self._make_valid_request()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _make_recovery(self, *, incident_id: str = "incident-001"):
        registry = AuthorityRegistry()
        registry.establish(self.workload_id, self.old_epoch)
        registry.retire(self.workload_id, self.old_epoch)
        coordinator = RecoveryCoordinator(self.trust, registry, self.recovery_signer)
        incident = Incident(
            incident_id, self.workload_id, self.old_epoch, self.now - 100, "runtime_compromise"
        )
        closure = ClosureCertificate(
            incident_id,
            self.workload_id,
            self.old_epoch,
            ClosureVerdict.QUIESCENT,
            ("credential:7", "queue:7", "callback:7"),
            ("credential:7", "queue:7", "callback:7"),
        )
        attestation = Attestation(
            self.workload_id,
            self.instance.signer_id,
            self.new_epoch,
            self.instance.public_key_fingerprint,
            "manifest:approved",
            "config:approved",
            f"nonce:{incident_id}",
            self.now - 20,
            self.now + 600,
        )
        record = ReconciliationRecord(
            incident_id,
            "charge",
            "payment",
            "op:charge:42",
            EffectState.NO_EFFECT,
            "provider-fence:charge:42",
        )
        decision = coordinator.evaluate(
            incident_envelope=self.incident_signer.sign("incident", incident),
            closure_envelope=self.closure_signer.sign("closure", closure),
            attestation_envelope=self.attestation_signer.sign("attestation", attestation),
            reconciliation_envelopes=(
                self.provider_signer.sign("reconciliation", record),
            ),
            previous_scope=Scope.of({"charge", "refund"}, {"order:42"}, 500),
            current_policy=Scope.of({"charge"}, {"order:42"}, 200),
            steps=(Step("charge", "payment", "op:charge:42", False),),
            expected_nonce=f"nonce:{incident_id}",
            approved_manifest_hashes=frozenset({"manifest:approved"}),
            approved_configuration_hashes=frozenset({"config:approved"}),
            now=self.now,
            grant_id=f"recovery-grant:{incident_id}",
        )
        self.assertEqual(decision.status, RecoveryStatus.AUTHORIZED)
        assert decision.certificate_envelope is not None
        return attestation, decision.certificate_envelope

    def _make_valid_request(self) -> AuthorizedEffectRequest:
        attestation, recovery_envelope = self._make_recovery()
        consent = PrincipalConsent(
            "consent-001",
            self.principal.signer_id,
            "task:checkout:42",
            self.workload_id,
            Scope.of({"charge"}, {"order:42"}, 150),
            self.now - 50,
            self.now + 500,
            "principal-nonce-001",
        )
        consent_envelope = self.principal.sign("principal_consent", consent)
        attestation_envelope = self.attestation_signer.sign("attestation", attestation)
        delegation = self.authorizer.issue_delegation(
            consent_envelope=consent_envelope,
            attestation_envelope=attestation_envelope,
            recovery_envelope=recovery_envelope,
            requested_scope=Scope.of({"charge"}, {"order:42"}, 100),
            now=self.now,
            grant_id="delegation-001",
        )
        self.assertTrue(delegation.issued, delegation.reasons)
        assert delegation.envelope is not None
        permit = self.authorizer.issue_permit(
            delegation_envelope=delegation.envelope,
            provider_id="payment",
            step_id="charge",
            action="charge",
            resource="order:42",
            amount=75,
            operation_digest="op:charge:42",
            idempotency_key="task:checkout:42:charge:epoch:8",
            now=self.now,
            permit_id="permit-001",
        )
        self.assertTrue(permit.issued, permit.reasons)
        assert permit.envelope is not None
        intent = EffectIntent(
            self.principal.signer_id,
            consent.task_id,
            self.instance.signer_id,
            "payment",
            "charge",
            "order:42",
            75,
            EffectRequest(
                "incident-001",
                "charge",
                self.workload_id,
                self.new_epoch,
                "op:charge:42",
                "task:checkout:42:charge:epoch:8",
            ),
        )
        proof = make_execution_proof(self.instance, permit.envelope, intent, now=self.now)
        return AuthorizedEffectRequest(
            intent,
            consent_envelope,
            attestation_envelope,
            recovery_envelope,
            delegation.envelope,
            permit.envelope,
            proof,
        )

    def _resign_proof(
        self, request: AuthorizedEffectRequest, signer: Ed25519Signer | None = None
    ) -> AuthorizedEffectRequest:
        proof = make_execution_proof(
            signer or self.instance,
            request.permit_envelope,
            request.intent,
            now=self.now,
        )
        return dataclasses.replace(request, proof_envelope=proof)

    def _dynamic_request(self) -> AuthorizedEffectRequest:
        attestation = self.request.attestation_envelope.payload
        enrollment = make_instance_key_enrollment(
            self.attestation_signer,
            attestation,
            self.instance,
            now=self.now,
        )
        return dataclasses.replace(
            self.request,
            key_enrollment_envelope=enrollment,
        )

    def test_valid_chain_commits_and_exact_replay_is_idempotent(self) -> None:
        first = self.enforcer.execute(self.request, now=self.now)
        second = self.enforcer.execute(self.request, now=self.now)
        self.assertEqual(first.status, "committed")
        self.assertFalse(first.replayed)
        self.assertEqual(second.status, "committed")
        self.assertTrue(second.replayed)
        self.assertEqual(self.database.effect_count("incident-001", "charge"), 1)

    def test_concurrent_exact_replay_produces_one_effect(self) -> None:
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(
                executor.map(lambda _: self.enforcer.execute(self.request, now=self.now), range(16))
            )
        self.assertTrue(all(result.status == "committed" for result in results))
        self.assertEqual(sum(not result.replayed for result in results), 1)
        self.assertEqual(self.database.effect_count("incident-001", "charge"), 1)

    def test_provider_rejects_binding_and_lineage_attacks(self) -> None:
        intent = self.request.intent
        old_effect = dataclasses.replace(intent.effect, epoch=self.old_epoch)
        alternate_recovery = self._make_recovery(incident_id="incident-002")[1]
        attacks = {
            "tampered_action": dataclasses.replace(
                self.request, intent=dataclasses.replace(intent, action="refund")
            ),
            "tampered_resource": dataclasses.replace(
                self.request, intent=dataclasses.replace(intent, resource="order:99")
            ),
            "amount_escalation": dataclasses.replace(
                self.request, intent=dataclasses.replace(intent, amount=175)
            ),
            "cross_task_replay": dataclasses.replace(
                self.request, intent=dataclasses.replace(intent, task_id="task:other")
            ),
            "cross_provider_replay": dataclasses.replace(
                self.request, intent=dataclasses.replace(intent, provider_id="inventory")
            ),
            "cross_epoch_replay": dataclasses.replace(
                self.request, intent=dataclasses.replace(intent, effect=old_effect)
            ),
            "swapped_recovery": dataclasses.replace(
                self.request, recovery_envelope=alternate_recovery
            ),
            "stolen_permit_without_instance_key": self._resign_proof(
                self.request, self.attacker
            ),
        }
        for name, attack in attacks.items():
            if name not in {"swapped_recovery", "stolen_permit_without_instance_key"}:
                attack = self._resign_proof(attack)
            with self.subTest(attack=name):
                decision = self.enforcer.verify_full_chain(
                    attack, now=self.now, active_epoch=self.new_epoch
                )
                self.assertFalse(decision.authorized, name)

    def test_forged_permit_is_rejected(self) -> None:
        forged = self.attacker.sign("action_permit", self.request.permit_envelope.payload)
        request = dataclasses.replace(self.request, permit_envelope=forged)
        request = self._resign_proof(request)
        decision = self.enforcer.verify_full_chain(
            request, now=self.now, active_epoch=self.new_epoch
        )
        self.assertFalse(decision.authorized)
        self.assertIn("invalid_action_permit", decision.reasons)

    def test_revoked_or_expired_consent_is_rejected_at_provider(self) -> None:
        self.consents.revoke("consent-001")
        revoked = self.enforcer.verify_full_chain(
            self.request, now=self.now, active_epoch=self.new_epoch
        )
        self.assertFalse(revoked.authorized)
        self.assertIn("revoked_principal_consent", revoked.reasons)

        fresh_registry = ConsentRegistry()
        fresh_enforcer = ProviderAuthorizationEnforcer(
            provider_id="payment", trust_store=self.trust, consent_registry=fresh_registry
        )
        expired_consent = dataclasses.replace(
            self.request.consent_envelope.payload, expires_at=self.now
        )
        expired = dataclasses.replace(
            self.request,
            consent_envelope=self.principal.sign("principal_consent", expired_consent),
        )
        decision = fresh_enforcer.verify_full_chain(
            expired, now=self.now, active_epoch=self.new_epoch
        )
        self.assertFalse(decision.authorized)
        self.assertIn("stale_principal_consent", decision.reasons)

    def test_authorizer_prevents_privilege_rebound(self) -> None:
        decision = self.authorizer.issue_permit(
            delegation_envelope=self.request.delegation_envelope,
            provider_id="payment",
            step_id="refund",
            action="refund",
            resource="order:42",
            amount=100,
            operation_digest="op:refund:42",
            idempotency_key="task:checkout:42:refund:epoch:8",
            now=self.now,
            permit_id="permit:overbroad",
        )
        self.assertFalse(decision.issued)
        self.assertIn("action_outside_delegated_scope", decision.reasons)

    def test_authorizer_rejects_future_attestation(self) -> None:
        attestation = dataclasses.replace(
            self.request.attestation_envelope.payload,
            issued_at=self.now + 1,
            expires_at=self.now + 600,
        )
        recovery = dataclasses.replace(
            self.request.recovery_envelope.payload,
            grant=dataclasses.replace(
                self.request.recovery_envelope.payload.grant,
                attestation_digest=digest(attestation),
            ),
        )
        recovery = dataclasses.replace(
            recovery,
            lineage_digest=digest(
                {
                    "incident": recovery.grant.incident_digest,
                    "closure": recovery.grant.closure_digest,
                    "attestation": recovery.grant.attestation_digest,
                    "grant": digest(recovery.grant),
                    "reconciliation": recovery.reconciliation_digest,
                    "instructions": recovery.instructions,
                }
            ),
        )
        decision = self.authorizer.issue_delegation(
            consent_envelope=self.request.consent_envelope,
            attestation_envelope=self.attestation_signer.sign("attestation", attestation),
            recovery_envelope=self.recovery_signer.sign(
                "recovery_certificate", recovery
            ),
            requested_scope=Scope.of({"charge"}, {"order:42"}, 100),
            now=self.now,
            grant_id="delegation:future-attestation",
        )
        self.assertFalse(decision.issued)
        self.assertIn("stale_attestation", decision.reasons)

    def test_provider_detects_legitimately_signed_overbroad_delegation(self) -> None:
        grant = self.request.delegation_envelope.payload
        overbroad_grant = dataclasses.replace(
            grant, scope=Scope.of({"charge", "refund"}, {"order:42"}, 1_000)
        )
        delegation = self.delegation_signer.sign("delegation_grant", overbroad_grant)
        permit = dataclasses.replace(
            self.request.permit_envelope.payload,
            delegation_digest=digest(overbroad_grant),
            action="refund",
            step_id="refund",
            amount=900,
            operation_digest="op:refund:42",
            idempotency_key="task:checkout:42:refund:epoch:8",
        )
        permit_envelope = self.permit_signer.sign("action_permit", permit)
        intent = dataclasses.replace(
            self.request.intent,
            action="refund",
            amount=900,
            effect=dataclasses.replace(
                self.request.intent.effect,
                step_id="refund",
                operation_digest="op:refund:42",
                idempotency_key="task:checkout:42:refund:epoch:8",
            ),
        )
        request = dataclasses.replace(
            self.request,
            delegation_envelope=delegation,
            permit_envelope=permit_envelope,
            intent=intent,
        )
        request = self._resign_proof(request)
        signed_permit = self.enforcer.verify_signed_permit(
            request, now=self.now, active_epoch=self.new_epoch
        )
        full_chain = self.enforcer.verify_full_chain(
            request, now=self.now, active_epoch=self.new_epoch
        )
        self.assertTrue(signed_permit.authorized)
        self.assertFalse(full_chain.authorized)
        self.assertIn("delegation_exceeds_consent", full_chain.reasons)
        self.assertIn("delegation_exceeds_recovery_grant", full_chain.reasons)

    def test_provider_rejects_permit_identity_not_bound_to_delegation(self) -> None:
        permit = dataclasses.replace(
            self.request.permit_envelope.payload,
            task_id="task:substituted",
        )
        permit_envelope = self.permit_signer.sign("action_permit", permit)
        intent = dataclasses.replace(self.request.intent, task_id="task:substituted")
        request = dataclasses.replace(
            self.request,
            permit_envelope=permit_envelope,
            intent=intent,
        )
        request = self._resign_proof(request)
        signed_permit = self.enforcer.verify_signed_permit(
            request, now=self.now, active_epoch=self.new_epoch
        )
        full_chain = self.enforcer.verify_full_chain(
            request, now=self.now, active_epoch=self.new_epoch
        )
        self.assertTrue(signed_permit.authorized)
        self.assertFalse(full_chain.authorized)
        self.assertIn("permit_delegation_identity_mismatch", full_chain.reasons)

    def test_dynamic_key_enrollment_removes_static_instance_key_requirement(self) -> None:
        dynamic_trust = TrustStore()
        for role, signer in (
            ("principal", self.principal),
            ("attestation_verifier", self.attestation_signer),
            ("recovery_authority", self.recovery_signer),
            ("delegation_authority", self.delegation_signer),
            ("permit_authority", self.permit_signer),
        ):
            dynamic_trust.register(role, signer)
        enforcer = ProviderAuthorizationEnforcer(
            provider_id="payment",
            trust_store=dynamic_trust,
            consent_registry=self.consents,
            database=self.database,
            require_dynamic_key_enrollment=True,
        )
        result = enforcer.execute(self._dynamic_request(), now=self.now)
        self.assertEqual(result.status, "committed")
        self.assertEqual(self.database.effect_count("incident-001", "charge"), 1)

    def test_dynamic_key_enrollment_rejects_key_substitution_and_missing_evidence(self) -> None:
        enforcer = ProviderAuthorizationEnforcer(
            provider_id="payment",
            trust_store=self.trust,
            consent_registry=self.consents,
            require_dynamic_key_enrollment=True,
        )
        missing = enforcer.verify_full_chain(
            self.request, now=self.now, active_epoch=self.new_epoch
        )
        self.assertFalse(missing.authorized)
        self.assertIn("missing_instance_key_enrollment", missing.reasons)

        dynamic = self._dynamic_request()
        enrollment = dynamic.key_enrollment_envelope
        assert enrollment is not None
        substituted = dataclasses.replace(
            enrollment.payload,
            public_key=encode_public_key(self.attacker.public_key_bytes),
        )
        attack = dataclasses.replace(
            dynamic,
            key_enrollment_envelope=self.attestation_signer.sign(
                "instance_key_enrollment", substituted
            ),
        )
        decision = enforcer.verify_full_chain(
            attack, now=self.now, active_epoch=self.new_epoch
        )
        self.assertFalse(decision.authorized)
        self.assertIn("enrolled_key_fingerprint_mismatch", decision.reasons)
        self.assertIn("invalid_instance_proof", decision.reasons)

    def test_durable_revocation_linearizes_with_effect_commit_and_survives_restart(self) -> None:
        registry = SQLiteConsentRegistry(self.database)
        enforcer = ProviderAuthorizationEnforcer(
            provider_id="payment",
            trust_store=self.trust,
            consent_registry=registry,
            database=self.database,
            require_dynamic_key_enrollment=True,
        )
        request = self._dynamic_request()
        barrier = threading.Barrier(2)

        def execute():
            barrier.wait()
            return enforcer.execute(request, now=self.now)

        def revoke():
            barrier.wait()
            registry.revoke("consent-001")

        with ThreadPoolExecutor(max_workers=2) as executor:
            execution_future = executor.submit(execute)
            revocation_future = executor.submit(revoke)
            result = execution_future.result(timeout=3)
            revocation_future.result(timeout=3)

        revoked_at = self.database.consent_revoked_at("consent-001")
        committed_at = self.database.effect_committed_at(
            request.intent.effect.idempotency_key
        )
        self.assertIsNotNone(revoked_at)
        if result.status == "committed":
            self.assertIsNotNone(committed_at)
            assert committed_at is not None and revoked_at is not None
            self.assertLess(committed_at, revoked_at)
        else:
            self.assertEqual(result.reason, "revoked_principal_consent")
            self.assertIsNone(committed_at)

        reopened = ProviderDatabase(self.database.path)
        restarted_registry = SQLiteConsentRegistry(reopened)
        restarted = ProviderAuthorizationEnforcer(
            provider_id="payment",
            trust_store=self.trust,
            consent_registry=restarted_registry,
            database=reopened,
            require_dynamic_key_enrollment=True,
        )
        retry = restarted.execute(request, now=self.now)
        self.assertEqual(retry.status, "rejected")
        self.assertIn("revoked_principal_consent", retry.reason)


if __name__ == "__main__":
    unittest.main()
