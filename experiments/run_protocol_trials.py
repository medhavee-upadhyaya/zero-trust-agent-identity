from __future__ import annotations

import csv
import dataclasses
import random
import sys
import time
from pathlib import Path

from ztai import (
    Attestation,
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


SCENARIOS = (
    "valid",
    "indeterminate_closure",
    "unresolved_carrier",
    "stale_attestation",
    "preincident_attestation",
    "unapproved_manifest",
    "nonce_mismatch",
    "epoch_rollback",
    "ambiguous_effect",
    "missing_provider_record",
    "forged_provider_record",
    "provider_binding_mismatch",
    "operation_binding_mismatch",
    "tampered_closure",
    "authority_overlap",
)


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: run_protocol_trials.py SEED TRIALS OUTPUT_CSV", file=sys.stderr)
        return 2
    seed = int(sys.argv[1])
    trials = int(sys.argv[2])
    output = Path(sys.argv[3])
    rng = random.Random(seed)

    incident_signer = Ed25519Signer("incident-control")
    closure_signer = Ed25519Signer("closure-verifier")
    attestation_signer = Ed25519Signer("rats-verifier")
    provider_a = Ed25519Signer("provider-a")
    provider_b = Ed25519Signer("provider-b")
    recovery_signer = Ed25519Signer("recovery-control")
    attacker = Ed25519Signer("attacker")
    trust = TrustStore()
    trust.register("incident_authority", incident_signer)
    trust.register("closure_authority", closure_signer)
    trust.register("attestation_verifier", attestation_signer)
    trust.register("provider", provider_a)
    trust.register("provider", provider_b)
    trust.register("recovery_authority", recovery_signer)

    output.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "trial",
        "seed",
        "scenario",
        "expected",
        "observed",
        "correct",
        "latency_ns",
        "scope_subset",
        "reason_count",
    )
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for trial in range(trials):
            scenario = SCENARIOS[trial % len(SCENARIOS)]
            old_epoch = 2 * trial + 1
            new_epoch = old_epoch + 1
            incident_id = f"inc-{seed}-{trial}"
            workload_id = f"agent/{trial % 17}"
            nonce = f"nonce-{seed}-{trial}"
            now = 10_000 + trial

            registry = AuthorityRegistry()
            registry.establish(workload_id, old_epoch)
            if scenario != "authority_overlap":
                registry.retire(workload_id, old_epoch)
            coordinator = RecoveryCoordinator(trust, registry, recovery_signer)

            incident = Incident(incident_id, workload_id, old_epoch, now - 20, "compromise")
            closure = ClosureCertificate(
                incident_id,
                workload_id,
                old_epoch,
                ClosureVerdict.QUIESCENT,
                ("credential", "queue", "callback"),
                ("credential", "queue", "callback"),
            )
            attestation = Attestation(
                workload_id,
                f"instance-{trial}",
                new_epoch,
                f"pk-{trial}",
                "manifest-approved",
                "config-approved",
                nonce,
                now - 5,
                now + 60,
            )
            steps = (
                Step("charge", "provider-a", f"charge-{trial}", False),
                Step("notify", "provider-b", f"notify-{trial}", True),
            )
            charge = ReconciliationRecord(
                incident_id,
                "charge",
                "provider-a",
                f"charge-{trial}",
                EffectState.COMMITTED,
                f"receipt-{trial}",
            )
            notify = ReconciliationRecord(
                incident_id,
                "notify",
                "provider-b",
                f"notify-{trial}",
                EffectState.NO_EFFECT,
                f"lookup-{trial}",
            )
            expected_nonce = nonce
            closure_envelope = closure_signer.sign("closure", closure)
            attestation_envelope = attestation_signer.sign("attestation", attestation)
            reconciliation = [
                provider_a.sign("reconciliation", charge),
                provider_b.sign("reconciliation", notify),
            ]

            if scenario == "indeterminate_closure":
                closure = dataclasses.replace(closure, verdict=ClosureVerdict.INDETERMINATE)
                closure_envelope = closure_signer.sign("closure", closure)
            elif scenario == "unresolved_carrier":
                closure = dataclasses.replace(
                    closure,
                    closed_carriers=("credential", "queue"),
                    unresolved_carriers=("callback",),
                )
                closure_envelope = closure_signer.sign("closure", closure)
            elif scenario == "stale_attestation":
                attestation = dataclasses.replace(attestation, expires_at=now)
                attestation_envelope = attestation_signer.sign("attestation", attestation)
            elif scenario == "preincident_attestation":
                attestation = dataclasses.replace(attestation, issued_at=incident.declared_at)
                attestation_envelope = attestation_signer.sign("attestation", attestation)
            elif scenario == "unapproved_manifest":
                attestation = dataclasses.replace(attestation, manifest_hash="manifest-unknown")
                attestation_envelope = attestation_signer.sign("attestation", attestation)
            elif scenario == "nonce_mismatch":
                expected_nonce = "wrong-nonce"
            elif scenario == "epoch_rollback":
                attestation = dataclasses.replace(attestation, new_epoch=old_epoch)
                attestation_envelope = attestation_signer.sign("attestation", attestation)
            elif scenario == "ambiguous_effect":
                notify = dataclasses.replace(notify, state=EffectState.AMBIGUOUS)
                reconciliation[1] = provider_b.sign("reconciliation", notify)
            elif scenario == "missing_provider_record":
                reconciliation.pop()
            elif scenario == "forged_provider_record":
                reconciliation[1] = attacker.sign("reconciliation", notify)
            elif scenario == "provider_binding_mismatch":
                reconciliation[1] = provider_a.sign("reconciliation", notify)
            elif scenario == "operation_binding_mismatch":
                notify = dataclasses.replace(notify, operation_digest="different-operation")
                reconciliation[1] = provider_b.sign("reconciliation", notify)
            elif scenario == "tampered_closure":
                closure_envelope = dataclasses.replace(
                    closure_envelope,
                    payload=dataclasses.replace(closure, closed_carriers=()),
                )

            previous = Scope.of({"charge", "notify", "refund"}, {"acct:a", "acct:b"}, 1_000)
            policy_actions = rng.sample(tuple(sorted(previous.actions)), rng.randrange(1, 4))
            policy_resources = rng.sample(tuple(sorted(previous.resources)), rng.randrange(1, 3))
            current = Scope.of(policy_actions, policy_resources, rng.randrange(1, 1_001))

            started = time.perf_counter_ns()
            decision = coordinator.evaluate(
                incident_envelope=incident_signer.sign("incident", incident),
                closure_envelope=closure_envelope,
                attestation_envelope=attestation_envelope,
                reconciliation_envelopes=tuple(reconciliation),
                previous_scope=previous,
                current_policy=current,
                steps=steps,
                expected_nonce=expected_nonce,
                approved_manifest_hashes=frozenset({"manifest-approved"}),
                approved_configuration_hashes=frozenset({"config-approved"}),
                now=now,
                grant_id=f"grant-{trial}",
            )
            latency = time.perf_counter_ns() - started
            expected = RecoveryStatus.AUTHORIZED if scenario == "valid" else RecoveryStatus.QUARANTINED
            scope_subset = True
            if decision.certificate is not None:
                scope = decision.certificate.grant.scope
                scope_subset = scope.is_subset_of(previous) and scope.is_subset_of(current)
            writer.writerow(
                {
                    "trial": trial,
                    "seed": seed,
                    "scenario": scenario,
                    "expected": expected.value,
                    "observed": decision.status.value,
                    "correct": decision.status is expected,
                    "latency_ns": latency,
                    "scope_subset": scope_subset,
                    "reason_count": len(decision.reasons),
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
