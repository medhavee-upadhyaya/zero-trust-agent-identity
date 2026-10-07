from __future__ import annotations

import csv
import random
import sys
import tempfile
import time
from pathlib import Path

from ztai import (
    Attestation,
    AuthorityRegistry,
    ClosureCertificate,
    ClosureVerdict,
    Ed25519Signer,
    EffectRequest,
    Incident,
    ProviderClient,
    ProviderDatabase,
    ProviderProcess,
    RecoveryCoordinator,
    RecoveryStatus,
    Scope,
    Step,
    TrustStore,
)


MECHANISMS = (
    "effect_closed_recovery",
    "blind_successor",
    "same_key_retry_then_retire",
    "quarantine",
)
FAULTS = ("crash_before_commit", "crash_after_commit")


def _run_case(
    *,
    trial: int,
    seed: int,
    mechanism: str,
    fault: str,
    provider: ProviderProcess,
    database: ProviderDatabase,
    provider_signer: Ed25519Signer,
    incident_signer: Ed25519Signer,
    closure_signer: Ed25519Signer,
    attestation_signer: Ed25519Signer,
    recovery_signer: Ed25519Signer,
) -> dict[str, object]:
    case_id = f"{seed}-{trial}-{mechanism}"
    incident_id = f"inc-{case_id}"
    workload_id = f"agent/{case_id}"
    old_epoch = 2 * trial + 1
    new_epoch = old_epoch + 1
    declared_at = 1_000_000 + trial * 10
    operation_digest = f"sha256:operation:{case_id}"
    old_request = EffectRequest(
        incident_id=incident_id,
        step_id="charge",
        workload_id=workload_id,
        epoch=old_epoch,
        operation_digest=operation_digest,
        idempotency_key=f"{case_id}:epoch:{old_epoch}",
    )
    successor_request = EffectRequest(
        incident_id=incident_id,
        step_id="charge",
        workload_id=workload_id,
        epoch=new_epoch,
        operation_digest=operation_digest,
        idempotency_key=f"{case_id}:epoch:{new_epoch}",
    )
    database.establish_epoch(workload_id, old_epoch, declared_at - 100)
    first_client = ProviderClient(provider.base_url)
    first_result = first_client.execute(old_request, fault=fault)
    if first_result.status != "ambiguous":
        raise AssertionError(f"fault injection did not produce ambiguity: {first_result}")
    assert provider.process is not None
    provider.process.join(2)
    if provider.process.is_alive():
        raise AssertionError("provider process survived injected crash")

    started = time.perf_counter_ns()
    provider.restart()
    client = ProviderClient(provider.base_url)
    old_authority_accepted_after_incident = False
    resumed = False
    recovery_authorized = False
    signed_evidence_valid: bool | None = None
    certificate_valid: bool | None = None
    scope_subset: bool | None = None
    reconciliation_state = "not_requested"
    instruction = "none"

    if mechanism == "same_key_retry_then_retire":
        retry = client.execute(old_request)
        if retry.status != "committed":
            raise AssertionError(f"same-key retry failed: {retry}")
        old_authority_accepted_after_incident = True
        resumed = True
        if not database.retire_epoch(workload_id, old_epoch, declared_at + 1):
            raise AssertionError("old provider epoch was not retired")
        instruction = "retry_old_delivery"
    elif mechanism == "blind_successor":
        if not database.retire_epoch(workload_id, old_epoch, declared_at + 1):
            raise AssertionError("old provider epoch was not retired")
        if not database.activate_epoch(workload_id, new_epoch, declared_at + 2):
            raise AssertionError("new provider epoch was not activated")
        successor = client.execute(successor_request)
        if successor.status != "committed":
            raise AssertionError(f"blind successor failed: {successor}")
        resumed = True
        instruction = "execute_without_reconciliation"
    elif mechanism == "quarantine":
        if not database.retire_epoch(workload_id, old_epoch, declared_at + 1):
            raise AssertionError("old provider epoch was not retired")
        instruction = "stop"
    elif mechanism == "effect_closed_recovery":
        if not database.retire_epoch(workload_id, old_epoch, declared_at + 1):
            raise AssertionError("old provider epoch was not retired")
        outcome = client.reconcile(old_request, create_fence=True)
        if outcome.envelope is None:
            raise AssertionError(f"provider did not certify an outcome: {outcome}")
        reconciliation_state = outcome.status

        trust = TrustStore()
        for role, signer in (
            ("provider", provider_signer),
            ("incident_authority", incident_signer),
            ("closure_authority", closure_signer),
            ("attestation_verifier", attestation_signer),
            ("recovery_authority", recovery_signer),
        ):
            trust.register(role, signer)
        signed_evidence_valid = trust.verify("provider", outcome.envelope, "reconciliation")

        registry = AuthorityRegistry()
        registry.establish(workload_id, old_epoch)
        registry.retire(workload_id, old_epoch)
        coordinator = RecoveryCoordinator(trust, registry, recovery_signer)
        incident = Incident(
            incident_id,
            workload_id,
            old_epoch,
            declared_at,
            "runtime_compromise",
        )
        closure = ClosureCertificate(
            incident_id,
            workload_id,
            old_epoch,
            ClosureVerdict.QUIESCENT,
            (f"credential:{old_epoch}", f"provider-delivery:{old_epoch}"),
            (f"credential:{old_epoch}", f"provider-delivery:{old_epoch}"),
        )
        nonce = f"nonce-{case_id}"
        attestation = Attestation(
            workload_id,
            f"instance-{case_id}",
            new_epoch,
            f"pk:{new_epoch}",
            "manifest:approved",
            "config:approved",
            nonce,
            declared_at + 2,
            declared_at + 100,
        )
        previous_scope = Scope.of({"charge", "refund"}, {f"acct:{trial}"}, 500)
        current_policy = Scope.of({"charge"}, {f"acct:{trial}"}, 200)
        decision = coordinator.evaluate(
            incident_envelope=incident_signer.sign("incident", incident),
            closure_envelope=closure_signer.sign("closure", closure),
            attestation_envelope=attestation_signer.sign("attestation", attestation),
            reconciliation_envelopes=(outcome.envelope,),
            previous_scope=previous_scope,
            current_policy=current_policy,
            steps=(Step("charge", provider_signer.signer_id, operation_digest, False),),
            expected_nonce=nonce,
            approved_manifest_hashes=frozenset({"manifest:approved"}),
            approved_configuration_hashes=frozenset({"config:approved"}),
            now=declared_at + 3,
            grant_id=f"grant-{case_id}",
        )
        recovery_authorized = decision.status is RecoveryStatus.AUTHORIZED
        if decision.certificate_envelope is not None:
            certificate_valid = coordinator.verify_certificate(decision.certificate_envelope)
        if decision.certificate is not None:
            scope = decision.certificate.grant.scope
            scope_subset = scope.is_subset_of(previous_scope) and scope.is_subset_of(current_policy)
            instruction = decision.certificate.instructions[0].action
        if not recovery_authorized:
            raise AssertionError(f"valid recovery was quarantined: {decision.reasons}")
        if not database.activate_epoch(workload_id, new_epoch, declared_at + 4):
            raise AssertionError("new provider epoch was not activated")
        registry.activate(workload_id, new_epoch)
        resumed = True
        if instruction in {"execute", "execute_once"}:
            successor = client.execute(successor_request)
            if successor.status != "committed":
                raise AssertionError(f"certified successor failed: {successor}")
        elif instruction != "skip":
            raise AssertionError(f"unsupported recovery instruction: {instruction}")
    else:
        raise ValueError(mechanism)

    latency_ns = time.perf_counter_ns() - started
    effects = database.effect_count(incident_id, "charge")
    exact_once = effects == 1
    duplicate_effect = effects > 1
    incomplete = effects == 0
    safe_completion = (
        resumed
        and exact_once
        and not old_authority_accepted_after_incident
        and (scope_subset is not False)
        and (signed_evidence_valid is not False)
        and (certificate_valid is not False)
    )

    if mechanism == "effect_closed_recovery" and not (
        exact_once and signed_evidence_valid and certificate_valid and scope_subset
    ):
        raise AssertionError("effect-closed recovery violated an acceptance invariant")
    if mechanism == "blind_successor" and duplicate_effect != (fault == "crash_after_commit"):
        raise AssertionError("blind-successor outcome did not match the commit point")
    if mechanism == "same_key_retry_then_retire" and not (
        exact_once and old_authority_accepted_after_incident
    ):
        raise AssertionError("same-key retry did not expose its declared tradeoff")
    if mechanism == "quarantine" and resumed:
        raise AssertionError("quarantine unexpectedly resumed")

    return {
        "trial": trial,
        "seed": seed,
        "mechanism": mechanism,
        "fault": fault,
        "resumed": resumed,
        "old_authority_accepted_after_incident": old_authority_accepted_after_incident,
        "recovery_authorized": recovery_authorized,
        "signed_evidence_valid": signed_evidence_valid,
        "certificate_valid": certificate_valid,
        "scope_subset": scope_subset,
        "reconciliation_state": reconciliation_state,
        "instruction": instruction,
        "effect_count": effects,
        "exact_once": exact_once,
        "duplicate_effect": duplicate_effect,
        "incomplete": incomplete,
        "safe_completion": safe_completion,
        "recovery_latency_ns": latency_ns,
    }


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: run_provider_faults.py SEED TRIALS OUTPUT_CSV", file=sys.stderr)
        return 2
    seed = int(sys.argv[1])
    trials = int(sys.argv[2])
    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)

    provider_signer = Ed25519Signer("provider-a")
    incident_signer = Ed25519Signer("incident-control")
    closure_signer = Ed25519Signer("closure-verifier")
    attestation_signer = Ed25519Signer("rats-verifier")
    recovery_signer = Ed25519Signer("recovery-control")
    fields = (
        "trial",
        "seed",
        "mechanism",
        "fault",
        "resumed",
        "old_authority_accepted_after_incident",
        "recovery_authorized",
        "signed_evidence_valid",
        "certificate_valid",
        "scope_subset",
        "reconciliation_state",
        "instruction",
        "effect_count",
        "exact_once",
        "duplicate_effect",
        "incomplete",
        "safe_completion",
        "recovery_latency_ns",
    )

    with tempfile.TemporaryDirectory() as temporary_directory:
        database_path = Path(temporary_directory) / "provider.sqlite3"
        database = ProviderDatabase(database_path)
        provider = ProviderProcess(
            database_path, provider_signer, enable_faults=True
        ).start()
        try:
            with output.open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for trial in range(trials):
                    fault = FAULTS[trial % len(FAULTS)]
                    mechanisms = list(MECHANISMS)
                    rng.shuffle(mechanisms)
                    for mechanism in mechanisms:
                        writer.writerow(
                            _run_case(
                                trial=trial,
                                seed=seed,
                                mechanism=mechanism,
                                fault=fault,
                                provider=provider,
                                database=database,
                                provider_signer=provider_signer,
                                incident_signer=incident_signer,
                                closure_signer=closure_signer,
                                attestation_signer=attestation_signer,
                                recovery_signer=recovery_signer,
                            )
                        )
                        handle.flush()
        finally:
            provider.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
