from __future__ import annotations

import csv
import dataclasses
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ztai import (
    Attestation,
    AuthorityBarrierCertificate,
    AuthorizedEffectRequest,
    ConsentRegistry,
    Ed25519Signer,
    EffectIntent,
    EffectRequest,
    PrincipalBoundAuthorizer,
    PrincipalConsent,
    ProviderAuthorizationEnforcer,
    ProviderDatabase,
    SQLiteConsentRegistry,
    Scope,
    TrustStore,
    make_execution_proof,
    make_instance_key_enrollment,
)
from ztai.crypto import encode_public_key
from ztai.model import Grant, RecoveryCertificate, ResumeInstruction, digest


ENROLLMENT_SCENARIOS = (
    "valid",
    "missing_enrollment",
    "forged_enrollment",
    "substituted_public_key",
    "stale_enrollment",
    "cross_workload_enrollment",
    "cross_epoch_enrollment",
)
RACE_SCHEDULES = (
    "effect_before_revocation",
    "revocation_before_effect",
    "simultaneous",
)


def recovery_certificate(
    *,
    workload_id: str,
    old_epoch: int,
    new_epoch: int,
    attestation: Attestation,
    scope: Scope,
    identity: str,
    authority_barrier_digest: str,
) -> RecoveryCertificate:
    grant = Grant(
        f"recovery:{identity}",
        workload_id,
        new_epoch,
        scope,
        digest({"incident": identity}),
        digest({"closed": identity}),
        digest(attestation),
        digest(scope),
        authority_barrier_digest,
    )
    instructions = (ResumeInstruction("charge", "execute", "certified_no_effect"),)
    reconciliation_digest = digest({"charge": "no_effect", "identity": identity})
    lineage_digest = digest(
        {
            "incident": grant.incident_digest,
            "closure": grant.closure_digest,
            "attestation": grant.attestation_digest,
            "grant": digest(grant),
            "reconciliation": reconciliation_digest,
            "instructions": instructions,
        }
    )
    return RecoveryCertificate(
        workload_id,
        old_epoch,
        new_epoch,
        grant,
        reconciliation_digest,
        instructions,
        lineage_digest,
    )


def valid_request(
    *,
    identity: str,
    now: int,
    signers: dict[str, Ed25519Signer],
    trust: TrustStore,
    consent_registry: ConsentRegistry,
) -> tuple[AuthorizedEffectRequest, int]:
    workload_id = f"agent:{identity}"
    task_id = f"task:{identity}"
    resource = f"order:{identity}"
    old_epoch = int(identity.rsplit(":", 1)[-1]) * 2 + 1
    new_epoch = old_epoch + 1
    scope = Scope.of({"charge"}, {resource}, 100)
    attestation = Attestation(
        workload_id,
        signers["instance"].signer_id,
        new_epoch,
        signers["instance"].public_key_fingerprint,
        "manifest:approved",
        "config:approved",
        f"nonce:{identity}",
        now - 10,
        now + 600,
    )
    barrier = AuthorityBarrierCertificate(
        transition_id=f"transition:{identity}",
        incident_id=f"incident:{identity}",
        workload_id=workload_id,
        version=new_epoch,
        retired_epoch=old_epoch,
        active_epoch=new_epoch,
        transition_digest=digest({"transition": identity}),
        provider_ids=("payment",),
        acknowledgement_digests=(digest({"provider": "payment", "identity": identity}),),
        formed_at=now - 1,
    )
    barrier_envelope = signers["barrier"].sign("authority_barrier", barrier)
    recovery = recovery_certificate(
        workload_id=workload_id,
        old_epoch=old_epoch,
        new_epoch=new_epoch,
        attestation=attestation,
        scope=scope,
        identity=identity,
        authority_barrier_digest=digest(barrier),
    )
    consent = PrincipalConsent(
        f"consent:{identity}",
        signers["principal"].signer_id,
        task_id,
        workload_id,
        scope,
        now - 20,
        now + 500,
        f"principal-nonce:{identity}",
    )
    consent_envelope = signers["principal"].sign("principal_consent", consent)
    attestation_envelope = signers["attestation"].sign("attestation", attestation)
    recovery_envelope = signers["recovery"].sign(
        "recovery_certificate", recovery
    )
    authorizer = PrincipalBoundAuthorizer(
        trust,
        consent_registry,
        signers["delegation"],
        signers["permit"],
    )
    delegation = authorizer.issue_delegation(
        consent_envelope=consent_envelope,
        attestation_envelope=attestation_envelope,
        recovery_envelope=recovery_envelope,
        authority_barrier_envelope=barrier_envelope,
        requested_scope=scope,
        now=now,
        grant_id=f"delegation:{identity}",
    )
    if not delegation.issued or delegation.envelope is None:
        raise AssertionError(f"delegation setup failed: {delegation.reasons}")
    permit = authorizer.issue_permit(
        delegation_envelope=delegation.envelope,
        provider_id="payment",
        step_id="charge",
        action="charge",
        resource=resource,
        amount=75,
        operation_digest=f"op:{identity}",
        idempotency_key=f"effect:{identity}:epoch:{new_epoch}",
        now=now,
        permit_id=f"permit:{identity}",
    )
    if not permit.issued or permit.envelope is None:
        raise AssertionError(f"permit setup failed: {permit.reasons}")
    intent = EffectIntent(
        consent.principal_id,
        task_id,
        signers["instance"].signer_id,
        "payment",
        "charge",
        resource,
        75,
        EffectRequest(
            f"incident:{identity}",
            "charge",
            workload_id,
            new_epoch,
            f"op:{identity}",
            f"effect:{identity}:epoch:{new_epoch}",
        ),
    )
    enrollment = make_instance_key_enrollment(
        signers["attestation"],
        attestation,
        signers["instance"],
        now=now,
    )
    proof = make_execution_proof(
        signers["instance"], permit.envelope, intent, now=now
    )
    return (
        AuthorizedEffectRequest(
            intent,
            consent_envelope,
            attestation_envelope,
            recovery_envelope,
            delegation.envelope,
            permit.envelope,
            proof,
            enrollment,
            barrier_envelope,
        ),
        new_epoch,
    )


def mutate_enrollment(
    scenario: str,
    request: AuthorizedEffectRequest,
    *,
    now: int,
    signers: dict[str, Ed25519Signer],
) -> AuthorizedEffectRequest:
    enrollment_envelope = request.key_enrollment_envelope
    if enrollment_envelope is None:
        raise AssertionError("valid request is missing enrollment")
    enrollment = enrollment_envelope.payload
    if scenario == "missing_enrollment":
        return dataclasses.replace(request, key_enrollment_envelope=None)
    if scenario == "forged_enrollment":
        return dataclasses.replace(
            request,
            key_enrollment_envelope=signers["attacker"].sign(
                "instance_key_enrollment", enrollment
            ),
        )
    if scenario == "substituted_public_key":
        enrollment = dataclasses.replace(
            enrollment,
            public_key=encode_public_key(signers["attacker"].public_key_bytes),
        )
    elif scenario == "stale_enrollment":
        enrollment = dataclasses.replace(enrollment, expires_at=now)
    elif scenario == "cross_workload_enrollment":
        enrollment = dataclasses.replace(
            enrollment, workload_id=f"{enrollment.workload_id}:other"
        )
    elif scenario == "cross_epoch_enrollment":
        enrollment = dataclasses.replace(enrollment, epoch=enrollment.epoch + 1)
    return dataclasses.replace(
        request,
        key_enrollment_envelope=signers["attestation"].sign(
            "instance_key_enrollment", enrollment
        ),
    )


def enrollment_row(
    *,
    seed: int,
    trial: int,
    scenario: str,
    now: int,
    request: AuthorizedEffectRequest,
    active_epoch: int,
    trust: TrustStore,
    registry: ConsentRegistry,
    signers: dict[str, Ed25519Signer],
) -> dict[str, object]:
    candidate = mutate_enrollment(
        scenario, request, now=now, signers=signers
    )
    enforcer = ProviderAuthorizationEnforcer(
        provider_id="payment",
        trust_store=trust,
        consent_registry=registry,
        require_dynamic_key_enrollment=True,
    )
    started = time.perf_counter_ns()
    decision = enforcer.verify_full_chain(
        candidate, now=now, active_epoch=active_epoch
    )
    latency = time.perf_counter_ns() - started
    expected = scenario == "valid"
    return {
        "seed": seed,
        "trial": trial,
        "mode": "key_enrollment",
        "scenario": scenario,
        "schedule": "",
        "expected_authorized": expected,
        "authorized": decision.authorized,
        "correct": decision.authorized == expected,
        "effect_committed": "",
        "effect_rejected_after_revocation": "",
        "commit_after_revocation": "",
        "linearizable": "",
        "post_restart_retry_rejected": "",
        "reason": ";".join(decision.reasons),
        "latency_ns": latency,
    }


def race_row(
    *,
    seed: int,
    trial: int,
    schedule: str,
    now: int,
    request: AuthorizedEffectRequest,
    active_epoch: int,
    trust: TrustStore,
    database: ProviderDatabase,
    registry: SQLiteConsentRegistry,
) -> dict[str, object]:
    database.establish_epoch(request.intent.effect.workload_id, active_epoch, now - 1)
    enforcer = ProviderAuthorizationEnforcer(
        provider_id="payment",
        trust_store=trust,
        consent_registry=registry,
        database=database,
        require_dynamic_key_enrollment=True,
    )
    consent_id = request.consent_envelope.payload.consent_id
    started = time.perf_counter_ns()
    if schedule == "effect_before_revocation":
        result = enforcer.execute(request, now=now)
        registry.revoke(consent_id)
    elif schedule == "revocation_before_effect":
        registry.revoke(consent_id)
        result = enforcer.execute(request, now=now)
    elif schedule == "simultaneous":
        barrier = threading.Barrier(2)

        def execute():
            barrier.wait()
            return enforcer.execute(request, now=now)

        def revoke():
            barrier.wait()
            registry.revoke(consent_id)

        with ThreadPoolExecutor(max_workers=2) as executor:
            execution_future = executor.submit(execute)
            revocation_future = executor.submit(revoke)
            result = execution_future.result(timeout=5)
            revocation_future.result(timeout=5)
    else:
        raise ValueError(schedule)
    latency = time.perf_counter_ns() - started

    revoked_at = database.consent_revoked_at(consent_id)
    committed_at = database.effect_committed_at(request.intent.effect.idempotency_key)
    effect_committed = result.status == "committed"
    rejected_after_revocation = (
        result.status == "rejected"
        and "revoked_principal_consent" in result.reason
    )
    commit_after_revocation = (
        committed_at is not None
        and revoked_at is not None
        and committed_at >= revoked_at
    )
    linearizable = (
        (effect_committed and committed_at is not None and committed_at < revoked_at)
        or (rejected_after_revocation and committed_at is None)
    )

    reopened = ProviderDatabase(database.path)
    restarted_registry = SQLiteConsentRegistry(reopened)
    restarted = ProviderAuthorizationEnforcer(
        provider_id="payment",
        trust_store=trust,
        consent_registry=restarted_registry,
        database=reopened,
        require_dynamic_key_enrollment=True,
    )
    retry = restarted.execute(request, now=now)
    retry_rejected = (
        retry.status == "rejected" and "revoked_principal_consent" in retry.reason
    )
    if commit_after_revocation or not linearizable or not retry_rejected:
        raise AssertionError(
            f"revocation race invariant failed: {schedule=} {result=} "
            f"{committed_at=} {revoked_at=} {retry=}"
        )
    return {
        "seed": seed,
        "trial": trial,
        "mode": "revocation_race",
        "scenario": "consent_revocation",
        "schedule": schedule,
        "expected_authorized": "",
        "authorized": "",
        "correct": "",
        "effect_committed": effect_committed,
        "effect_rejected_after_revocation": rejected_after_revocation,
        "commit_after_revocation": commit_after_revocation,
        "linearizable": linearizable,
        "post_restart_retry_rejected": retry_rejected,
        "reason": result.reason,
        "latency_ns": latency,
    }


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: run_revocation_key_races.py SEED TRIALS OUTPUT_CSV", file=sys.stderr)
        return 2
    seed = int(sys.argv[1])
    trials = int(sys.argv[2])
    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)

    signers = {
        "principal": Ed25519Signer("principal:alice"),
        "instance": Ed25519Signer("instance:dynamic"),
        "attacker": Ed25519Signer("instance:attacker"),
        "attestation": Ed25519Signer("rats-verifier"),
        "recovery": Ed25519Signer("recovery-control"),
        "barrier": Ed25519Signer("barrier-control"),
        "delegation": Ed25519Signer("delegation-control"),
        "permit": Ed25519Signer("permit-control"),
    }
    trust = TrustStore()
    for role, name in (
        ("principal", "principal"),
        ("attestation_verifier", "attestation"),
        ("recovery_authority", "recovery"),
        ("authority_barrier_authority", "barrier"),
        ("delegation_authority", "delegation"),
        ("permit_authority", "permit"),
    ):
        trust.register(role, signers[name])

    fields = (
        "seed",
        "trial",
        "mode",
        "scenario",
        "schedule",
        "expected_authorized",
        "authorized",
        "correct",
        "effect_committed",
        "effect_rejected_after_revocation",
        "commit_after_revocation",
        "linearizable",
        "post_restart_retry_rejected",
        "reason",
        "latency_ns",
    )
    with tempfile.TemporaryDirectory() as temporary_directory:
        database = ProviderDatabase(Path(temporary_directory) / "provider.sqlite3")
        with output.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            for trial in range(trials):
                now = 1_000_000 + trial
                identity = f"{seed}:{trial}"
                enrollment_registry = ConsentRegistry()
                request, active_epoch = valid_request(
                    identity=identity,
                    now=now,
                    signers=signers,
                    trust=trust,
                    consent_registry=enrollment_registry,
                )
                scenario = ENROLLMENT_SCENARIOS[trial % len(ENROLLMENT_SCENARIOS)]
                writer.writerow(
                    enrollment_row(
                        seed=seed,
                        trial=trial,
                        scenario=scenario,
                        now=now,
                        request=request,
                        active_epoch=active_epoch,
                        trust=trust,
                        registry=enrollment_registry,
                        signers=signers,
                    )
                )

                race_identity = f"{seed}:{trial + trials}"
                race_registry = SQLiteConsentRegistry(database)
                race_request, race_epoch = valid_request(
                    identity=race_identity,
                    now=now,
                    signers=signers,
                    trust=trust,
                    consent_registry=race_registry,
                )
                schedule = RACE_SCHEDULES[(trial + seed) % len(RACE_SCHEDULES)]
                writer.writerow(
                    race_row(
                        seed=seed,
                        trial=trial,
                        schedule=schedule,
                        now=now,
                        request=race_request,
                        active_epoch=race_epoch,
                        trust=trust,
                        database=database,
                        registry=race_registry,
                    )
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
