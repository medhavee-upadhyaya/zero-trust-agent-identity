from __future__ import annotations

import csv
import dataclasses
import random
import sys
import time
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
    Scope,
    TrustStore,
    make_execution_proof,
)
from ztai.model import Grant, RecoveryCertificate, ResumeInstruction, digest


MECHANISMS = (
    "bearer_token",
    "epoch_identity",
    "signed_action_permit",
    "effect_closed_principal_chain",
)

SCENARIOS = (
    "valid",
    "retired_epoch_replay",
    "forged_permit",
    "tampered_action",
    "tampered_resource",
    "amount_escalation",
    "cross_task_replay",
    "cross_provider_replay",
    "cross_epoch_replay",
    "stale_consent",
    "revoked_consent",
    "forged_consent",
    "swapped_recovery_certificate",
    "privilege_rebound",
    "permit_identity_substitution",
    "stolen_permit_without_instance_key",
)


def make_recovery_certificate(
    *,
    workload_id: str,
    old_epoch: int,
    new_epoch: int,
    attestation: Attestation,
    scope: Scope,
    trial_id: str,
    authority_barrier_digest: str,
) -> RecoveryCertificate:
    grant = Grant(
        grant_id=f"recovery:{trial_id}",
        workload_id=workload_id,
        epoch=new_epoch,
        scope=scope,
        incident_digest=digest({"incident": trial_id, "retired_epoch": old_epoch}),
        closure_digest=digest({"closed": True, "trial": trial_id}),
        attestation_digest=digest(attestation),
        policy_digest=digest(scope),
        authority_barrier_digest=authority_barrier_digest,
    )
    instructions = (ResumeInstruction("charge", "execute", "certified_no_effect"),)
    reconciliation_digest = digest({"charge": "provider_fenced_no_effect", "trial": trial_id})
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


def prepare_case(
    *,
    scenario: str,
    seed: int,
    trial: int,
    rng: random.Random,
    trust: TrustStore,
    signers: dict[str, Ed25519Signer],
) -> tuple[AuthorizedEffectRequest, ProviderAuthorizationEnforcer, int, int]:
    trial_id = f"{seed}:{trial}"
    now = 1_000_000 + trial
    old_epoch = trial * 2 + 1
    active_epoch = old_epoch + 1
    workload_id = f"agent/payments/{trial % 31}"
    task_id = f"task:{trial_id}"
    resource = f"order:{trial_id}"
    amount = rng.randrange(1, 101)
    principal_scope = Scope.of({"charge"}, {resource}, amount + 100)
    recovery_scope = Scope.of({"charge"}, {resource}, amount + 75)
    delegated_scope = Scope.of({"charge"}, {resource}, amount + 25)
    instance = signers["instance"]

    attestation = Attestation(
        workload_id,
        instance.signer_id,
        active_epoch,
        instance.public_key_fingerprint,
        "manifest:approved",
        "config:approved",
        f"nonce:{trial_id}",
        now - 20,
        now + 600,
    )
    barrier = AuthorityBarrierCertificate(
        transition_id=f"transition:{trial_id}",
        incident_id=f"incident:{trial_id}",
        workload_id=workload_id,
        version=active_epoch,
        retired_epoch=old_epoch,
        active_epoch=active_epoch,
        transition_digest=digest({"transition": trial_id}),
        provider_ids=("payment",),
        acknowledgement_digests=(digest({"provider": "payment", "trial": trial_id}),),
        formed_at=now - 1,
    )
    barrier_envelope = signers["barrier"].sign("authority_barrier", barrier)
    recovery = make_recovery_certificate(
        workload_id=workload_id,
        old_epoch=old_epoch,
        new_epoch=active_epoch,
        attestation=attestation,
        scope=recovery_scope,
        trial_id=trial_id,
        authority_barrier_digest=digest(barrier),
    )
    consent = PrincipalConsent(
        f"consent:{trial_id}",
        signers["principal"].signer_id,
        task_id,
        workload_id,
        principal_scope,
        now - 50,
        now + 500,
        f"principal-nonce:{trial_id}",
    )
    consent_envelope = signers["principal"].sign("principal_consent", consent)
    attestation_envelope = signers["attestation"].sign("attestation", attestation)
    recovery_envelope = signers["recovery"].sign("recovery_certificate", recovery)
    consents = ConsentRegistry()
    authorizer = PrincipalBoundAuthorizer(
        trust, consents, signers["delegation"], signers["permit"]
    )
    delegation = authorizer.issue_delegation(
        consent_envelope=consent_envelope,
        attestation_envelope=attestation_envelope,
        recovery_envelope=recovery_envelope,
        authority_barrier_envelope=barrier_envelope,
        requested_scope=delegated_scope,
        now=now,
        grant_id=f"delegation:{trial_id}",
    )
    if not delegation.issued or delegation.envelope is None:
        raise RuntimeError(f"valid delegation setup failed: {delegation.reasons}")
    idempotency_key = f"{task_id}:charge:epoch:{active_epoch}"
    permit = authorizer.issue_permit(
        delegation_envelope=delegation.envelope,
        provider_id="payment",
        step_id="charge",
        action="charge",
        resource=resource,
        amount=amount,
        operation_digest=f"op:charge:{trial_id}",
        idempotency_key=idempotency_key,
        now=now,
        permit_id=f"permit:{trial_id}",
    )
    if not permit.issued or permit.envelope is None:
        raise RuntimeError(f"valid permit setup failed: {permit.reasons}")
    intent = EffectIntent(
        consent.principal_id,
        task_id,
        instance.signer_id,
        "payment",
        "charge",
        resource,
        amount,
        EffectRequest(
            f"incident:{trial_id}",
            "charge",
            workload_id,
            active_epoch,
            f"op:charge:{trial_id}",
            idempotency_key,
        ),
    )
    proof = make_execution_proof(instance, permit.envelope, intent, now=now)
    request = AuthorizedEffectRequest(
        intent,
        consent_envelope,
        attestation_envelope,
        recovery_envelope,
        delegation.envelope,
        permit.envelope,
        proof,
        authority_barrier_envelope=barrier_envelope,
    )
    enforcer = ProviderAuthorizationEnforcer(
        provider_id="payment", trust_store=trust, consent_registry=consents
    )

    if scenario == "retired_epoch_replay":
        effect = dataclasses.replace(intent.effect, epoch=old_epoch)
        request = dataclasses.replace(request, intent=dataclasses.replace(intent, effect=effect))
    elif scenario == "forged_permit":
        request = dataclasses.replace(
            request,
            permit_envelope=signers["attacker"].sign(
                "action_permit", request.permit_envelope.payload
            ),
        )
    elif scenario == "tampered_action":
        request = dataclasses.replace(request, intent=dataclasses.replace(intent, action="refund"))
    elif scenario == "tampered_resource":
        request = dataclasses.replace(
            request, intent=dataclasses.replace(intent, resource=f"order:other:{trial_id}")
        )
    elif scenario == "amount_escalation":
        request = dataclasses.replace(
            request, intent=dataclasses.replace(intent, amount=amount + 1_000)
        )
    elif scenario == "cross_task_replay":
        request = dataclasses.replace(
            request, intent=dataclasses.replace(intent, task_id=f"task:other:{trial_id}")
        )
    elif scenario == "cross_provider_replay":
        request = dataclasses.replace(
            request, intent=dataclasses.replace(intent, provider_id="inventory")
        )
    elif scenario == "cross_epoch_replay":
        effect = dataclasses.replace(intent.effect, epoch=active_epoch + 1)
        request = dataclasses.replace(request, intent=dataclasses.replace(intent, effect=effect))
    elif scenario == "stale_consent":
        stale = dataclasses.replace(consent, expires_at=now)
        request = dataclasses.replace(
            request,
            consent_envelope=signers["principal"].sign("principal_consent", stale),
        )
    elif scenario == "revoked_consent":
        consents.revoke(consent.consent_id)
    elif scenario == "forged_consent":
        request = dataclasses.replace(
            request,
            consent_envelope=signers["attacker"].sign("principal_consent", consent),
        )
    elif scenario == "swapped_recovery_certificate":
        alternate = dataclasses.replace(
            recovery,
            grant=dataclasses.replace(recovery.grant, grant_id=f"other:{trial_id}"),
        )
        alternate = dataclasses.replace(
            alternate,
            lineage_digest=digest(
                {
                    "incident": alternate.grant.incident_digest,
                    "closure": alternate.grant.closure_digest,
                    "attestation": alternate.grant.attestation_digest,
                    "grant": digest(alternate.grant),
                    "reconciliation": alternate.reconciliation_digest,
                    "instructions": alternate.instructions,
                }
            ),
        )
        request = dataclasses.replace(
            request,
            recovery_envelope=signers["recovery"].sign("recovery_certificate", alternate),
        )
    elif scenario == "privilege_rebound":
        overbroad_grant = dataclasses.replace(
            delegation.envelope.payload,
            scope=Scope.of({"charge", "refund"}, {resource}, amount + 1_000),
        )
        delegation_envelope = signers["delegation"].sign(
            "delegation_grant", overbroad_grant
        )
        rebound_permit = dataclasses.replace(
            permit.envelope.payload,
            delegation_digest=digest(overbroad_grant),
            step_id="refund",
            action="refund",
            amount=amount + 500,
            operation_digest=f"op:refund:{trial_id}",
            idempotency_key=f"{task_id}:refund:epoch:{active_epoch}",
        )
        permit_envelope = signers["permit"].sign("action_permit", rebound_permit)
        rebound_intent = dataclasses.replace(
            intent,
            action="refund",
            amount=amount + 500,
            effect=dataclasses.replace(
                intent.effect,
                step_id="refund",
                operation_digest=f"op:refund:{trial_id}",
                idempotency_key=f"{task_id}:refund:epoch:{active_epoch}",
            ),
        )
        request = dataclasses.replace(
            request,
            delegation_envelope=delegation_envelope,
            permit_envelope=permit_envelope,
            intent=rebound_intent,
        )
    elif scenario == "permit_identity_substitution":
        substituted_task = f"task:substituted:{trial_id}"
        substituted_permit = dataclasses.replace(
            permit.envelope.payload,
            task_id=substituted_task,
        )
        request = dataclasses.replace(
            request,
            permit_envelope=signers["permit"].sign(
                "action_permit", substituted_permit
            ),
            intent=dataclasses.replace(intent, task_id=substituted_task),
        )
    elif scenario == "stolen_permit_without_instance_key":
        pass

    if scenario == "stolen_permit_without_instance_key":
        request = dataclasses.replace(
            request,
            proof_envelope=make_execution_proof(
                signers["attacker"], request.permit_envelope, request.intent, now=now
            ),
        )
    elif scenario not in {
        "valid",
        "stale_consent",
        "revoked_consent",
        "forged_consent",
        "swapped_recovery_certificate",
    }:
        request = dataclasses.replace(
            request,
            proof_envelope=make_execution_proof(
                instance, request.permit_envelope, request.intent, now=now
            ),
        )
    return request, enforcer, now, active_epoch


def evaluate(
    mechanism: str,
    request: AuthorizedEffectRequest,
    enforcer: ProviderAuthorizationEnforcer,
    *,
    now: int,
    active_epoch: int,
) -> tuple[bool, str]:
    if mechanism == "bearer_token":
        return True, "bearer_present"
    if mechanism == "epoch_identity":
        accepted = request.intent.effect.epoch == active_epoch
        return accepted, "active_epoch" if accepted else "inactive_authority_epoch"
    if mechanism == "signed_action_permit":
        decision = enforcer.verify_signed_permit(
            request, now=now, active_epoch=active_epoch
        )
    elif mechanism == "effect_closed_principal_chain":
        decision = enforcer.verify_full_chain(
            request, now=now, active_epoch=active_epoch
        )
    else:
        raise ValueError(mechanism)
    return decision.authorized, ";".join(decision.reasons) if decision.reasons else "authorized"


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: run_authorization_attacks.py SEED TRIALS OUTPUT_CSV", file=sys.stderr)
        return 2
    seed = int(sys.argv[1])
    trials = int(sys.argv[2])
    output = Path(sys.argv[3])
    rng = random.Random(seed)

    signers = {
        "principal": Ed25519Signer("principal:alice"),
        "instance": Ed25519Signer("instance:repaired"),
        "attacker": Ed25519Signer("attacker"),
        "attestation": Ed25519Signer("rats-verifier"),
        "recovery": Ed25519Signer("recovery-control"),
        "barrier": Ed25519Signer("barrier-control"),
        "delegation": Ed25519Signer("delegation-control"),
        "permit": Ed25519Signer("permit-control"),
    }
    trust = TrustStore()
    for role, name in (
        ("principal", "principal"),
        ("agent_instance", "instance"),
        ("agent_instance", "attacker"),
        ("attestation_verifier", "attestation"),
        ("recovery_authority", "recovery"),
        ("authority_barrier_authority", "barrier"),
        ("delegation_authority", "delegation"),
        ("permit_authority", "permit"),
    ):
        trust.register(role, signers[name])

    output.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "seed",
        "trial",
        "scenario",
        "mechanism",
        "attack",
        "accepted",
        "unsafe_accept",
        "false_reject",
        "reason",
        "latency_ns",
    )
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for trial in range(trials):
            scenario = SCENARIOS[trial % len(SCENARIOS)]
            request, enforcer, now, active_epoch = prepare_case(
                scenario=scenario,
                seed=seed,
                trial=trial,
                rng=rng,
                trust=trust,
                signers=signers,
            )
            attack = scenario != "valid"
            for mechanism in MECHANISMS:
                started = time.perf_counter_ns()
                accepted, reason = evaluate(
                    mechanism,
                    request,
                    enforcer,
                    now=now,
                    active_epoch=active_epoch,
                )
                latency = time.perf_counter_ns() - started
                writer.writerow(
                    {
                        "seed": seed,
                        "trial": trial,
                        "scenario": scenario,
                        "mechanism": mechanism,
                        "attack": attack,
                        "accepted": accepted,
                        "unsafe_accept": attack and accepted,
                        "false_reject": not attack and not accepted,
                        "reason": reason,
                        "latency_ns": latency,
                    }
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
