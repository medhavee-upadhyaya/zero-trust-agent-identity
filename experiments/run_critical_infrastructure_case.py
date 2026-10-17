from __future__ import annotations

import csv
import dataclasses
import random
import sys
import tempfile
import time
from dataclasses import dataclass
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


SCENARIOS = (
    "valid_workflow",
    "exact_replay",
    "missing_second_approval",
    "duplicate_operator",
    "forged_operator",
    "incomplete_provider_barrier",
    "cloud_target_substitution",
    "delegated_scope_widening",
    "stale_workload_identity",
    "wrong_agent_instance",
    "old_authority_epoch",
    "unsafe_workflow_order",
)
PROVIDERS = (
    "crew-access",
    "notification",
    "switch-gateway",
    "work-order",
)


@dataclass
class Context:
    now: int
    trust: TrustStore
    issuer: Ed25519Signer
    federation: Ed25519Signer
    utility: Ed25519Signer
    contractor: Ed25519Signer
    barrier_signer: Ed25519Signer
    cloud_signer: Ed25519Signer
    instance: Ed25519Signer
    supervisor: Ed25519Signer
    safety_officer: Ed25519Signer
    attacker: Ed25519Signer
    evidence: WorkloadIdentityEvidence
    identity_binding: FederatedIdentityBinding
    root: OrganizationDelegation
    child: OrganizationDelegation
    barrier: AuthorityBarrierCertificate
    authorizer: CriticalInfrastructureAuthorizer
    twin: GridMaintenanceDigitalTwin


def make_context(seed: int, trial: int, database_path: Path) -> Context:
    now = 90_000 + trial * 10
    issuer = Ed25519Signer(f"spire:utility:{seed}:{trial}")
    federation = Ed25519Signer(f"federation:utility:{seed}:{trial}")
    utility = Ed25519Signer(f"authority:utility:{seed}:{trial}")
    contractor = Ed25519Signer(f"authority:contractor:{seed}:{trial}")
    barrier_signer = Ed25519Signer(f"barrier:utility:{seed}:{trial}")
    cloud_signer = Ed25519Signer(f"cloud-binding:utility:{seed}:{trial}")
    instance = Ed25519Signer(f"instance:restoration:{seed}:{trial}")
    supervisor = Ed25519Signer(f"operator:supervisor:{seed}:{trial}")
    safety_officer = Ed25519Signer(f"operator:safety:{seed}:{trial}")
    attacker = Ed25519Signer(f"attacker:{seed}:{trial}")
    trust = TrustStore()
    for role, signer in (
        ("workload_identity_issuer", issuer),
        ("federation_authority", federation),
        ("organization_authority", utility),
        ("organization_authority", contractor),
        ("authority_barrier_authority", barrier_signer),
        ("cloud_binding_authority", cloud_signer),
        ("agent_instance", instance),
        ("operator", supervisor),
        ("operator", safety_officer),
    ):
        trust.register(role, signer)
    evidence = WorkloadIdentityEvidence(
        "spiffe://utility.example/agent/restoration/instance-7",
        "https://spire.utility.example",
        "spiffe://utility.example/agent/restoration/instance-7",
        "switch-gateway",
        "utility",
        "restoration-agent",
        instance.signer_id,
        instance.public_key_fingerprint,
        now - 100,
        now + 600,
        f"nonce:{seed}:{trial}",
    )
    identity_binding = FederatedIdentityBinding(
        f"identity-binding:{seed}:{trial}",
        "operator:alice",
        "agent/restoration",
        "restoration-agent",
        instance.signer_id,
        "utility",
        f"delegation-child:{seed}:{trial}",
        7,
        "switch-gateway",
        PROVIDERS,
        digest(evidence),
        now - 90,
        now + 500,
    )
    full_scope = Scope.of(
        {"create_work_order", "grant_crew_access", "isolate", "notify", "restore"},
        {"feeder:7"},
    )
    root = OrganizationDelegation(
        f"delegation-root:{seed}:{trial}",
        "utility",
        "utility.example",
        "operator:alice",
        "agent:coordinator",
        "switch-gateway",
        full_scope,
        "",
        0,
        now - 80,
        now + 400,
        f"nonce-root:{seed}:{trial}",
    )
    child = OrganizationDelegation(
        f"delegation-child:{seed}:{trial}",
        "contractor",
        "contractor.example",
        "agent:coordinator",
        "restoration-agent",
        "switch-gateway",
        full_scope,
        digest(root),
        1,
        now - 70,
        now + 300,
        f"nonce-child:{seed}:{trial}",
    )
    barrier = AuthorityBarrierCertificate(
        f"transition:{seed}:{trial}",
        f"incident:{seed}:{trial}",
        "agent/restoration",
        1,
        6,
        7,
        digest({"transition": seed, "trial": trial}),
        PROVIDERS,
        tuple(digest({"provider": provider, "trial": trial}) for provider in PROVIDERS),
        now - 60,
    )
    identity_verifier = FederatedIdentityVerifier(
        trust,
        issuer_trust_domains={issuer.signer_id: "utility.example"},
        issuer_urls={issuer.signer_id: "https://spire.utility.example"},
    )
    delegation_verifier = DelegationChainVerifier(
        trust,
        signer_domains={
            utility.signer_id: "utility.example",
            contractor.signer_id: "contractor.example",
        },
        signer_organizations={
            utility.signer_id: "utility",
            contractor.signer_id: "contractor",
        },
        allowed_domain_edges=frozenset(
            {("utility.example", "contractor.example")}
        ),
    )
    policy = CriticalInfrastructurePolicy(
        "switch-gateway",
        PROVIDERS,
        frozenset(full_scope.actions),
        frozenset(full_scope.resources),
        frozenset({"isolate", "restore"}),
        ("switching_supervisor", "safety_officer"),
    )
    authorizer = CriticalInfrastructureAuthorizer(
        trust_store=trust,
        identity_verifier=identity_verifier,
        delegation_verifier=delegation_verifier,
        policy=policy,
    )
    return Context(
        now,
        trust,
        issuer,
        federation,
        utility,
        contractor,
        barrier_signer,
        cloud_signer,
        instance,
        supervisor,
        safety_officer,
        attacker,
        evidence,
        identity_binding,
        root,
        child,
        barrier,
        authorizer,
        GridMaintenanceDigitalTwin(database_path),
    )


def command(context: Context, operation: str, index: int) -> InfrastructureCommand:
    return InfrastructureCommand(
        f"command:{operation}:{index}",
        "maintenance-case-7",
        "operator:alice",
        "agent/restoration",
        "utility",
        "restoration-agent",
        context.instance.signer_id,
        7,
        operation,
        "feeder:7",
        CloudEffectTarget(
            "azure", "tenant-test", "grid-digital-twin", "feeder:7", operation
        ),
        f"maintenance-case-7:{operation}:{index}",
        "safety-case:approved:7",
        context.now + index,
        context.now + 200,
    )


def bundle(
    context: Context,
    current: InfrastructureCommand,
    *,
    scenario: str = "valid_workflow",
) -> InfrastructureAuthorizationBundle:
    evidence = context.evidence
    identity_binding = context.identity_binding
    child = context.child
    barrier = context.barrier
    target = current.target
    command_signer = context.instance
    approval_signers = [context.supervisor, context.safety_officer]
    approval_roles = ["switching_supervisor", "safety_officer"]
    approval_count = 2 if current.operation in {"isolate", "restore"} else 1
    if current.operation == "isolate":
        if scenario == "missing_second_approval":
            approval_count = 1
        elif scenario == "duplicate_operator":
            approval_signers[1] = context.supervisor
        elif scenario == "forged_operator":
            approval_signers[1] = context.attacker
        elif scenario == "incomplete_provider_barrier":
            barrier = dataclasses.replace(
                barrier,
                provider_ids=("switch-gateway", "work-order"),
                acknowledgement_digests=("ack-switch", "ack-work"),
            )
        elif scenario == "cloud_target_substitution":
            target = dataclasses.replace(target, resource="feeder:99")
        elif scenario == "delegated_scope_widening":
            child = dataclasses.replace(
                child,
                scope=Scope.of(context.root.scope.actions, {"feeder:7", "feeder:99"}),
            )
        elif scenario == "stale_workload_identity":
            evidence = dataclasses.replace(evidence, expires_at=current.issued_at)
            identity_binding = dataclasses.replace(
                identity_binding,
                evidence_digest=digest(evidence),
                expires_at=current.issued_at,
            )
        elif scenario == "wrong_agent_instance":
            current = dataclasses.replace(current, instance_id=context.attacker.signer_id)
        elif scenario == "old_authority_epoch":
            current = dataclasses.replace(current, authority_epoch=6)

    cloud_binding = CloudAuthorityBinding(
        f"cloud:{current.command_id}",
        current.principal_id,
        current.agent_id,
        current.instance_id,
        current.workload_id,
        current.organization_id,
        current.authority_epoch,
        digest(child),
        digest(evidence),
        digest(barrier),
        target,
        current.issued_at,
        current.expires_at,
    )
    approvals = []
    for index in range(approval_count):
        signer = approval_signers[index]
        approval = OperatorApproval(
            f"approval:{current.command_id}:{index}",
            signer.signer_id,
            approval_roles[index],
            digest(current),
            current.issued_at,
            current.expires_at,
        )
        approvals.append(signer.sign("operator_approval", approval))
    return InfrastructureAuthorizationBundle(
        command_signer.sign("infrastructure_command", current),
        context.issuer.sign("workload_identity_evidence", evidence),
        context.federation.sign("federated_identity_binding", identity_binding),
        (
            context.utility.sign("organization_delegation", context.root),
            context.contractor.sign("organization_delegation", child),
        ),
        context.barrier_signer.sign("authority_barrier", barrier),
        context.cloud_signer.sign("cloud_authority_binding", cloud_binding),
        tuple(approvals),
    )


def authorize_and_execute(
    context: Context,
    current: InfrastructureCommand,
    scenario: str,
):
    current_bundle = bundle(context, current, scenario=scenario)
    actual_command = current_bundle.command_envelope.payload
    started = time.perf_counter_ns()
    decision = context.authorizer.authorize(
        current_bundle,
        now=current.issued_at,
    )
    result = context.twin.execute(actual_command, decision)
    return decision, result, time.perf_counter_ns() - started


def run_case(seed: int, trial: int, scenario: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as directory:
        context = make_context(seed, trial, Path(directory) / "digital-twin.sqlite3")
        latency_ns = 0
        setup_ok = True
        if scenario != "unsafe_workflow_order":
            for index, operation in enumerate(("create_work_order", "grant_crew_access")):
                decision, result, elapsed = authorize_and_execute(
                    context, command(context, operation, index), "valid_workflow"
                )
                latency_ns += elapsed
                setup_ok = setup_ok and decision.authorized and result.status == "committed"

        isolate = command(context, "isolate", 2)
        decision, result, elapsed = authorize_and_execute(context, isolate, scenario)
        latency_ns += elapsed
        replayed = False
        if scenario in {"valid_workflow", "exact_replay"}:
            for index, operation in ((3, "notify"), (4, "restore")):
                final_decision, final_result, elapsed = authorize_and_execute(
                    context,
                    command(context, operation, index),
                    "valid_workflow",
                )
                latency_ns += elapsed
                setup_ok = (
                    setup_ok
                    and final_decision.authorized
                    and final_result.status == "committed"
                )
                result = final_result
            if scenario == "exact_replay":
                replay_decision, replay_result, elapsed = authorize_and_execute(
                    context,
                    command(context, "restore", 4),
                    "valid_workflow",
                )
                latency_ns += elapsed
                replayed = replay_decision.authorized and replay_result.replayed

        final_state = context.twin.state("maintenance-case-7") or "none"
        effect_count = context.twin.effect_count("maintenance-case-7")
        if scenario == "valid_workflow":
            correct = setup_ok and final_state == "restored" and effect_count == 5
        elif scenario == "exact_replay":
            correct = setup_ok and replayed and final_state == "restored" and effect_count == 5
        elif scenario == "unsafe_workflow_order":
            correct = (
                decision.authorized
                and result.status == "rejected"
                and result.reason == "unsafe_workflow_order"
                and effect_count == 0
            )
        else:
            correct = (
                setup_ok
                and not decision.authorized
                and result.status == "rejected"
                and final_state == "crew_access_granted"
                and effect_count == 2
            )
        return {
            "seed": seed,
            "trial": trial,
            "scenario": scenario,
            "authorized_target": decision.authorized,
            "authorization_reasons": ";".join(decision.reasons),
            "effect_status": result.status,
            "effect_reason": result.reason,
            "final_state": final_state,
            "effect_count": effect_count,
            "replayed": replayed,
            "unsafe_isolation": final_state in {"isolated", "notified", "restored"}
            and scenario not in {"valid_workflow", "exact_replay"},
            "correct": correct,
            "latency_ns": latency_ns,
            "execution_mode": "single_host_digital_twin",
        }


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: run_critical_infrastructure_case.py SEED CYCLES OUTPUT_CSV",
            file=sys.stderr,
        )
        return 2
    seed = int(sys.argv[1])
    cycles = int(sys.argv[2])
    output = Path(sys.argv[3])
    if cycles < 1:
        raise ValueError("cycles must be positive")
    cases = [scenario for _ in range(cycles) for scenario in SCENARIOS]
    random.Random(seed).shuffle(cases)
    rows = [run_case(seed, trial, scenario) for trial, scenario in enumerate(cases)]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=tuple(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
