from __future__ import annotations

import csv
import random
import sys
import tempfile
import time
from pathlib import Path

from ztai import (
    Ed25519Signer,
    EffectRequest,
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


PROVIDER_IDS = ("payment", "inventory", "notification", "callback")
STEP_DEFINITIONS = (
    ("charge", "payment", False),
    ("reserve", "inventory", False),
    ("notify", "notification", True),
    ("callback", "callback", False),
)
MECHANISMS = (
    "effect_closed_recovery",
    "blind_successor",
    "same_epoch_replay_then_retire",
    "quarantine",
)
FAULTS = ("crash_before_commit", "crash_after_commit")


def _bindings(
    provider_ids: tuple[str, ...],
    databases: dict[str, ProviderDatabase],
    processes: dict[str, ProviderProcess],
) -> dict[str, ProviderBinding]:
    return {
        provider_id: ProviderBinding(
            provider_id,
            databases[provider_id],
            ProviderClient(processes[provider_id].base_url, timeout=0.25),
        )
        for provider_id in provider_ids
    }


def _engine(
    *,
    store: WorkflowStore,
    provider_ids: tuple[str, ...],
    databases: dict[str, ProviderDatabase],
    processes: dict[str, ProviderProcess],
    trust: TrustStore,
    incident_signer: Ed25519Signer,
    closure_signer: Ed25519Signer,
    attestation_signer: Ed25519Signer,
    recovery_signer: Ed25519Signer,
) -> WorkflowRecoveryEngine:
    return WorkflowRecoveryEngine(
        store=store,
        providers=_bindings(provider_ids, databases, processes),
        trust_store=trust,
        incident_signer=incident_signer,
        closure_signer=closure_signer,
        attestation_signer=attestation_signer,
        recovery_signer=recovery_signer,
    )


def _request(
    *,
    workflow_id: str,
    incident_id: str,
    workload_id: str,
    epoch: int,
    step: WorkflowStepSpec,
) -> EffectRequest:
    return EffectRequest(
        incident_id=incident_id,
        step_id=step.step_id,
        workload_id=workload_id,
        epoch=epoch,
        operation_digest=step.operation_digest,
        idempotency_key=f"{workflow_id}:{step.step_id}:epoch:{epoch}",
    )


def _retire_all(
    provider_ids: tuple[str, ...],
    databases: dict[str, ProviderDatabase],
    workload_id: str,
    old_epoch: int,
    now: int,
) -> None:
    for provider_id in provider_ids:
        database = databases[provider_id]
        if database.epoch_state(workload_id, old_epoch) == "active":
            if not database.retire_epoch(workload_id, old_epoch, now):
                raise AssertionError("provider refused old epoch retirement")


def _activate_all(
    provider_ids: tuple[str, ...],
    databases: dict[str, ProviderDatabase],
    workload_id: str,
    new_epoch: int,
    now: int,
) -> None:
    for provider_id in provider_ids:
        database = databases[provider_id]
        if database.active_epoch(workload_id) is None:
            if not database.activate_epoch(workload_id, new_epoch, now):
                raise AssertionError("provider refused successor epoch activation")


def _effect_counts(
    *,
    steps: tuple[WorkflowStepSpec, ...],
    incident_id: str,
    databases: dict[str, ProviderDatabase],
) -> list[int]:
    return [
        databases[step.provider_id].effect_count(incident_id, step.step_id)
        for step in steps
    ]


def _create_main_case(
    *,
    trial: int,
    seed: int,
    mechanism: str,
    store: WorkflowStore,
    databases: dict[str, ProviderDatabase],
    processes: dict[str, ProviderProcess],
    trust: TrustStore,
    incident_signer: Ed25519Signer,
    closure_signer: Ed25519Signer,
    attestation_signer: Ed25519Signer,
    recovery_signer: Ed25519Signer,
) -> dict[str, object]:
    workflow_id = f"wf-{seed}-{trial}-{mechanism}"
    incident_id = f"inc-{seed}-{trial}-{mechanism}"
    workload_id = f"agent/{seed}/{trial}/{mechanism}"
    old_epoch = trial * 2 + 1
    new_epoch = old_epoch + 1
    crash_position = trial % len(STEP_DEFINITIONS)
    fault = FAULTS[(trial // len(STEP_DEFINITIONS)) % len(FAULTS)]
    delayed_duplicates = trial % 3 == 0
    controller_restart = trial % 4 == 0
    outage_injected = trial % 5 == 0 and mechanism == "effect_closed_recovery"
    steps = tuple(
        WorkflowStepSpec(
            position,
            step_id,
            provider_id,
            f"op:{workflow_id}:{step_id}",
            idempotent,
        )
        for position, (step_id, provider_id, idempotent) in enumerate(STEP_DEFINITIONS)
    )
    store.create_workflow(
        workflow_id=workflow_id,
        incident_id=incident_id,
        workload_id=workload_id,
        old_epoch=old_epoch,
        new_epoch=new_epoch,
        steps=steps,
        now=10_000 + trial,
    )
    for provider_id in PROVIDER_IDS:
        databases[provider_id].establish_epoch(workload_id, old_epoch, 9_000 + trial)

    engine = _engine(
        store=store,
        provider_ids=PROVIDER_IDS,
        databases=databases,
        processes=processes,
        trust=trust,
        incident_signer=incident_signer,
        closure_signer=closure_signer,
        attestation_signer=attestation_signer,
        recovery_signer=recovery_signer,
    )
    for step in steps[:crash_position]:
        result = engine.providers[step.provider_id].client.execute(
            _request(
                workflow_id=workflow_id,
                incident_id=incident_id,
                workload_id=workload_id,
                epoch=old_epoch,
                step=step,
            )
        )
        if result.status != "committed":
            raise AssertionError("prefix execution failed")
        store.set_step_state(workflow_id, step.step_id, "committed")

    crash_step = steps[crash_position]
    crash_request = _request(
        workflow_id=workflow_id,
        incident_id=incident_id,
        workload_id=workload_id,
        epoch=old_epoch,
        step=crash_step,
    )
    crash_message_id = f"{workflow_id}:crash"
    store.enqueue(
        message_id=crash_message_id,
        workflow_id=workflow_id,
        provider_id=crash_step.provider_id,
        request=crash_request,
        available_at=10_000 + trial,
    )
    crash_attempt = store.deliver(
        crash_message_id,
        engine.providers[crash_step.provider_id].client,
        now=10_000 + trial,
        fault=fault,
    )
    if crash_attempt.queue_status != "ambiguous":
        raise AssertionError("crash did not create an ambiguous delivery")
    processes[crash_step.provider_id].restart()

    for step in steps[crash_position + 1 :]:
        request = _request(
            workflow_id=workflow_id,
            incident_id=incident_id,
            workload_id=workload_id,
            epoch=old_epoch,
            step=step,
        )
        store.enqueue(
            message_id=f"{workflow_id}:{step.step_id}:a",
            workflow_id=workflow_id,
            provider_id=step.provider_id,
            request=request,
            available_at=99_999,
        )
        if delayed_duplicates:
            store.enqueue(
                message_id=f"{workflow_id}:{step.step_id}:b",
                workflow_id=workflow_id,
                provider_id=step.provider_id,
                request=request,
                available_at=99_999,
            )
    if controller_restart:
        store.restart_controller(workflow_id, 10_050 + trial)

    started = time.perf_counter_ns()
    resumed = False
    authorized = False
    certificate_valid: bool | None = None
    scope_subset: bool | None = None
    old_authority_after_incident = False
    outage_first_quarantined: bool | None = None
    stale_deliveries_accepted = 0

    if mechanism == "effect_closed_recovery":
        engine = _engine(
            store=store,
            provider_ids=PROVIDER_IDS,
            databases=databases,
            processes=processes,
            trust=trust,
            incident_signer=incident_signer,
            closure_signer=closure_signer,
            attestation_signer=attestation_signer,
            recovery_signer=recovery_signer,
        )
        if outage_injected:
            outage_provider = PROVIDER_IDS[(crash_position + 1) % len(PROVIDER_IDS)]
            processes[outage_provider].stop()
            first = engine.recover(
                workflow_id=workflow_id,
                previous_scope=Scope.of(
                    {item[0] for item in STEP_DEFINITIONS} | {"refund"},
                    {f"order:{trial}"},
                    500,
                ),
                current_policy=Scope.of(
                    {item[0] for item in STEP_DEFINITIONS},
                    {f"order:{trial}"},
                    200,
                ),
                manifest_hash="manifest:approved",
                configuration_hash="config:approved",
                approved_manifest_hashes=frozenset({"manifest:approved"}),
                approved_configuration_hashes=frozenset({"config:approved"}),
                expected_nonce=f"nonce:{workflow_id}:first",
                now=10_100 + trial,
            )
            outage_first_quarantined = first.status is RecoveryStatus.QUARANTINED
            processes[outage_provider].start()
            store.restart_controller(workflow_id, 10_101 + trial)
        engine = _engine(
            store=store,
            provider_ids=PROVIDER_IDS,
            databases=databases,
            processes=processes,
            trust=trust,
            incident_signer=incident_signer,
            closure_signer=closure_signer,
            attestation_signer=attestation_signer,
            recovery_signer=recovery_signer,
        )
        result = engine.recover(
            workflow_id=workflow_id,
            previous_scope=Scope.of(
                {item[0] for item in STEP_DEFINITIONS} | {"refund"},
                {f"order:{trial}"},
                500,
            ),
            current_policy=Scope.of(
                {item[0] for item in STEP_DEFINITIONS},
                {f"order:{trial}"},
                200,
            ),
            manifest_hash="manifest:approved",
            configuration_hash="config:approved",
            approved_manifest_hashes=frozenset({"manifest:approved"}),
            approved_configuration_hashes=frozenset({"config:approved"}),
            expected_nonce=f"nonce:{workflow_id}:final",
            now=10_110 + trial,
        )
        authorized = result.status is RecoveryStatus.AUTHORIZED
        resumed = authorized
        if result.decision.certificate_envelope is not None:
            certificate_valid = trust.verify(
                "recovery_authority",
                result.decision.certificate_envelope,
                "recovery_certificate",
            )
        if result.decision.certificate is not None:
            scope = result.decision.certificate.grant.scope
            prior = Scope.of(
                {item[0] for item in STEP_DEFINITIONS} | {"refund"},
                {f"order:{trial}"},
                500,
            )
            policy = Scope.of(
                {item[0] for item in STEP_DEFINITIONS},
                {f"order:{trial}"},
                200,
            )
            scope_subset = scope.is_subset_of(prior) and scope.is_subset_of(policy)
    elif mechanism == "blind_successor":
        store.cancel_epoch(workflow_id, old_epoch)
        _retire_all(PROVIDER_IDS, databases, workload_id, old_epoch, 10_100 + trial)
        _activate_all(PROVIDER_IDS, databases, workload_id, new_epoch, 10_101 + trial)
        for step in steps:
            result = ProviderClient(processes[step.provider_id].base_url).execute(
                _request(
                    workflow_id=workflow_id,
                    incident_id=incident_id,
                    workload_id=workload_id,
                    epoch=new_epoch,
                    step=step,
                )
            )
            if result.status != "committed":
                raise AssertionError("blind successor execution failed")
        resumed = True
    elif mechanism == "same_epoch_replay_then_retire":
        old_authority_after_incident = True
        for step in steps:
            result = ProviderClient(processes[step.provider_id].base_url).execute(
                _request(
                    workflow_id=workflow_id,
                    incident_id=incident_id,
                    workload_id=workload_id,
                    epoch=old_epoch,
                    step=step,
                )
            )
            if result.status != "committed":
                raise AssertionError("same-epoch replay failed")
        for delivery in store.deliveries(workflow_id):
            attempt = store.deliver(
                delivery.message_id,
                ProviderClient(processes[delivery.provider_id].base_url),
                now=100_000,
            )
            if attempt.execution is not None and attempt.execution.status == "committed":
                stale_deliveries_accepted += 1
        store.cancel_epoch(workflow_id, old_epoch)
        _retire_all(PROVIDER_IDS, databases, workload_id, old_epoch, 10_102 + trial)
        resumed = True
    elif mechanism == "quarantine":
        store.cancel_epoch(workflow_id, old_epoch)
        _retire_all(PROVIDER_IDS, databases, workload_id, old_epoch, 10_100 + trial)
    else:
        raise ValueError(mechanism)

    latency_ns = time.perf_counter_ns() - started
    for delivery in store.deliveries(workflow_id):
        if delivery.state in {"pending", "ambiguous"}:
            attempt = store.deliver(
                delivery.message_id,
                ProviderClient(processes[delivery.provider_id].base_url),
                now=100_000,
            )
            if attempt.execution is not None and attempt.execution.status == "committed":
                stale_deliveries_accepted += 1
    counts = _effect_counts(steps=steps, incident_id=incident_id, databases=databases)
    duplicate_steps = sum(count > 1 for count in counts)
    incomplete_steps = sum(count == 0 for count in counts)
    exact_once = all(count == 1 for count in counts)
    safe_completion = resumed and exact_once and not old_authority_after_incident
    old_epochs_closed = all(
        databases[provider_id].epoch_state(workload_id, old_epoch) == "retired"
        for provider_id in PROVIDER_IDS
    )
    if mechanism == "effect_closed_recovery" and not (
        authorized
        and certificate_valid
        and scope_subset
        and exact_once
        and old_epochs_closed
        and stale_deliveries_accepted == 0
        and (not outage_injected or outage_first_quarantined)
    ):
        raise AssertionError("effect-closed workflow violated an acceptance invariant")

    return {
        "trial": trial,
        "seed": seed,
        "mode": "forward",
        "mechanism": mechanism,
        "crash_step": crash_step.step_id,
        "fault": fault,
        "delayed_duplicates": delayed_duplicates,
        "controller_restart": controller_restart,
        "outage_injected": outage_injected,
        "outage_first_quarantined": outage_first_quarantined,
        "resumed": resumed,
        "authorized": authorized,
        "certificate_valid": certificate_valid,
        "scope_subset": scope_subset,
        "old_authority_after_incident": old_authority_after_incident,
        "old_epochs_closed": old_epochs_closed,
        "stale_deliveries_accepted": stale_deliveries_accepted,
        "completed_step_count": sum(count > 0 for count in counts),
        "duplicate_step_count": duplicate_steps,
        "incomplete_step_count": incomplete_steps,
        "exact_once_workflow": exact_once,
        "safe_completion": safe_completion,
        "recovery_latency_ns": latency_ns,
    }


def _create_compensation_case(
    *,
    trial: int,
    seed: int,
    store: WorkflowStore,
    databases: dict[str, ProviderDatabase],
    processes: dict[str, ProviderProcess],
    trust: TrustStore,
    incident_signer: Ed25519Signer,
    closure_signer: Ed25519Signer,
    attestation_signer: Ed25519Signer,
    recovery_signer: Ed25519Signer,
) -> dict[str, object]:
    mechanism = "effect_closed_compensation"
    workflow_id = f"comp-{seed}-{trial}"
    incident_id = f"comp-inc-{seed}-{trial}"
    workload_id = f"agent/comp/{seed}/{trial}"
    old_epoch = 1_000_000 + trial * 2
    new_epoch = old_epoch + 1
    fault = FAULTS[trial % len(FAULTS)]
    steps = (
        WorkflowStepSpec(0, "charge", "payment", f"op:{workflow_id}:charge", False),
        WorkflowStepSpec(1, "refund", "payment", f"op:{workflow_id}:refund", False),
    )
    store.create_workflow(
        workflow_id=workflow_id,
        incident_id=incident_id,
        workload_id=workload_id,
        old_epoch=old_epoch,
        new_epoch=new_epoch,
        steps=steps,
        now=20_000 + trial,
    )
    databases["payment"].establish_epoch(workload_id, old_epoch, 19_000 + trial)
    engine = _engine(
        store=store,
        provider_ids=("payment",),
        databases=databases,
        processes=processes,
        trust=trust,
        incident_signer=incident_signer,
        closure_signer=closure_signer,
        attestation_signer=attestation_signer,
        recovery_signer=recovery_signer,
    )
    charge = _request(
        workflow_id=workflow_id,
        incident_id=incident_id,
        workload_id=workload_id,
        epoch=old_epoch,
        step=steps[0],
    )
    if engine.providers["payment"].client.execute(charge).status != "committed":
        raise AssertionError("charge failed before compensation")
    refund = _request(
        workflow_id=workflow_id,
        incident_id=incident_id,
        workload_id=workload_id,
        epoch=old_epoch,
        step=steps[1],
    )
    store.enqueue(
        message_id=f"{workflow_id}:refund",
        workflow_id=workflow_id,
        provider_id="payment",
        request=refund,
        available_at=20_000 + trial,
    )
    attempt = store.deliver(
        f"{workflow_id}:refund",
        engine.providers["payment"].client,
        now=20_000 + trial,
        fault=fault,
    )
    if attempt.queue_status != "ambiguous":
        raise AssertionError("refund crash did not produce ambiguity")
    processes["payment"].restart()
    if trial % 3 == 0:
        store.restart_controller(workflow_id, 20_050 + trial)
    started = time.perf_counter_ns()
    outage_injected = trial % 5 == 0
    outage_first_quarantined: bool | None = None
    engine = _engine(
        store=store,
        provider_ids=("payment",),
        databases=databases,
        processes=processes,
        trust=trust,
        incident_signer=incident_signer,
        closure_signer=closure_signer,
        attestation_signer=attestation_signer,
        recovery_signer=recovery_signer,
    )
    previous_scope = Scope.of({"charge", "refund"}, {f"order:{trial}"}, 500)
    current_policy = Scope.of({"refund"}, {f"order:{trial}"}, 500)
    if outage_injected:
        processes["payment"].stop()
        first = engine.recover(
            workflow_id=workflow_id,
            previous_scope=previous_scope,
            current_policy=current_policy,
            manifest_hash="manifest:approved",
            configuration_hash="config:approved",
            approved_manifest_hashes=frozenset({"manifest:approved"}),
            approved_configuration_hashes=frozenset({"config:approved"}),
            expected_nonce=f"nonce:{workflow_id}:first",
            now=20_090 + trial,
        )
        outage_first_quarantined = first.status is RecoveryStatus.QUARANTINED
        processes["payment"].start()
        store.restart_controller(workflow_id, 20_091 + trial)
        engine = _engine(
            store=store,
            provider_ids=("payment",),
            databases=databases,
            processes=processes,
            trust=trust,
            incident_signer=incident_signer,
            closure_signer=closure_signer,
            attestation_signer=attestation_signer,
            recovery_signer=recovery_signer,
        )
    result = engine.recover(
        workflow_id=workflow_id,
        previous_scope=previous_scope,
        current_policy=current_policy,
        manifest_hash="manifest:approved",
        configuration_hash="config:approved",
        approved_manifest_hashes=frozenset({"manifest:approved"}),
        approved_configuration_hashes=frozenset({"config:approved"}),
        expected_nonce=f"nonce:{workflow_id}",
        now=20_100 + trial,
    )
    latency_ns = time.perf_counter_ns() - started
    counts = _effect_counts(steps=steps, incident_id=incident_id, databases=databases)
    exact_once = counts == [1, 1]
    certificate_valid = (
        result.decision.certificate_envelope is not None
        and trust.verify(
            "recovery_authority",
            result.decision.certificate_envelope,
            "recovery_certificate",
        )
    )
    scope_subset = False
    if result.decision.certificate is not None:
        scope = result.decision.certificate.grant.scope
        scope_subset = scope.is_subset_of(previous_scope) and scope.is_subset_of(current_policy)
    old_epoch_closed = databases["payment"].epoch_state(workload_id, old_epoch) == "retired"
    if not (
        result.status is RecoveryStatus.AUTHORIZED
        and certificate_valid
        and scope_subset
        and exact_once
        and old_epoch_closed
        and (not outage_injected or outage_first_quarantined)
    ):
        raise AssertionError("compensation recovery violated an acceptance invariant")
    return {
        "trial": trial,
        "seed": seed,
        "mode": "compensation",
        "mechanism": mechanism,
        "crash_step": "refund",
        "fault": fault,
        "delayed_duplicates": False,
        "controller_restart": trial % 3 == 0,
        "outage_injected": outage_injected,
        "outage_first_quarantined": outage_first_quarantined,
        "resumed": True,
        "authorized": True,
        "certificate_valid": certificate_valid,
        "scope_subset": scope_subset,
        "old_authority_after_incident": False,
        "old_epochs_closed": old_epoch_closed,
        "stale_deliveries_accepted": 0,
        "completed_step_count": 2,
        "duplicate_step_count": 0,
        "incomplete_step_count": 0,
        "exact_once_workflow": exact_once,
        "safe_completion": exact_once,
        "recovery_latency_ns": latency_ns,
    }


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: run_workflow_faults.py SEED TRIALS OUTPUT_CSV", file=sys.stderr)
        return 2
    seed = int(sys.argv[1])
    trials = int(sys.argv[2])
    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    fields = (
        "trial",
        "seed",
        "mode",
        "mechanism",
        "crash_step",
        "fault",
        "delayed_duplicates",
        "controller_restart",
        "outage_injected",
        "outage_first_quarantined",
        "resumed",
        "authorized",
        "certificate_valid",
        "scope_subset",
        "old_authority_after_incident",
        "old_epochs_closed",
        "stale_deliveries_accepted",
        "completed_step_count",
        "duplicate_step_count",
        "incomplete_step_count",
        "exact_once_workflow",
        "safe_completion",
        "recovery_latency_ns",
    )
    provider_signers = {provider_id: Ed25519Signer(provider_id) for provider_id in PROVIDER_IDS}
    incident_signer = Ed25519Signer("incident-control")
    closure_signer = Ed25519Signer("closure-verifier")
    attestation_signer = Ed25519Signer("rats-verifier")
    recovery_signer = Ed25519Signer("recovery-control")
    trust = TrustStore()
    for signer in provider_signers.values():
        trust.register("provider", signer)
    for role, signer in (
        ("incident_authority", incident_signer),
        ("closure_authority", closure_signer),
        ("attestation_verifier", attestation_signer),
        ("recovery_authority", recovery_signer),
    ):
        trust.register(role, signer)

    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        store = WorkflowStore(root / "workflows.sqlite3")
        databases = {
            provider_id: ProviderDatabase(root / f"{provider_id}.sqlite3")
            for provider_id in PROVIDER_IDS
        }
        processes = {
            provider_id: ProviderProcess(
                databases[provider_id].path,
                provider_signers[provider_id],
                enable_faults=True,
            ).start()
            for provider_id in PROVIDER_IDS
        }
        try:
            with output.open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for trial in range(trials):
                    mechanisms = list(MECHANISMS)
                    rng.shuffle(mechanisms)
                    for mechanism in mechanisms:
                        writer.writerow(
                            _create_main_case(
                                trial=trial,
                                seed=seed,
                                mechanism=mechanism,
                                store=store,
                                databases=databases,
                                processes=processes,
                                trust=trust,
                                incident_signer=incident_signer,
                                closure_signer=closure_signer,
                                attestation_signer=attestation_signer,
                                recovery_signer=recovery_signer,
                            )
                        )
                        handle.flush()
                    writer.writerow(
                        _create_compensation_case(
                            trial=trial,
                            seed=seed,
                            store=store,
                            databases=databases,
                            processes=processes,
                            trust=trust,
                            incident_signer=incident_signer,
                            closure_signer=closure_signer,
                            attestation_signer=attestation_signer,
                            recovery_signer=recovery_signer,
                        )
                    )
                    handle.flush()
        finally:
            for process in processes.values():
                process.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
