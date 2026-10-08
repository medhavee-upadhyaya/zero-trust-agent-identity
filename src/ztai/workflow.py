from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .provider import EffectRequest, ExecutionResult, ProviderClient


WORKFLOW_SCHEMA = """
CREATE TABLE IF NOT EXISTS workflows (
    workflow_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    workload_id TEXT NOT NULL,
    old_epoch INTEGER NOT NULL,
    new_epoch INTEGER NOT NULL,
    declared_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    controller_generation INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS workflow_steps (
    workflow_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    step_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    operation_digest TEXT NOT NULL,
    idempotent INTEGER NOT NULL CHECK (idempotent IN (0, 1)),
    state TEXT NOT NULL,
    instruction TEXT NOT NULL,
    PRIMARY KEY (workflow_id, step_id),
    UNIQUE (workflow_id, position),
    FOREIGN KEY (workflow_id) REFERENCES workflows(workflow_id)
);

CREATE TABLE IF NOT EXISTS deliveries (
    message_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    workload_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    operation_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'claimed', 'ambiguous', 'delivered', 'rejected', 'canceled')
    ),
    attempts INTEGER NOT NULL,
    last_reason TEXT NOT NULL,
    available_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (workflow_id) REFERENCES workflows(workflow_id)
);
CREATE INDEX IF NOT EXISTS deliveries_by_workflow_epoch
ON deliveries(workflow_id, epoch, state);
"""


@dataclass(frozen=True)
class WorkflowStepSpec:
    position: int
    step_id: str
    provider_id: str
    operation_digest: str
    idempotent: bool


@dataclass(frozen=True)
class WorkflowSnapshot:
    workflow_id: str
    incident_id: str
    workload_id: str
    old_epoch: int
    new_epoch: int
    declared_at: int
    status: str
    controller_generation: int


@dataclass(frozen=True)
class DeliveryRecord:
    message_id: str
    workflow_id: str
    provider_id: str
    request: EffectRequest
    state: str
    attempts: int
    last_reason: str
    available_at: int


@dataclass(frozen=True)
class DeliveryAttempt:
    message_id: str
    queue_status: str
    execution: ExecutionResult | None


class WorkflowStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(WORKFLOW_SCHEMA)

    def create_workflow(
        self,
        *,
        workflow_id: str,
        incident_id: str,
        workload_id: str,
        old_epoch: int,
        new_epoch: int,
        steps: tuple[WorkflowStepSpec, ...],
        now: int,
    ) -> None:
        positions = [step.position for step in steps]
        step_ids = [step.step_id for step in steps]
        if positions != list(range(len(steps))):
            raise ValueError("workflow positions must be contiguous and zero-based")
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("workflow step identifiers must be unique")
        if new_epoch <= old_epoch:
            raise ValueError("new epoch must be greater than old epoch")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO workflows(workflow_id, incident_id, workload_id, old_epoch, "
                "new_epoch, declared_at, status, controller_generation, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'running', 0, ?)",
                (workflow_id, incident_id, workload_id, old_epoch, new_epoch, now, now),
            )
            connection.executemany(
                "INSERT INTO workflow_steps(workflow_id, position, step_id, provider_id, "
                "operation_digest, idempotent, state, instruction) "
                "VALUES (?, ?, ?, ?, ?, ?, 'not_started', 'none')",
                (
                    (
                        workflow_id,
                        step.position,
                        step.step_id,
                        step.provider_id,
                        step.operation_digest,
                        int(step.idempotent),
                    )
                    for step in steps
                ),
            )
            connection.commit()

    def snapshot(self, workflow_id: str) -> WorkflowSnapshot:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM workflows WHERE workflow_id=?", (workflow_id,)
            ).fetchone()
        if row is None:
            raise KeyError(workflow_id)
        return WorkflowSnapshot(
            workflow_id=row["workflow_id"],
            incident_id=row["incident_id"],
            workload_id=row["workload_id"],
            old_epoch=row["old_epoch"],
            new_epoch=row["new_epoch"],
            declared_at=row["declared_at"],
            status=row["status"],
            controller_generation=row["controller_generation"],
        )

    def steps(self, workflow_id: str) -> tuple[WorkflowStepSpec, ...]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM workflow_steps WHERE workflow_id=? ORDER BY position",
                (workflow_id,),
            ).fetchall()
        return tuple(
            WorkflowStepSpec(
                row["position"],
                row["step_id"],
                row["provider_id"],
                row["operation_digest"],
                bool(row["idempotent"]),
            )
            for row in rows
        )

    def set_status(self, workflow_id: str, status: str, now: int) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE workflows SET status=?, updated_at=? WHERE workflow_id=?",
                (status, now, workflow_id),
            )
        if cursor.rowcount != 1:
            raise KeyError(workflow_id)

    def restart_controller(self, workflow_id: str, now: int) -> int:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE workflows SET controller_generation=controller_generation+1, "
                "updated_at=? WHERE workflow_id=?",
                (now, workflow_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise KeyError(workflow_id)
            generation = connection.execute(
                "SELECT controller_generation FROM workflows WHERE workflow_id=?",
                (workflow_id,),
            ).fetchone()[0]
            connection.commit()
        return int(generation)

    def set_step_state(
        self,
        workflow_id: str,
        step_id: str,
        state: str,
        instruction: str = "none",
    ) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE workflow_steps SET state=?, instruction=? "
                "WHERE workflow_id=? AND step_id=?",
                (state, instruction, workflow_id, step_id),
            )
        if cursor.rowcount != 1:
            raise KeyError((workflow_id, step_id))

    def step_states(self, workflow_id: str) -> dict[str, tuple[str, str]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT step_id, state, instruction FROM workflow_steps "
                "WHERE workflow_id=? ORDER BY position",
                (workflow_id,),
            ).fetchall()
        return {row["step_id"]: (row["state"], row["instruction"]) for row in rows}

    def enqueue(
        self,
        *,
        message_id: str,
        workflow_id: str,
        provider_id: str,
        request: EffectRequest,
        available_at: int,
    ) -> None:
        snapshot = self.snapshot(workflow_id)
        if request.incident_id != snapshot.incident_id:
            raise ValueError("delivery incident does not match workflow")
        if request.workload_id != snapshot.workload_id:
            raise ValueError("delivery workload does not match workflow")
        if request.epoch != snapshot.old_epoch:
            raise ValueError("queued delivery must use the workflow old epoch")
        steps = {step.step_id: step for step in self.steps(workflow_id)}
        step = steps.get(request.step_id)
        if step is None:
            raise ValueError("delivery step is not in workflow")
        if step.provider_id != provider_id or step.operation_digest != request.operation_digest:
            raise ValueError("delivery does not match workflow step binding")
        expected_key = f"{workflow_id}:{request.step_id}:epoch:{request.epoch}"
        if request.idempotency_key != expected_key:
            raise ValueError("delivery does not use the canonical workflow identity")
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO deliveries(message_id, workflow_id, incident_id, step_id, "
                "provider_id, workload_id, epoch, operation_digest, idempotency_key, state, "
                "attempts, last_reason, available_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, '', ?, ?)",
                (
                    message_id,
                    workflow_id,
                    request.incident_id,
                    request.step_id,
                    provider_id,
                    request.workload_id,
                    request.epoch,
                    request.operation_digest,
                    request.idempotency_key,
                    available_at,
                    time.time_ns(),
                ),
            )
        self.set_step_state(workflow_id, request.step_id, "queued")

    def delivery(self, message_id: str) -> DeliveryRecord:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM deliveries WHERE message_id=?", (message_id,)
            ).fetchone()
        if row is None:
            raise KeyError(message_id)
        request = EffectRequest(
            incident_id=row["incident_id"],
            step_id=row["step_id"],
            workload_id=row["workload_id"],
            epoch=row["epoch"],
            operation_digest=row["operation_digest"],
            idempotency_key=row["idempotency_key"],
        )
        return DeliveryRecord(
            message_id=row["message_id"],
            workflow_id=row["workflow_id"],
            provider_id=row["provider_id"],
            request=request,
            state=row["state"],
            attempts=row["attempts"],
            last_reason=row["last_reason"],
            available_at=row["available_at"],
        )

    def _claim(self, message_id: str, now: int) -> DeliveryRecord | None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE deliveries SET state='claimed', attempts=attempts+1, updated_at=? "
                "WHERE message_id=? AND state IN ('pending', 'ambiguous') AND available_at<=?",
                (time.time_ns(), message_id, now),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                return None
            connection.commit()
        return self.delivery(message_id)

    def deliver(
        self,
        message_id: str,
        client: ProviderClient,
        *,
        now: int,
        fault: str = "none",
    ) -> DeliveryAttempt:
        delivery = self._claim(message_id, now)
        if delivery is None:
            current = self.delivery(message_id)
            return DeliveryAttempt(message_id, current.state, None)
        result = client.execute(delivery.request, fault=fault)
        if result.status == "committed":
            state = "delivered"
        elif result.status == "ambiguous":
            state = "ambiguous"
        else:
            state = "rejected"
        with self.connect() as connection:
            connection.execute(
                "UPDATE deliveries SET state=?, last_reason=?, updated_at=? "
                "WHERE message_id=? AND state='claimed'",
                (state, result.reason, time.time_ns(), message_id),
            )
        if state == "delivered":
            self.set_step_state(delivery.workflow_id, delivery.request.step_id, "committed")
        elif state == "ambiguous":
            self.set_step_state(delivery.workflow_id, delivery.request.step_id, "ambiguous")
        return DeliveryAttempt(message_id, state, result)

    def cancel_epoch(self, workflow_id: str, epoch: int) -> tuple[str, ...]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT message_id FROM deliveries WHERE workflow_id=? AND epoch=? "
                "AND state IN ('pending', 'claimed', 'ambiguous') ORDER BY message_id",
                (workflow_id, epoch),
            ).fetchall()
            connection.execute(
                "UPDATE deliveries SET state='canceled', last_reason='epoch_closed', updated_at=? "
                "WHERE workflow_id=? AND epoch=? "
                "AND state IN ('pending', 'claimed', 'ambiguous')",
                (time.time_ns(), workflow_id, epoch),
            )
            connection.commit()
        return tuple(f"queue:{row['message_id']}" for row in rows)

    def epoch_carriers(self, workflow_id: str, epoch: int) -> tuple[str, ...]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT message_id FROM deliveries WHERE workflow_id=? AND epoch=? "
                "ORDER BY message_id",
                (workflow_id, epoch),
            ).fetchall()
        return tuple(f"queue:{row['message_id']}" for row in rows)

    def open_epoch_carriers(self, workflow_id: str, epoch: int) -> tuple[str, ...]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT message_id FROM deliveries WHERE workflow_id=? AND epoch=? "
                "AND state IN ('pending', 'claimed', 'ambiguous') ORDER BY message_id",
                (workflow_id, epoch),
            ).fetchall()
        return tuple(f"queue:{row['message_id']}" for row in rows)

    def deliveries(self, workflow_id: str) -> tuple[DeliveryRecord, ...]:
        with self.connect() as connection:
            message_ids = [
                row[0]
                for row in connection.execute(
                    "SELECT message_id FROM deliveries WHERE workflow_id=? ORDER BY message_id",
                    (workflow_id,),
                ).fetchall()
            ]
        return tuple(self.delivery(message_id) for message_id in message_ids)
