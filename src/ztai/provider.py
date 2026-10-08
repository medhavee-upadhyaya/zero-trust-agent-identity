from __future__ import annotations

import dataclasses
import hashlib
import http.client
import json
import multiprocessing
import os
import socket
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .crypto import Ed25519Signer, SignedEnvelope
from .model import EffectState, ReconciliationRecord, canonical_bytes


SCHEMA = """
CREATE TABLE IF NOT EXISTS authority_epochs (
    workload_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    changed_at INTEGER NOT NULL,
    PRIMARY KEY (workload_id, epoch)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_epoch_per_workload
ON authority_epochs(workload_id) WHERE state = 'active';

CREATE TABLE IF NOT EXISTS effects (
    idempotency_key TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    workload_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    operation_digest TEXT NOT NULL,
    committed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_fences (
    idempotency_key TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    operation_digest TEXT NOT NULL,
    fenced_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS permit_uses (
    permit_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL
);
"""


@dataclass(frozen=True)
class EffectRequest:
    incident_id: str
    step_id: str
    workload_id: str
    epoch: int
    operation_digest: str
    idempotency_key: str


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    http_status: int | None
    replayed: bool = False
    reason: str = ""


@dataclass(frozen=True)
class OutcomeResult:
    status: str
    envelope: SignedEnvelope | None
    reason: str = ""


class ProviderDatabase:
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
            connection.executescript(SCHEMA)

    def establish_epoch(self, workload_id: str, epoch: int, changed_at: int) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO authority_epochs(workload_id, epoch, state, changed_at) "
                "VALUES (?, ?, 'active', ?)",
                (workload_id, epoch, changed_at),
            )
            connection.commit()

    def retire_epoch(self, workload_id: str, epoch: int, changed_at: int) -> bool:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE authority_epochs SET state='retired', changed_at=? "
                "WHERE workload_id=? AND epoch=? AND state='active'",
                (changed_at, workload_id, epoch),
            )
            connection.commit()
            return cursor.rowcount == 1

    def activate_epoch(self, workload_id: str, epoch: int, changed_at: int) -> bool:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                "SELECT 1 FROM authority_epochs WHERE workload_id=? AND state='active'",
                (workload_id,),
            ).fetchone()
            retired = connection.execute(
                "SELECT 1 FROM authority_epochs "
                "WHERE workload_id=? AND epoch=? AND state='retired'",
                (workload_id, epoch),
            ).fetchone()
            if active or retired:
                connection.rollback()
                return False
            connection.execute(
                "INSERT INTO authority_epochs(workload_id, epoch, state, changed_at) "
                "VALUES (?, ?, 'active', ?)",
                (workload_id, epoch, changed_at),
            )
            connection.commit()
            return True

    def epoch_state(self, workload_id: str, epoch: int) -> str | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT state FROM authority_epochs WHERE workload_id=? AND epoch=?",
                (workload_id, epoch),
            ).fetchone()
        return None if row is None else str(row["state"])

    def active_epoch(self, workload_id: str) -> int | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT epoch FROM authority_epochs WHERE workload_id=? AND state='active'",
                (workload_id,),
            ).fetchone()
        return None if row is None else int(row["epoch"])

    def apply_effect(self, request: EffectRequest) -> tuple[int, dict[str, Any]]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                "SELECT 1 FROM authority_epochs WHERE workload_id=? AND epoch=? AND state='active'",
                (request.workload_id, request.epoch),
            ).fetchone()
            if not active:
                connection.rollback()
                return 403, {"status": "rejected", "reason": "inactive_epoch"}

            fenced = connection.execute(
                "SELECT incident_id, step_id, operation_digest FROM delivery_fences "
                "WHERE idempotency_key=?",
                (request.idempotency_key,),
            ).fetchone()
            if fenced:
                connection.rollback()
                return 409, {"status": "rejected", "reason": "delivery_fenced"}

            existing = connection.execute(
                "SELECT * FROM effects WHERE idempotency_key=?", (request.idempotency_key,)
            ).fetchone()
            if existing:
                same = (
                    existing["incident_id"] == request.incident_id
                    and existing["step_id"] == request.step_id
                    and existing["workload_id"] == request.workload_id
                    and existing["epoch"] == request.epoch
                    and existing["operation_digest"] == request.operation_digest
                )
                connection.rollback()
                if same:
                    return 200, {"status": "committed", "replayed": True}
                return 409, {"status": "rejected", "reason": "idempotency_collision"}

            connection.execute(
                "INSERT INTO effects(idempotency_key, incident_id, step_id, workload_id, epoch, "
                "operation_digest, committed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    request.idempotency_key,
                    request.incident_id,
                    request.step_id,
                    request.workload_id,
                    request.epoch,
                    request.operation_digest,
                    time.time_ns(),
                ),
            )
            connection.commit()
            return 200, {"status": "committed", "replayed": False}

    def reconcile(
        self,
        *,
        incident_id: str,
        step_id: str,
        operation_digest: str,
        idempotency_key: str,
        create_fence: bool,
    ) -> ReconciliationRecord | None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            effect = connection.execute(
                "SELECT * FROM effects WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if effect:
                if (
                    effect["incident_id"] != incident_id
                    or effect["step_id"] != step_id
                    or effect["operation_digest"] != operation_digest
                ):
                    connection.rollback()
                    return None
                connection.rollback()
                evidence = hashlib.sha256(
                    canonical_bytes({key: effect[key] for key in effect.keys()})
                ).hexdigest()
                return ReconciliationRecord(
                    incident_id,
                    step_id,
                    "",
                    operation_digest,
                    EffectState.COMMITTED,
                    f"sqlite-effect:{evidence}",
                )

            if not create_fence:
                connection.rollback()
                return None
            fence = connection.execute(
                "SELECT * FROM delivery_fences WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if fence and (
                fence["incident_id"] != incident_id
                or fence["step_id"] != step_id
                or fence["operation_digest"] != operation_digest
            ):
                connection.rollback()
                return None
            if not fence:
                connection.execute(
                    "INSERT INTO delivery_fences(idempotency_key, incident_id, step_id, "
                    "operation_digest, fenced_at) VALUES (?, ?, ?, ?, ?)",
                    (idempotency_key, incident_id, step_id, operation_digest, time.time_ns()),
                )
            connection.commit()
            evidence = hashlib.sha256(
                canonical_bytes(
                    {
                        "idempotency_key": idempotency_key,
                        "incident_id": incident_id,
                        "step_id": step_id,
                        "operation_digest": operation_digest,
                    }
                )
            ).hexdigest()
            return ReconciliationRecord(
                incident_id,
                step_id,
                "",
                operation_digest,
                EffectState.NO_EFFECT,
                f"sqlite-fence:{evidence}",
            )

    def effect_count(self, incident_id: str | None = None, step_id: str | None = None) -> int:
        clauses: list[str] = []
        parameters: list[str] = []
        if incident_id is not None:
            clauses.append("incident_id=?")
            parameters.append(incident_id)
        if step_id is not None:
            clauses.append("step_id=?")
            parameters.append(step_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as connection:
            return int(
                connection.execute(
                    f"SELECT COUNT(*) FROM effects{where}", parameters  # noqa: S608
                ).fetchone()[0]
            )

    def record_permit_use(self, permit_id: str, request_digest: str) -> str:
        """Atomically records first use and distinguishes exact replay from collision."""
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT request_digest FROM permit_uses WHERE permit_id=?", (permit_id,)
            ).fetchone()
            if existing is not None:
                connection.rollback()
                return "replay" if existing["request_digest"] == request_digest else "collision"
            connection.execute(
                "INSERT INTO permit_uses(permit_id, request_digest, first_seen_at) "
                "VALUES (?, ?, ?)",
                (permit_id, request_digest, time.time_ns()),
            )
            connection.commit()
            return "new"


def _payload_dict(record: ReconciliationRecord) -> dict[str, Any]:
    payload = dataclasses.asdict(record)
    payload["state"] = record.state.value
    return payload


def _make_handler(
    database_path: str,
    provider_id: str,
    signer: Ed25519Signer,
    enable_faults: bool,
):
    database = ProviderDatabase(database_path)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ZTProvider/0.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            if self.path != "/effect":
                self._send(404, {"status": "not_found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            request = EffectRequest(**data)
            fault = self.headers.get("X-Fault-Mode", "none")
            if fault != "none" and not enable_faults:
                self._send(403, {"status": "rejected", "reason": "fault_injection_disabled"})
                return
            if fault == "crash_before_commit":
                os._exit(86)
            if fault == "drop_before_commit":
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            status, payload = database.apply_effect(request)
            if fault == "crash_after_commit" and status == 200:
                os._exit(87)
            if fault == "drop_after_commit" and status == 200:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            self._send(status, payload)

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/health":
                self._send(200, {"status": "ok", "provider_id": provider_id})
                return
            if parsed.path != "/outcome":
                self._send(404, {"status": "not_found"})
                return
            query = urllib.parse.parse_qs(parsed.query)
            required = ("incident_id", "step_id", "operation_digest", "idempotency_key")
            if any(key not in query for key in required):
                self._send(400, {"status": "invalid_request"})
                return
            record = database.reconcile(
                incident_id=query["incident_id"][0],
                step_id=query["step_id"][0],
                operation_digest=query["operation_digest"][0],
                idempotency_key=query["idempotency_key"][0],
                create_fence=query.get("fence", ["false"])[0].lower() == "true",
            )
            if record is None:
                self._send(404, {"status": "unknown"})
                return
            record = dataclasses.replace(record, provider_id=provider_id)
            envelope = signer.sign("reconciliation", record)
            self._send(
                200,
                {
                    "status": record.state.value,
                    "envelope": {
                        "kind": envelope.kind,
                        "signer_id": envelope.signer_id,
                        "payload": _payload_dict(record),
                        "signature": envelope.signature,
                    },
                },
            )

    return Handler


def _serve(
    database_path: str,
    provider_id: str,
    private_key: bytes,
    enable_faults: bool,
    ready: multiprocessing.connection.Connection,
) -> None:
    signer = Ed25519Signer.from_private_bytes(provider_id, private_key)
    handler = _make_handler(database_path, provider_id, signer, enable_faults)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    ready.send(server.server_address[1])
    ready.close()
    server.serve_forever(poll_interval=0.05)


class ProviderProcess:
    def __init__(
        self,
        database_path: str | Path,
        signer: Ed25519Signer,
        *,
        enable_faults: bool = False,
    ) -> None:
        self.database_path = str(database_path)
        self.signer = signer
        self.enable_faults = enable_faults
        self.process: multiprocessing.Process | None = None
        self.port: int | None = None

    def start(self) -> "ProviderProcess":
        if self.process is not None:
            raise RuntimeError("provider already started")
        parent, child = multiprocessing.Pipe(duplex=False)
        process = multiprocessing.Process(
            target=_serve,
            args=(
                self.database_path,
                self.signer.signer_id,
                self.signer.private_key_bytes,
                self.enable_faults,
                child,
            ),
            daemon=True,
        )
        process.start()
        child.close()
        if not parent.poll(10):
            process.terminate()
            process.join(5)
            raise TimeoutError("provider did not start")
        try:
            self.port = int(parent.recv())
        except EOFError as error:
            process.join(5)
            message = f"provider exited during startup with code {process.exitcode}"
            raise RuntimeError(message) from error
        parent.close()
        self.process = process
        return self

    @property
    def base_url(self) -> str:
        if self.port is None:
            raise RuntimeError("provider is not running")
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        if self.process is None:
            return
        self.process.terminate()
        self.process.join(5)
        if self.process.is_alive():
            self.process.kill()
            self.process.join(5)
        self.process = None
        self.port = None

    def restart(self) -> "ProviderProcess":
        self.stop()
        return self.start()

    def __enter__(self) -> "ProviderProcess":
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.stop()


class ProviderClient:
    def __init__(self, base_url: str, timeout: float = 2.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def execute(self, request: EffectRequest, fault: str = "none") -> ExecutionResult:
        body = json.dumps(dataclasses.asdict(request), sort_keys=True).encode()
        message = urllib.request.Request(
            f"{self.base_url}/effect",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "X-Fault-Mode": fault},
        )
        try:
            with urllib.request.urlopen(message, timeout=self.timeout) as response:
                payload = json.loads(response.read())
                return ExecutionResult(
                    payload["status"],
                    response.status,
                    bool(payload.get("replayed")),
                    payload.get("reason", ""),
                )
        except urllib.error.HTTPError as error:
            payload = json.loads(error.read())
            return ExecutionResult(payload["status"], error.code, False, payload.get("reason", ""))
        except (
            urllib.error.URLError,
            http.client.RemoteDisconnected,
            ConnectionError,
            TimeoutError,
        ):
            return ExecutionResult("ambiguous", None, False, "transport_failure")

    def reconcile(self, request: EffectRequest, create_fence: bool = True) -> OutcomeResult:
        query = urllib.parse.urlencode(
            {
                "incident_id": request.incident_id,
                "step_id": request.step_id,
                "operation_digest": request.operation_digest,
                "idempotency_key": request.idempotency_key,
                "fence": str(create_fence).lower(),
            }
        )
        try:
            url = f"{self.base_url}/outcome?{query}"
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as error:
            return OutcomeResult("unknown", None, f"http_{error.code}")
        except (
            urllib.error.URLError,
            http.client.RemoteDisconnected,
            ConnectionError,
            TimeoutError,
        ):
            return OutcomeResult("unknown", None, "transport_failure")
        wire = payload["envelope"]
        raw = wire["payload"]
        record = ReconciliationRecord(
            incident_id=raw["incident_id"],
            step_id=raw["step_id"],
            provider_id=raw["provider_id"],
            operation_digest=raw["operation_digest"],
            state=EffectState(raw["state"]),
            evidence_ref=raw["evidence_ref"],
        )
        envelope = SignedEnvelope(wire["kind"], wire["signer_id"], record, wire["signature"])
        return OutcomeResult(payload["status"], envelope)
