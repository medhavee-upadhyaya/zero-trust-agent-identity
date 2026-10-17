from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .cloud_identity import CloudAuthorityBinding, CloudEffectTarget
from .crypto import SignedEnvelope, TrustStore
from .distributed import AuthorityBarrierCertificate
from .federation import (
    DelegationChainVerifier,
    FederatedIdentityBinding,
    FederatedIdentityVerifier,
    OrganizationDelegation,
    WorkloadIdentityEvidence,
)
from .model import Scope, digest


@dataclass(frozen=True)
class InfrastructureCommand:
    command_id: str
    case_id: str
    principal_id: str
    workload_id: str
    organization_id: str
    agent_id: str
    instance_id: str
    authority_epoch: int
    operation: str
    asset_id: str
    target: CloudEffectTarget
    idempotency_key: str
    safety_case_digest: str
    issued_at: int
    expires_at: int

    def is_fresh(self, now: int) -> bool:
        return self.issued_at <= now < self.expires_at


@dataclass(frozen=True)
class OperatorApproval:
    approval_id: str
    operator_id: str
    role: str
    command_digest: str
    issued_at: int
    expires_at: int

    def is_fresh(self, now: int) -> bool:
        return self.issued_at <= now < self.expires_at


@dataclass(frozen=True)
class InfrastructureAuthorizationBundle:
    command_envelope: SignedEnvelope
    workload_evidence_envelope: SignedEnvelope
    identity_binding_envelope: SignedEnvelope
    delegation_chain: tuple[SignedEnvelope, ...]
    authority_barrier_envelope: SignedEnvelope
    cloud_binding_envelope: SignedEnvelope
    approval_envelopes: tuple[SignedEnvelope, ...]


@dataclass(frozen=True)
class InfrastructureDecision:
    authorized: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CriticalInfrastructurePolicy:
    audience: str
    required_provider_ids: tuple[str, ...]
    allowed_actions: frozenset[str]
    allowed_assets: frozenset[str]
    high_risk_actions: frozenset[str]
    required_approval_roles: tuple[str, ...]


class CriticalInfrastructureAuthorizer:
    """Fail-closed authorization for a deployment-oriented digital twin."""

    def __init__(
        self,
        *,
        trust_store: TrustStore,
        identity_verifier: FederatedIdentityVerifier,
        delegation_verifier: DelegationChainVerifier,
        policy: CriticalInfrastructurePolicy,
    ) -> None:
        self._trust = trust_store
        self._identity = identity_verifier
        self._delegation = delegation_verifier
        self._policy = policy

    def authorize(
        self,
        bundle: InfrastructureAuthorizationBundle,
        *,
        now: int,
    ) -> InfrastructureDecision:
        reasons: list[str] = []
        if not self._trust.verify(
            "agent_instance", bundle.command_envelope, "infrastructure_command"
        ):
            reasons.append("invalid_agent_command_signature")
        if not self._trust.verify(
            "authority_barrier_authority",
            bundle.authority_barrier_envelope,
            "authority_barrier",
        ):
            reasons.append("invalid_authority_barrier")
        if not self._trust.verify(
            "cloud_binding_authority",
            bundle.cloud_binding_envelope,
            "cloud_authority_binding",
        ):
            reasons.append("invalid_cloud_authority_binding")
        if reasons:
            return InfrastructureDecision(False, tuple(sorted(set(reasons))))

        command = bundle.command_envelope.payload
        evidence = bundle.workload_evidence_envelope.payload
        identity_binding = bundle.identity_binding_envelope.payload
        barrier = bundle.authority_barrier_envelope.payload
        cloud_binding = bundle.cloud_binding_envelope.payload
        if not isinstance(command, InfrastructureCommand):
            reasons.append("malformed_infrastructure_command")
        if not isinstance(evidence, WorkloadIdentityEvidence):
            reasons.append("malformed_workload_identity_evidence")
        if not isinstance(identity_binding, FederatedIdentityBinding):
            reasons.append("malformed_federated_identity_binding")
        if not isinstance(barrier, AuthorityBarrierCertificate):
            reasons.append("malformed_authority_barrier")
        if not isinstance(cloud_binding, CloudAuthorityBinding):
            reasons.append("malformed_cloud_authority_binding")
        if reasons:
            return InfrastructureDecision(False, tuple(sorted(set(reasons))))
        assert isinstance(command, InfrastructureCommand)
        assert isinstance(evidence, WorkloadIdentityEvidence)
        assert isinstance(identity_binding, FederatedIdentityBinding)
        assert isinstance(barrier, AuthorityBarrierCertificate)
        assert isinstance(cloud_binding, CloudAuthorityBinding)

        if bundle.command_envelope.signer_id != command.instance_id:
            reasons.append("agent_command_signer_mismatch")
        if not command.is_fresh(now):
            reasons.append("stale_infrastructure_command")
        if command.operation not in self._policy.allowed_actions:
            reasons.append("infrastructure_action_not_allowed")
        if command.asset_id not in self._policy.allowed_assets:
            reasons.append("infrastructure_asset_not_allowed")
        if not command.command_id or not command.idempotency_key or not command.safety_case_digest:
            reasons.append("incomplete_infrastructure_command")

        identity_decision = self._identity.verify(
            bundle.workload_evidence_envelope,
            bundle.identity_binding_envelope,
            expected_audience=self._policy.audience,
            expected_principal_id=command.principal_id,
            expected_workload_id=command.workload_id,
            expected_organization_id=command.organization_id,
            expected_agent_id=command.agent_id,
            expected_instance_id=command.instance_id,
            expected_epoch=command.authority_epoch,
            required_provider_ids=self._policy.required_provider_ids,
            now=now,
        )
        reasons.extend(identity_decision.reasons)

        chain_decision = self._delegation.verify(
            bundle.delegation_chain,
            expected_audience=self._policy.audience,
            expected_final_delegatee=command.agent_id,
            now=now,
        )
        reasons.extend(chain_decision.reasons)
        if chain_decision.effective_scope is not None:
            requested_scope = Scope.of({command.operation}, {command.asset_id})
            if not requested_scope.is_subset_of(chain_decision.effective_scope):
                reasons.append("command_exceeds_delegated_scope")

        if barrier.workload_id != command.workload_id:
            reasons.append("barrier_workload_mismatch")
        if barrier.active_epoch != command.authority_epoch:
            reasons.append("barrier_epoch_mismatch")
        if barrier.formed_at > command.issued_at:
            reasons.append("command_precedes_authority_barrier")
        if tuple(sorted(set(barrier.provider_ids))) != barrier.provider_ids:
            reasons.append("noncanonical_critical_provider_barrier")
        if not set(self._policy.required_provider_ids).issubset(barrier.provider_ids):
            reasons.append("incomplete_critical_provider_barrier")
        if len(barrier.acknowledgement_digests) != len(barrier.provider_ids):
            reasons.append("incomplete_barrier_acknowledgements")
        if len(set(barrier.acknowledgement_digests)) != len(
            barrier.acknowledgement_digests
        ):
            reasons.append("duplicate_barrier_acknowledgement")

        cloud_reasons = cloud_binding.validation_errors(
            expected=command.target,
            expected_epoch=command.authority_epoch,
            now=now,
        )
        reasons.extend(cloud_reasons)
        if cloud_binding.principal_id != command.principal_id:
            reasons.append("cloud_principal_mismatch")
        if cloud_binding.agent_id != command.agent_id:
            reasons.append("cloud_agent_mismatch")
        if cloud_binding.instance_id != command.instance_id:
            reasons.append("cloud_instance_mismatch")
        if cloud_binding.workload_id != command.workload_id:
            reasons.append("cloud_workload_mismatch")
        if cloud_binding.organization_id != command.organization_id:
            reasons.append("cloud_organization_mismatch")
        if cloud_binding.identity_evidence_digest != digest(evidence):
            reasons.append("cloud_identity_evidence_mismatch")
        if cloud_binding.barrier_digest != digest(barrier):
            reasons.append("cloud_barrier_mismatch")
        if not bundle.delegation_chain:
            reasons.append("missing_delegation_chain")
        else:
            final_delegation = bundle.delegation_chain[-1].payload
            if not isinstance(final_delegation, OrganizationDelegation):
                reasons.append("malformed_final_delegation")
            elif cloud_binding.delegation_digest != digest(final_delegation):
                reasons.append("cloud_delegation_mismatch")

        approvals: dict[str, OperatorApproval] = {}
        operator_ids: set[str] = set()
        approval_ids: set[str] = set()
        for envelope in bundle.approval_envelopes:
            if not self._trust.verify("operator", envelope, "operator_approval"):
                reasons.append("invalid_operator_approval")
                continue
            approval = envelope.payload
            if not isinstance(approval, OperatorApproval):
                reasons.append("malformed_operator_approval")
                continue
            if envelope.signer_id != approval.operator_id:
                reasons.append("operator_approval_signer_mismatch")
            if approval.command_digest != digest(command):
                reasons.append("operator_approval_command_mismatch")
            if not approval.is_fresh(now):
                reasons.append("stale_operator_approval")
            if approval.operator_id in operator_ids:
                reasons.append("duplicate_operator_approval")
            operator_ids.add(approval.operator_id)
            if not approval.approval_id or approval.approval_id in approval_ids:
                reasons.append("duplicate_or_missing_approval_id")
            approval_ids.add(approval.approval_id)
            approvals[approval.role] = approval

        required_roles = (
            self._policy.required_approval_roles
            if command.operation in self._policy.high_risk_actions
            else self._policy.required_approval_roles[:1]
        )
        for role in required_roles:
            if role not in approvals:
                reasons.append(f"missing_operator_approval:{role}")
        return InfrastructureDecision(not reasons, tuple(sorted(set(reasons))))


@dataclass(frozen=True)
class DigitalTwinExecution:
    status: str
    state: str
    replayed: bool
    reason: str


class GridMaintenanceDigitalTwin:
    """Durable, exactly-once state machine for a simulated feeder workflow."""

    TRANSITIONS = {
        ("ready", "create_work_order"): "work_order_open",
        ("work_order_open", "grant_crew_access"): "crew_access_granted",
        ("crew_access_granted", "isolate"): "isolated",
        ("isolated", "notify"): "notified",
        ("notified", "restore"): "restored",
    }

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        with sqlite3.connect(self.path) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS cases ("
                "case_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, state TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS executions ("
                "idempotency_key TEXT PRIMARY KEY, command_digest TEXT NOT NULL, "
                "case_id TEXT NOT NULL, resulting_state TEXT NOT NULL)"
            )

    def execute(
        self,
        command: InfrastructureCommand,
        decision: InfrastructureDecision,
    ) -> DigitalTwinExecution:
        if not decision.authorized:
            return DigitalTwinExecution(
                "rejected", "unknown", False, ",".join(decision.reasons)
            )
        command_digest = digest(command)
        with sqlite3.connect(self.path, isolation_level=None) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT command_digest, resulting_state FROM executions "
                "WHERE idempotency_key = ?",
                (command.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing[0] != command_digest:
                    connection.rollback()
                    return DigitalTwinExecution(
                        "rejected", str(existing[1]), False, "idempotency_conflict"
                    )
                connection.commit()
                return DigitalTwinExecution("committed", str(existing[1]), True, "")
            row = connection.execute(
                "SELECT asset_id, state FROM cases WHERE case_id = ?",
                (command.case_id,),
            ).fetchone()
            if row is None:
                current_state = "ready"
                connection.execute(
                    "INSERT INTO cases(case_id, asset_id, state) VALUES (?, ?, ?)",
                    (command.case_id, command.asset_id, current_state),
                )
            else:
                if row[0] != command.asset_id:
                    connection.rollback()
                    return DigitalTwinExecution(
                        "rejected", str(row[1]), False, "case_asset_mismatch"
                    )
                current_state = str(row[1])
            next_state = self.TRANSITIONS.get((current_state, command.operation))
            if next_state is None:
                connection.rollback()
                return DigitalTwinExecution(
                    "rejected", current_state, False, "unsafe_workflow_order"
                )
            connection.execute(
                "UPDATE cases SET state = ? WHERE case_id = ?",
                (next_state, command.case_id),
            )
            connection.execute(
                "INSERT INTO executions(idempotency_key, command_digest, case_id, resulting_state) "
                "VALUES (?, ?, ?, ?)",
                (command.idempotency_key, command_digest, command.case_id, next_state),
            )
            connection.commit()
            return DigitalTwinExecution("committed", next_state, False, "")

    def state(self, case_id: str) -> str | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT state FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
        return None if row is None else str(row[0])

    def effect_count(self, case_id: str) -> int:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM executions WHERE case_id = ?", (case_id,)
            ).fetchone()
        return int(row[0]) if row is not None else 0
