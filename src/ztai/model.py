from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable


def _primitive(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {field.name: _primitive(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _primitive(item) for key, item in sorted(value.items())}
    if isinstance(value, (set, frozenset)):
        return sorted(_primitive(item) for item in value)
    if isinstance(value, (list, tuple)):
        return [_primitive(item) for item in value]
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(_primitive(value), sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class Scope:
    actions: frozenset[str]
    resources: frozenset[str]
    max_amount: int | None = None

    @classmethod
    def of(
        cls,
        actions: Iterable[str],
        resources: Iterable[str],
        max_amount: int | None = None,
    ) -> Scope:
        if max_amount is not None and max_amount < 0:
            raise ValueError("max_amount must be non-negative")
        return cls(frozenset(actions), frozenset(resources), max_amount)

    def intersect(self, other: Scope) -> Scope:
        if self.max_amount is None:
            amount = other.max_amount
        elif other.max_amount is None:
            amount = self.max_amount
        else:
            amount = min(self.max_amount, other.max_amount)
        return Scope(self.actions & other.actions, self.resources & other.resources, amount)

    def is_subset_of(self, other: Scope) -> bool:
        amount_ok = (
            other.max_amount is None
            or (self.max_amount is not None and self.max_amount <= other.max_amount)
        )
        return self.actions <= other.actions and self.resources <= other.resources and amount_ok


class ClosureVerdict(str, Enum):
    QUIESCENT = "quiescent"
    INDETERMINATE = "indeterminate"


class EffectState(str, Enum):
    NOT_STARTED = "not_started"
    NO_EFFECT = "no_effect"
    COMMITTED = "committed"
    COMPENSATED = "compensated"
    IRREVERSIBLE = "irreversible"
    AMBIGUOUS = "ambiguous"


class RecoveryStatus(str, Enum):
    AUTHORIZED = "authorized"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class Incident:
    incident_id: str
    workload_id: str
    retired_epoch: int
    declared_at: int
    reason_code: str


@dataclass(frozen=True)
class ClosureCertificate:
    incident_id: str
    workload_id: str
    retired_epoch: int
    verdict: ClosureVerdict
    inventoried_carriers: tuple[str, ...]
    closed_carriers: tuple[str, ...]
    unresolved_carriers: tuple[str, ...] = ()

    def is_positive(self) -> bool:
        return (
            self.verdict is ClosureVerdict.QUIESCENT
            and not self.unresolved_carriers
            and set(self.inventoried_carriers) == set(self.closed_carriers)
            and len(self.inventoried_carriers) == len(set(self.inventoried_carriers))
        )


@dataclass(frozen=True)
class Attestation:
    workload_id: str
    instance_id: str
    new_epoch: int
    public_key_fingerprint: str
    manifest_hash: str
    configuration_hash: str
    nonce: str
    issued_at: int
    expires_at: int

    def is_fresh(self, now: int, expected_nonce: str) -> bool:
        return self.nonce == expected_nonce and self.issued_at <= now < self.expires_at


@dataclass(frozen=True)
class Step:
    step_id: str
    provider_id: str
    operation_digest: str
    idempotent: bool


@dataclass(frozen=True)
class ReconciliationRecord:
    incident_id: str
    step_id: str
    provider_id: str
    operation_digest: str
    state: EffectState
    evidence_ref: str


@dataclass(frozen=True)
class Grant:
    grant_id: str
    workload_id: str
    epoch: int
    scope: Scope
    incident_digest: str
    closure_digest: str
    attestation_digest: str
    policy_digest: str
    authority_barrier_digest: str = ""


@dataclass(frozen=True)
class ResumeInstruction:
    step_id: str
    action: str
    reason: str


@dataclass(frozen=True)
class RecoveryCertificate:
    workload_id: str
    retired_epoch: int
    active_epoch: int
    grant: Grant
    reconciliation_digest: str
    instructions: tuple[ResumeInstruction, ...]
    lineage_digest: str
