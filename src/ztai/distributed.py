from __future__ import annotations

import dataclasses
import http.client
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Protocol

from .crypto import Ed25519Signer, SignedEnvelope, TrustStore
from .model import RecoveryStatus, digest
from .provider import ProviderDatabase


@dataclass(frozen=True)
class AuthorityTransition:
    transition_id: str
    incident_id: str
    workload_id: str
    version: int
    retired_epoch: int
    active_epoch: int
    provider_ids: tuple[str, ...]
    issued_at: int

    def validation_errors(self) -> tuple[str, ...]:
        reasons: list[str] = []
        if not self.transition_id:
            reasons.append("missing_transition_id")
        if not self.incident_id:
            reasons.append("missing_incident_id")
        if not self.workload_id:
            reasons.append("missing_workload_id")
        if self.version < 1:
            reasons.append("invalid_authority_version")
        if self.retired_epoch < 0 or self.active_epoch < 0:
            reasons.append("invalid_epoch")
        if self.retired_epoch == self.active_epoch:
            reasons.append("unchanged_epoch")
        if not self.provider_ids:
            reasons.append("missing_effect_providers")
        if tuple(sorted(set(self.provider_ids))) != self.provider_ids:
            reasons.append("noncanonical_provider_set")
        return tuple(reasons)


@dataclass(frozen=True)
class ProviderAuthorityAcknowledgement:
    provider_id: str
    transition_id: str
    incident_id: str
    workload_id: str
    version: int
    retired_epoch: int
    active_epoch: int
    transition_digest: str
    persisted_at: int


@dataclass(frozen=True)
class AuthorityBarrierCertificate:
    transition_id: str
    incident_id: str
    workload_id: str
    version: int
    retired_epoch: int
    active_epoch: int
    transition_digest: str
    provider_ids: tuple[str, ...]
    acknowledgement_digests: tuple[str, ...]
    formed_at: int


@dataclass(frozen=True)
class ProviderTransitionResult:
    accepted: bool
    reason: str
    acknowledgement_envelope: SignedEnvelope | None
    replayed: bool = False


@dataclass(frozen=True)
class AuthorityBarrierDecision:
    status: RecoveryStatus
    reasons: tuple[str, ...]
    transition_envelope: SignedEnvelope
    acknowledgement_envelopes: tuple[SignedEnvelope, ...]
    barrier_envelope: SignedEnvelope | None


class AuthorityProvider(Protocol):
    provider_id: str

    def apply_transition(
        self, transition_envelope: SignedEnvelope, *, now: int
    ) -> ProviderTransitionResult: ...


class DurableAuthorityProvider:
    """Installs a signed transition before acknowledging it to the coordinator."""

    def __init__(
        self,
        provider_id: str,
        database: ProviderDatabase,
        trust_store: TrustStore,
        signer: Ed25519Signer,
    ) -> None:
        self.provider_id = provider_id
        self.database = database
        self.trust_store = trust_store
        self.signer = signer

    def apply_transition(
        self, transition_envelope: SignedEnvelope, *, now: int
    ) -> ProviderTransitionResult:
        if not self.trust_store.verify(
            "authority_transition_authority",
            transition_envelope,
            "authority_transition",
        ):
            return ProviderTransitionResult(False, "invalid_transition_signature", None)
        transition = transition_envelope.payload
        if not isinstance(transition, AuthorityTransition):
            return ProviderTransitionResult(False, "invalid_transition_payload", None)
        errors = transition.validation_errors()
        if errors:
            return ProviderTransitionResult(False, errors[0], None)
        if self.provider_id not in transition.provider_ids:
            return ProviderTransitionResult(False, "provider_not_in_transition", None)
        if transition.issued_at > now:
            return ProviderTransitionResult(False, "transition_from_future", None)

        transition_digest = digest(transition)
        status, record = self.database.install_authority_transition(
            workload_id=transition.workload_id,
            version=transition.version,
            retired_epoch=transition.retired_epoch,
            active_epoch=transition.active_epoch,
            transition_digest=transition_digest,
            changed_at=now,
        )
        if status not in {"installed", "replayed"} or record is None:
            return ProviderTransitionResult(False, status, None)
        acknowledgement = ProviderAuthorityAcknowledgement(
            provider_id=self.provider_id,
            transition_id=transition.transition_id,
            incident_id=transition.incident_id,
            workload_id=transition.workload_id,
            version=int(record["version"]),
            retired_epoch=int(record["retired_epoch"]),
            active_epoch=int(record["active_epoch"]),
            transition_digest=str(record["transition_digest"]),
            persisted_at=int(record["changed_at"]),
        )
        return ProviderTransitionResult(
            True,
            status,
            self.signer.sign("authority_transition_ack", acknowledgement),
            replayed=status == "replayed",
        )


class NetworkAuthorityProvider:
    """Carries signed transitions and acknowledgements over HTTP."""

    def __init__(
        self,
        provider_id: str,
        base_url: str,
        *,
        timeout: float = 2.0,
        fault: str = "none",
    ) -> None:
        self.provider_id = provider_id
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.fault = fault

    def apply_transition(
        self, transition_envelope: SignedEnvelope, *, now: int
    ) -> ProviderTransitionResult:
        body = json.dumps(
            {
                "now": now,
                "envelope": {
                    "kind": transition_envelope.kind,
                    "signer_id": transition_envelope.signer_id,
                    "payload": dataclasses.asdict(transition_envelope.payload),
                    "signature": transition_envelope.signature,
                },
            },
            sort_keys=True,
        ).encode()
        request = urllib.request.Request(
            f"{self.base_url}/authority-transition",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Authority-Fault-Mode": self.fault,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as error:
            payload = json.loads(error.read())
        except (
            urllib.error.URLError,
            http.client.RemoteDisconnected,
            ConnectionError,
            TimeoutError,
        ) as error:
            raise TimeoutError(self.provider_id) from error

        wire = payload.get("acknowledgement")
        acknowledgement_envelope = None
        if wire is not None:
            raw = wire["payload"]
            acknowledgement = ProviderAuthorityAcknowledgement(
                provider_id=raw["provider_id"],
                transition_id=raw["transition_id"],
                incident_id=raw["incident_id"],
                workload_id=raw["workload_id"],
                version=int(raw["version"]),
                retired_epoch=int(raw["retired_epoch"]),
                active_epoch=int(raw["active_epoch"]),
                transition_digest=raw["transition_digest"],
                persisted_at=int(raw["persisted_at"]),
            )
            acknowledgement_envelope = SignedEnvelope(
                wire["kind"],
                wire["signer_id"],
                acknowledgement,
                wire["signature"],
            )
        return ProviderTransitionResult(
            bool(payload.get("accepted")),
            payload.get("reason", "transport_rejected"),
            acknowledgement_envelope,
            bool(payload.get("replayed")),
        )


class DistributedAuthorityCoordinator:
    """Forms a barrier only from a complete, consistent, signed acknowledgement set."""

    def __init__(
        self,
        *,
        trust_store: TrustStore,
        providers: Mapping[str, AuthorityProvider],
        barrier_signer: Ed25519Signer,
    ) -> None:
        self.trust_store = trust_store
        self.providers = dict(providers)
        self.barrier_signer = barrier_signer

    @staticmethod
    def _ack_matches(
        acknowledgement: ProviderAuthorityAcknowledgement,
        transition: AuthorityTransition,
        provider_id: str,
        transition_digest: str,
    ) -> bool:
        return (
            acknowledgement.provider_id == provider_id
            and acknowledgement.transition_id == transition.transition_id
            and acknowledgement.incident_id == transition.incident_id
            and acknowledgement.workload_id == transition.workload_id
            and acknowledgement.version == transition.version
            and acknowledgement.retired_epoch == transition.retired_epoch
            and acknowledgement.active_epoch == transition.active_epoch
            and acknowledgement.transition_digest == transition_digest
            and acknowledgement.persisted_at >= transition.issued_at
        )

    def establish_barrier(
        self,
        transition_envelope: SignedEnvelope,
        *,
        now: int,
    ) -> AuthorityBarrierDecision:
        if not self.trust_store.verify(
            "authority_transition_authority",
            transition_envelope,
            "authority_transition",
        ):
            return AuthorityBarrierDecision(
                RecoveryStatus.QUARANTINED,
                ("invalid_transition_signature",),
                transition_envelope,
                (),
                None,
            )
        transition = transition_envelope.payload
        if not isinstance(transition, AuthorityTransition):
            return AuthorityBarrierDecision(
                RecoveryStatus.QUARANTINED,
                ("invalid_transition_payload",),
                transition_envelope,
                (),
                None,
            )
        errors = transition.validation_errors()
        if errors:
            return AuthorityBarrierDecision(
                RecoveryStatus.QUARANTINED,
                errors,
                transition_envelope,
                (),
                None,
            )

        transition_digest = digest(transition)
        reasons: list[str] = []
        acknowledgements: list[SignedEnvelope] = []
        for provider_id in transition.provider_ids:
            provider = self.providers.get(provider_id)
            if provider is None:
                reasons.append(f"missing_provider:{provider_id}")
                continue
            try:
                result = provider.apply_transition(transition_envelope, now=now)
            except (ConnectionError, TimeoutError):
                reasons.append(f"unavailable_provider:{provider_id}")
                continue
            acknowledgement_envelope = result.acknowledgement_envelope
            if not result.accepted or acknowledgement_envelope is None:
                reasons.append(f"transition_rejected:{provider_id}:{result.reason}")
                continue
            if not self.trust_store.verify(
                "effect_provider",
                acknowledgement_envelope,
                "authority_transition_ack",
            ):
                reasons.append(f"invalid_ack_signature:{provider_id}")
                continue
            if acknowledgement_envelope.signer_id != provider_id:
                reasons.append(f"invalid_ack_signer:{provider_id}")
                continue
            acknowledgement = acknowledgement_envelope.payload
            if not isinstance(acknowledgement, ProviderAuthorityAcknowledgement):
                reasons.append(f"invalid_ack_payload:{provider_id}")
                continue
            if not self._ack_matches(
                acknowledgement,
                transition,
                provider_id,
                transition_digest,
            ):
                reasons.append(f"conflicting_ack:{provider_id}")
                continue
            acknowledgements.append(acknowledgement_envelope)

        if reasons or len(acknowledgements) != len(transition.provider_ids):
            if not reasons:
                reasons.append("incomplete_acknowledgement_set")
            return AuthorityBarrierDecision(
                RecoveryStatus.QUARANTINED,
                tuple(reasons),
                transition_envelope,
                tuple(acknowledgements),
                None,
            )

        barrier = AuthorityBarrierCertificate(
            transition_id=transition.transition_id,
            incident_id=transition.incident_id,
            workload_id=transition.workload_id,
            version=transition.version,
            retired_epoch=transition.retired_epoch,
            active_epoch=transition.active_epoch,
            transition_digest=transition_digest,
            provider_ids=transition.provider_ids,
            acknowledgement_digests=tuple(digest(item) for item in acknowledgements),
            formed_at=now,
        )
        return AuthorityBarrierDecision(
            RecoveryStatus.AUTHORIZED,
            (),
            transition_envelope,
            tuple(acknowledgements),
            self.barrier_signer.sign("authority_barrier", barrier),
        )

    def verify_barrier(self, decision: AuthorityBarrierDecision) -> bool:
        envelope = decision.barrier_envelope
        if decision.status is not RecoveryStatus.AUTHORIZED or envelope is None:
            return False
        if not self.trust_store.verify(
            "authority_barrier_authority", envelope, "authority_barrier"
        ):
            return False
        barrier = envelope.payload
        transition = decision.transition_envelope.payload
        if not isinstance(barrier, AuthorityBarrierCertificate) or not isinstance(
            transition, AuthorityTransition
        ):
            return False
        if barrier.transition_digest != digest(transition):
            return False
        if barrier.provider_ids != transition.provider_ids:
            return False
        if len(decision.acknowledgement_envelopes) != len(transition.provider_ids):
            return False
        return barrier.acknowledgement_digests == tuple(
            digest(item) for item in decision.acknowledgement_envelopes
        )
