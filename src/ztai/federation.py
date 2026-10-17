from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .crypto import SignedEnvelope, TrustStore
from .model import Scope, digest


_SPIFFE_TRUST_DOMAIN = re.compile(r"[a-z0-9._-]+", re.ASCII)
_SPIFFE_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._-]+", re.ASCII)


@dataclass(frozen=True)
class SpiffeIdentity:
    """Strict representation of the SPIFFE ID shape used by the prototype.

    This is not a substitute for the SPIFFE conformance suite or a production
    SPIFFE library.
    """

    uri: str
    trust_domain: str
    path: str

    @classmethod
    def parse(cls, value: str) -> "SpiffeIdentity":
        if len(value.encode("ascii", errors="strict")) > 2048:
            raise ValueError("SPIFFE ID exceeds the supported maximum length")
        parsed = urlsplit(value)
        if parsed.scheme != "spiffe":
            raise ValueError("SPIFFE ID must use the spiffe scheme")
        if not parsed.netloc or parsed.hostname is None:
            raise ValueError("SPIFFE ID must contain a trust domain")
        if parsed.username is not None or parsed.password is not None or parsed.port is not None:
            raise ValueError("SPIFFE ID cannot contain user information or a port")
        if parsed.query or parsed.fragment:
            raise ValueError("SPIFFE ID cannot contain a query or fragment")
        if "%" in parsed.netloc or parsed.netloc != parsed.netloc.lower():
            raise ValueError("SPIFFE trust domain must be lowercase")
        trust_domain = parsed.hostname
        if (
            len(trust_domain.encode("ascii")) > 255
            or _SPIFFE_TRUST_DOMAIN.fullmatch(trust_domain) is None
        ):
            raise ValueError("SPIFFE trust domain contains invalid characters")
        path = parsed.path or ""
        if path:
            if not path.startswith("/") or path.endswith("/") or "%" in path:
                raise ValueError("SPIFFE path has an invalid shape")
            segments = path[1:].split("/")
            if any(
                segment in {"", ".", ".."}
                or _SPIFFE_PATH_SEGMENT.fullmatch(segment) is None
                for segment in segments
            ):
                raise ValueError("SPIFFE path contains an invalid segment")
        return cls(value, trust_domain, path)


@dataclass(frozen=True)
class WorkloadIdentityEvidence:
    spiffe_id: str
    issuer: str
    subject: str
    audience: str
    organization_id: str
    agent_id: str
    instance_id: str
    public_key_fingerprint: str
    issued_at: int
    expires_at: int
    nonce: str

    def is_fresh(self, now: int) -> bool:
        return self.issued_at <= now < self.expires_at


@dataclass(frozen=True)
class FederatedIdentityBinding:
    binding_id: str
    principal_id: str
    workload_id: str
    agent_id: str
    instance_id: str
    organization_id: str
    delegation_id: str
    authority_epoch: int
    audience: str
    provider_ids: tuple[str, ...]
    evidence_digest: str
    issued_at: int
    expires_at: int

    def is_fresh(self, now: int) -> bool:
        return self.issued_at <= now < self.expires_at


@dataclass(frozen=True)
class FederatedIdentityDecision:
    accepted: bool
    reasons: tuple[str, ...]
    identity: SpiffeIdentity | None = None


class FederatedIdentityVerifier:
    """Verifies signed workload evidence and its agent/authority binding."""

    def __init__(
        self,
        trust_store: TrustStore,
        *,
        issuer_trust_domains: dict[str, str],
        issuer_urls: dict[str, str] | None = None,
    ) -> None:
        self._trust = trust_store
        self._issuer_trust_domains = dict(issuer_trust_domains)
        self._issuer_urls = dict(issuer_urls or {})

    def verify(
        self,
        evidence_envelope: SignedEnvelope,
        binding_envelope: SignedEnvelope,
        *,
        expected_audience: str,
        expected_principal_id: str,
        expected_workload_id: str,
        expected_organization_id: str,
        expected_agent_id: str,
        expected_instance_id: str,
        expected_epoch: int,
        required_provider_ids: tuple[str, ...],
        now: int,
    ) -> FederatedIdentityDecision:
        reasons: list[str] = []
        if not self._trust.verify(
            "workload_identity_issuer", evidence_envelope, "workload_identity_evidence"
        ):
            reasons.append("invalid_workload_identity_signature")
        if not self._trust.verify(
            "federation_authority", binding_envelope, "federated_identity_binding"
        ):
            reasons.append("invalid_federation_binding_signature")
        if reasons:
            return FederatedIdentityDecision(False, tuple(reasons))

        evidence = evidence_envelope.payload
        binding = binding_envelope.payload
        if not isinstance(evidence, WorkloadIdentityEvidence):
            reasons.append("malformed_workload_identity_evidence")
        if not isinstance(binding, FederatedIdentityBinding):
            reasons.append("malformed_federation_binding")
        if reasons:
            return FederatedIdentityDecision(False, tuple(reasons))
        assert isinstance(evidence, WorkloadIdentityEvidence)
        assert isinstance(binding, FederatedIdentityBinding)

        try:
            identity = SpiffeIdentity.parse(evidence.spiffe_id)
        except (UnicodeError, ValueError):
            return FederatedIdentityDecision(False, ("invalid_spiffe_id",))

        trusted_domain = self._issuer_trust_domains.get(evidence_envelope.signer_id)
        if trusted_domain is None:
            reasons.append("untrusted_workload_identity_issuer")
        elif identity.trust_domain != trusted_domain:
            reasons.append("spiffe_trust_domain_mismatch")
        expected_issuer_url = self._issuer_urls.get(evidence_envelope.signer_id)
        if expected_issuer_url is not None and evidence.issuer != expected_issuer_url:
            reasons.append("workload_issuer_url_mismatch")
        if evidence.subject != evidence.spiffe_id:
            reasons.append("workload_subject_mismatch")
        if evidence.audience != expected_audience or binding.audience != expected_audience:
            reasons.append("federation_audience_mismatch")
        if evidence.organization_id != expected_organization_id:
            reasons.append("workload_organization_mismatch")
        if binding.organization_id != expected_organization_id:
            reasons.append("binding_organization_mismatch")
        if evidence.agent_id != expected_agent_id or binding.agent_id != expected_agent_id:
            reasons.append("agent_identity_mismatch")
        if (
            evidence.instance_id != expected_instance_id
            or binding.instance_id != expected_instance_id
        ):
            reasons.append("agent_instance_mismatch")
        if binding.principal_id != expected_principal_id:
            reasons.append("principal_binding_mismatch")
        if binding.workload_id != expected_workload_id:
            reasons.append("workload_binding_mismatch")
        if binding.authority_epoch != expected_epoch:
            reasons.append("authority_epoch_mismatch")
        if not evidence.is_fresh(now):
            reasons.append("stale_workload_identity")
        if not binding.is_fresh(now):
            reasons.append("stale_federation_binding")
        if binding.issued_at < evidence.issued_at or binding.expires_at > evidence.expires_at:
            reasons.append("invalid_federation_time_chain")
        if not evidence.nonce:
            reasons.append("missing_workload_identity_nonce")
        if not evidence.public_key_fingerprint:
            reasons.append("missing_workload_key_fingerprint")
        if binding.evidence_digest != digest(evidence):
            reasons.append("workload_evidence_binding_mismatch")
        if tuple(sorted(set(binding.provider_ids))) != binding.provider_ids:
            reasons.append("noncanonical_federated_provider_set")
        if not set(required_provider_ids).issubset(binding.provider_ids):
            reasons.append("incomplete_federated_provider_set")
        if not binding.binding_id or not binding.delegation_id or binding.authority_epoch < 0:
            reasons.append("incomplete_federation_binding")
        return FederatedIdentityDecision(
            not reasons,
            tuple(sorted(set(reasons))),
            identity,
        )


@dataclass(frozen=True)
class OrganizationDelegation:
    delegation_id: str
    organization_id: str
    trust_domain: str
    delegator_id: str
    delegatee_id: str
    audience: str
    scope: Scope
    parent_delegation_digest: str
    depth: int
    issued_at: int
    expires_at: int
    nonce: str

    def is_fresh(self, now: int) -> bool:
        return self.issued_at <= now < self.expires_at


@dataclass(frozen=True)
class DelegationChainDecision:
    accepted: bool
    reasons: tuple[str, ...]
    effective_scope: Scope | None = None


class DelegationChainVerifier:
    """Validates scope attenuation across independently signed trust domains."""

    def __init__(
        self,
        trust_store: TrustStore,
        *,
        signer_domains: dict[str, str],
        allowed_domain_edges: frozenset[tuple[str, str]],
        signer_organizations: dict[str, str] | None = None,
    ) -> None:
        self._trust = trust_store
        self._signer_domains = dict(signer_domains)
        self._allowed_domain_edges = allowed_domain_edges
        self._signer_organizations = dict(signer_organizations or {})

    def verify(
        self,
        chain: tuple[SignedEnvelope, ...],
        *,
        expected_audience: str,
        expected_final_delegatee: str,
        now: int,
    ) -> DelegationChainDecision:
        if not chain:
            return DelegationChainDecision(False, ("empty_delegation_chain",))

        reasons: list[str] = []
        grants: list[OrganizationDelegation] = []
        seen_ids: set[str] = set()
        visited_principals: set[str] = set()
        for index, envelope in enumerate(chain):
            if not self._trust.verify(
                "organization_authority", envelope, "organization_delegation"
            ):
                reasons.append(f"invalid_organization_signature:{index}")
                continue
            grant = envelope.payload
            if not isinstance(grant, OrganizationDelegation):
                reasons.append(f"malformed_organization_delegation:{index}")
                continue
            grants.append(grant)
            signer_domain = self._signer_domains.get(envelope.signer_id)
            if signer_domain != grant.trust_domain:
                reasons.append(f"organization_signer_domain_mismatch:{index}")
            signer_organization = self._signer_organizations.get(envelope.signer_id)
            if signer_organization is None:
                reasons.append(f"untrusted_organization_signer:{index}")
            elif signer_organization != grant.organization_id:
                reasons.append(f"organization_signer_identity_mismatch:{index}")
            try:
                parsed_domain = SpiffeIdentity.parse(
                    f"spiffe://{grant.trust_domain}/authority/{grant.organization_id}"
                ).trust_domain
            except (UnicodeError, ValueError):
                parsed_domain = ""
                reasons.append(f"invalid_organization_trust_domain:{index}")
            if parsed_domain != grant.trust_domain:
                reasons.append(f"invalid_organization_trust_domain:{index}")
            if grant.audience != expected_audience:
                reasons.append(f"delegation_audience_mismatch:{index}")
            if not grant.is_fresh(now):
                reasons.append(f"stale_organization_delegation:{index}")
            if not grant.nonce:
                reasons.append(f"missing_delegation_nonce:{index}")
            if grant.depth != index:
                reasons.append(f"delegation_depth_mismatch:{index}")
            if not grant.delegation_id or grant.delegation_id in seen_ids:
                reasons.append(f"duplicate_or_missing_delegation_id:{index}")
            seen_ids.add(grant.delegation_id)
            if index == 0:
                visited_principals.add(grant.delegator_id)
            if grant.delegatee_id in visited_principals:
                reasons.append(f"delegation_cycle:{index}")
            visited_principals.add(grant.delegatee_id)

        if len(grants) != len(chain):
            return DelegationChainDecision(False, tuple(sorted(set(reasons))))

        root = grants[0]
        if root.parent_delegation_digest:
            reasons.append("root_has_parent")
        for index in range(1, len(grants)):
            parent = grants[index - 1]
            child = grants[index]
            if child.parent_delegation_digest != digest(parent):
                reasons.append(f"delegation_parent_mismatch:{index}")
            if child.delegator_id != parent.delegatee_id:
                reasons.append(f"delegator_lineage_mismatch:{index}")
            if not child.scope.is_subset_of(parent.scope):
                reasons.append(f"delegation_scope_widening:{index}")
            if child.issued_at < parent.issued_at or child.expires_at > parent.expires_at:
                reasons.append(f"delegation_time_widening:{index}")
            edge = (parent.trust_domain, child.trust_domain)
            if edge not in self._allowed_domain_edges:
                reasons.append(f"untrusted_domain_edge:{index}")
        if grants[-1].delegatee_id != expected_final_delegatee:
            reasons.append("unexpected_final_delegatee")
        effective_scope = grants[-1].scope if not reasons else None
        return DelegationChainDecision(
            not reasons,
            tuple(sorted(set(reasons))),
            effective_scope,
        )
