from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlencode


TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"


def _require_nonempty(**values: str) -> None:
    missing = sorted(name for name, value in values.items() if not value)
    if missing:
        raise ValueError(f"missing required values: {','.join(missing)}")


@dataclass(frozen=True)
class TokenExchangeRequest:
    token_url: str
    audience: str
    subject_token: str
    subject_token_type: str = JWT_TOKEN_TYPE
    requested_token_type: str = ACCESS_TOKEN_TYPE
    scope: str = ""

    def form_fields(self) -> dict[str, str]:
        _require_nonempty(
            token_url=self.token_url,
            audience=self.audience,
            subject_token=self.subject_token,
            subject_token_type=self.subject_token_type,
            requested_token_type=self.requested_token_type,
        )
        fields = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "audience": self.audience,
            "requested_token_type": self.requested_token_type,
            "subject_token": self.subject_token,
            "subject_token_type": self.subject_token_type,
        }
        if self.scope:
            fields["scope"] = self.scope
        return fields

    def encoded_body(self) -> bytes:
        return urlencode(self.form_fields()).encode("ascii")


@dataclass(frozen=True)
class MicrosoftEntraFederationConfig:
    tenant_id: str
    client_id: str
    scope: str

    @property
    def token_url(self) -> str:
        _require_nonempty(tenant_id=self.tenant_id)
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

    def client_assertion_fields(self, jwt_svid: str) -> dict[str, str]:
        _require_nonempty(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            scope=self.scope,
            jwt_svid=jwt_svid,
        )
        return {
            "client_id": self.client_id,
            "client_assertion": jwt_svid,
            "client_assertion_type": (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ),
            "grant_type": "client_credentials",
            "scope": self.scope,
        }


@dataclass(frozen=True)
class GoogleWorkloadFederationConfig:
    project_number: str
    pool_id: str
    provider_id: str
    scope: str = "https://www.googleapis.com/auth/cloud-platform"

    @property
    def audience(self) -> str:
        _require_nonempty(
            project_number=self.project_number,
            pool_id=self.pool_id,
            provider_id=self.provider_id,
        )
        return (
            f"//iam.googleapis.com/projects/{self.project_number}/locations/global/"
            f"workloadIdentityPools/{self.pool_id}/providers/{self.provider_id}"
        )

    def token_exchange(self, subject_token: str) -> TokenExchangeRequest:
        return TokenExchangeRequest(
            token_url="https://sts.googleapis.com/v1/token",
            audience=self.audience,
            subject_token=subject_token,
            scope=self.scope,
        )


@dataclass(frozen=True)
class AwsWebIdentityConfig:
    role_arn: str
    role_session_name: str
    duration_seconds: int = 900
    provider_id: str = ""

    def query_fields(self, web_identity_token: str) -> dict[str, str]:
        _require_nonempty(
            role_arn=self.role_arn,
            role_session_name=self.role_session_name,
            web_identity_token=web_identity_token,
        )
        if not 900 <= self.duration_seconds <= 43_200:
            raise ValueError("duration_seconds must be between 900 and 43200")
        fields = {
            "Action": "AssumeRoleWithWebIdentity",
            "DurationSeconds": str(self.duration_seconds),
            "RoleArn": self.role_arn,
            "RoleSessionName": self.role_session_name,
            "Version": "2011-06-15",
            "WebIdentityToken": web_identity_token,
        }
        if self.provider_id:
            fields["ProviderId"] = self.provider_id
        return fields


@dataclass(frozen=True)
class CloudEffectTarget:
    cloud: str
    account_or_tenant: str
    service: str
    resource: str
    operation: str


@dataclass(frozen=True)
class CloudAuthorityBinding:
    binding_id: str
    principal_id: str
    agent_id: str
    instance_id: str
    workload_id: str
    organization_id: str
    authority_epoch: int
    delegation_digest: str
    identity_evidence_digest: str
    barrier_digest: str
    target: CloudEffectTarget
    issued_at: int
    expires_at: int

    def validation_errors(
        self,
        *,
        expected: CloudEffectTarget,
        expected_epoch: int,
        now: int,
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        if self.target != expected:
            reasons.append("cloud_effect_target_mismatch")
        if self.authority_epoch != expected_epoch:
            reasons.append("cloud_authority_epoch_mismatch")
        if not self.issued_at <= now < self.expires_at:
            reasons.append("stale_cloud_authority_binding")
        required = {
            "binding_id": self.binding_id,
            "principal_id": self.principal_id,
            "agent_id": self.agent_id,
            "instance_id": self.instance_id,
            "workload_id": self.workload_id,
            "organization_id": self.organization_id,
            "delegation_digest": self.delegation_digest,
            "identity_evidence_digest": self.identity_evidence_digest,
            "barrier_digest": self.barrier_digest,
        }
        if any(not value for value in required.values()):
            reasons.append("incomplete_cloud_authority_binding")
        return tuple(sorted(set(reasons)))


def redact_token_fields(fields: Mapping[str, str]) -> dict[str, str]:
    """Returns fields safe for experiment logs without bearer material."""

    sensitive = {"subject_token", "client_assertion", "WebIdentityToken"}
    return {
        key: "<redacted>" if key in sensitive else value
        for key, value in fields.items()
    }
