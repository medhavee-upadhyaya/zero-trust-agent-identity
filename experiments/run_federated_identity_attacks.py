from __future__ import annotations

import csv
import dataclasses
import random
import sys
import time
from pathlib import Path

from ztai import (
    AwsWebIdentityConfig,
    Ed25519Signer,
    FederatedIdentityBinding,
    FederatedIdentityVerifier,
    GoogleWorkloadFederationConfig,
    MicrosoftEntraFederationConfig,
    TrustStore,
    WorkloadIdentityEvidence,
    redact_token_fields,
)
from ztai.model import digest


SCENARIOS = (
    "valid",
    "wrong_audience",
    "wrong_subject",
    "wrong_trust_domain",
    "uppercase_trust_domain",
    "percent_encoded_path",
    "relative_path_segment",
    "wrong_issuer_url",
    "expired_identity",
    "wrong_agent",
    "wrong_instance",
    "stale_epoch",
    "missing_provider",
    "tampered_evidence_digest",
    "forged_identity_signature",
    "forged_binding_signature",
)
CLOUDS = ("aws", "google", "microsoft")
PROVIDERS = ("crew-access", "switch-gateway", "work-order")


def cloud_request_shape(cloud: str, token: str) -> tuple[bool, bool]:
    if cloud == "google":
        fields = GoogleWorkloadFederationConfig(
            "123456", "agent-pool", "spire"
        ).token_exchange(token).form_fields()
        safe = redact_token_fields(fields)
        return (
            fields["grant_type"]
            == "urn:ietf:params:oauth:grant-type:token-exchange",
            safe["subject_token"] == "<redacted>",
        )
    if cloud == "microsoft":
        fields = MicrosoftEntraFederationConfig(
            "tenant-test", "client-test", "https://storage.azure.com/.default"
        ).client_assertion_fields(token)
        safe = redact_token_fields(fields)
        return (
            fields["grant_type"] == "client_credentials",
            safe["client_assertion"] == "<redacted>",
        )
    fields = AwsWebIdentityConfig(
        "arn:aws:iam::123456789012:role/agent-test",
        "agent-instance",
    ).query_fields(token)
    safe = redact_token_fields(fields)
    return fields["Action"] == "AssumeRoleWithWebIdentity", safe["WebIdentityToken"] == "<redacted>"


def run_case(seed: int, trial: int, scenario: str, cloud: str) -> dict[str, object]:
    now = 50_000 + trial
    issuer = Ed25519Signer(f"spire:utility:{seed}:{trial}")
    federation = Ed25519Signer(f"federation:utility:{seed}:{trial}")
    attacker = Ed25519Signer(f"attacker:{seed}:{trial}")
    trust = TrustStore()
    trust.register("workload_identity_issuer", issuer)
    trust.register("federation_authority", federation)
    evidence = WorkloadIdentityEvidence(
        spiffe_id="spiffe://utility.example/agent/restoration/instance-7",
        issuer="https://spire.utility.example",
        subject="spiffe://utility.example/agent/restoration/instance-7",
        audience="cloud-sts",
        organization_id="utility",
        agent_id="restoration-agent",
        instance_id="instance-7",
        public_key_fingerprint=issuer.public_key_fingerprint,
        issued_at=now - 10,
        expires_at=now + 300,
        nonce=f"nonce:{seed}:{trial}",
    )
    binding = FederatedIdentityBinding(
        binding_id=f"binding:{seed}:{trial}",
        principal_id="operator:alice",
        workload_id="agent/restoration",
        agent_id="restoration-agent",
        instance_id="instance-7",
        organization_id="utility",
        delegation_id=f"delegation:{seed}:{trial}",
        authority_epoch=7,
        audience="cloud-sts",
        provider_ids=PROVIDERS,
        evidence_digest=digest(evidence),
        issued_at=now - 5,
        expires_at=now + 200,
    )
    issuer_for_case = issuer
    federation_for_case = federation
    if scenario == "wrong_audience":
        evidence = dataclasses.replace(evidence, audience="attacker-sts")
        binding = dataclasses.replace(binding, evidence_digest=digest(evidence))
    elif scenario == "wrong_subject":
        evidence = dataclasses.replace(evidence, subject="spiffe://utility.example/agent/other")
        binding = dataclasses.replace(binding, evidence_digest=digest(evidence))
    elif scenario == "wrong_trust_domain":
        evidence = dataclasses.replace(
            evidence,
            spiffe_id="spiffe://attacker.example/agent/restoration/instance-7",
            subject="spiffe://attacker.example/agent/restoration/instance-7",
        )
        binding = dataclasses.replace(binding, evidence_digest=digest(evidence))
    elif scenario == "uppercase_trust_domain":
        evidence = dataclasses.replace(
            evidence,
            spiffe_id="spiffe://Utility.example/agent/restoration/instance-7",
            subject="spiffe://Utility.example/agent/restoration/instance-7",
        )
        binding = dataclasses.replace(binding, evidence_digest=digest(evidence))
    elif scenario == "percent_encoded_path":
        evidence = dataclasses.replace(
            evidence,
            spiffe_id="spiffe://utility.example/agent/%2e%2e/admin",
            subject="spiffe://utility.example/agent/%2e%2e/admin",
        )
        binding = dataclasses.replace(binding, evidence_digest=digest(evidence))
    elif scenario == "relative_path_segment":
        evidence = dataclasses.replace(
            evidence,
            spiffe_id="spiffe://utility.example/agent/../admin",
            subject="spiffe://utility.example/agent/../admin",
        )
        binding = dataclasses.replace(binding, evidence_digest=digest(evidence))
    elif scenario == "wrong_issuer_url":
        evidence = dataclasses.replace(evidence, issuer="https://attacker.example")
        binding = dataclasses.replace(binding, evidence_digest=digest(evidence))
    elif scenario == "expired_identity":
        evidence = dataclasses.replace(evidence, expires_at=now)
        binding = dataclasses.replace(
            binding,
            evidence_digest=digest(evidence),
            expires_at=now,
        )
    elif scenario == "wrong_agent":
        binding = dataclasses.replace(binding, agent_id="other-agent")
    elif scenario == "wrong_instance":
        binding = dataclasses.replace(binding, instance_id="attacker-instance")
    elif scenario == "stale_epoch":
        binding = dataclasses.replace(binding, authority_epoch=6)
    elif scenario == "missing_provider":
        binding = dataclasses.replace(binding, provider_ids=("crew-access", "work-order"))
    elif scenario == "tampered_evidence_digest":
        binding = dataclasses.replace(binding, evidence_digest="0" * 64)
    elif scenario == "forged_identity_signature":
        issuer_for_case = attacker
    elif scenario == "forged_binding_signature":
        federation_for_case = attacker

    verifier = FederatedIdentityVerifier(
        trust,
        issuer_trust_domains={issuer.signer_id: "utility.example"},
        issuer_urls={issuer.signer_id: "https://spire.utility.example"},
    )
    started = time.perf_counter_ns()
    decision = verifier.verify(
        issuer_for_case.sign("workload_identity_evidence", evidence),
        federation_for_case.sign("federated_identity_binding", binding),
        expected_audience="cloud-sts",
        expected_principal_id="operator:alice",
        expected_workload_id="agent/restoration",
        expected_organization_id="utility",
        expected_agent_id="restoration-agent",
        expected_instance_id="instance-7",
        expected_epoch=7,
        required_provider_ids=("switch-gateway", "work-order"),
        now=now,
    )
    latency_ns = time.perf_counter_ns() - started
    request_shape_valid, token_redacted = cloud_request_shape(
        cloud,
        f"synthetic-token:{seed}:{trial}",
    )
    expected_accept = scenario == "valid"
    return {
        "seed": seed,
        "trial": trial,
        "scenario": scenario,
        "cloud_profile": cloud,
        "execution_mode": "offline_protocol_shape",
        "expected_accept": expected_accept,
        "accepted": decision.accepted,
        "correct": decision.accepted == expected_accept,
        "reasons": ";".join(decision.reasons),
        "request_shape_valid": request_shape_valid,
        "token_redacted": token_redacted,
        "latency_ns": latency_ns,
    }


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: run_federated_identity_attacks.py SEED CYCLES OUTPUT_CSV",
            file=sys.stderr,
        )
        return 2
    seed = int(sys.argv[1])
    cycles = int(sys.argv[2])
    output = Path(sys.argv[3])
    if cycles < 1:
        raise ValueError("cycles must be positive")
    rng = random.Random(seed)
    cases = [
        (scenario, cloud)
        for _ in range(cycles)
        for scenario in SCENARIOS
        for cloud in CLOUDS
    ]
    rng.shuffle(cases)
    rows = [
        run_case(seed, trial, scenario, cloud)
        for trial, (scenario, cloud) in enumerate(cases)
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=tuple(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
