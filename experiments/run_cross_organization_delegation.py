from __future__ import annotations

import csv
import dataclasses
import random
import sys
import time
from pathlib import Path

from ztai import (
    DelegationChainVerifier,
    Ed25519Signer,
    OrganizationDelegation,
    Scope,
    TrustStore,
)
from ztai.model import digest


SCENARIOS = (
    "valid",
    "scope_widening",
    "parent_substitution",
    "untrusted_domain_edge",
    "wrong_signer_domain",
    "wrong_organization",
    "expired_child",
    "time_widening",
    "delegation_cycle",
    "wrong_audience",
    "unexpected_final_delegatee",
    "delegation_truncation",
    "forged_child_signature",
)


def run_case(seed: int, trial: int, scenario: str) -> dict[str, object]:
    now = 70_000 + trial
    utility = Ed25519Signer(f"authority:utility:{seed}:{trial}")
    contractor = Ed25519Signer(f"authority:contractor:{seed}:{trial}")
    attacker = Ed25519Signer(f"attacker:{seed}:{trial}")
    trust = TrustStore()
    trust.register("organization_authority", utility)
    trust.register("organization_authority", contractor)
    root = OrganizationDelegation(
        f"root:{seed}:{trial}",
        "utility",
        "utility.example",
        "operator:alice",
        "agent:coordinator",
        "switch-gateway",
        Scope.of({"inspect", "isolate", "notify"}, {"feeder:7"}),
        "",
        0,
        now - 20,
        now + 300,
        f"root-nonce:{seed}:{trial}",
    )
    child = OrganizationDelegation(
        f"child:{seed}:{trial}",
        "contractor",
        "contractor.example",
        "agent:coordinator",
        "agent:inspection",
        "switch-gateway",
        Scope.of({"inspect"}, {"feeder:7"}),
        digest(root),
        1,
        now - 10,
        now + 100,
        f"child-nonce:{seed}:{trial}",
    )
    edges = frozenset({("utility.example", "contractor.example")})
    expected_final = "agent:inspection"
    child_signer = contractor
    chain_length = 2
    if scenario == "scope_widening":
        child = dataclasses.replace(
            child,
            scope=Scope.of({"inspect", "isolate", "export"}, {"feeder:7"}),
        )
    elif scenario == "parent_substitution":
        child = dataclasses.replace(child, parent_delegation_digest="other")
    elif scenario == "untrusted_domain_edge":
        edges = frozenset()
    elif scenario == "wrong_signer_domain":
        child = dataclasses.replace(child, trust_domain="supplier.example")
    elif scenario == "wrong_organization":
        child = dataclasses.replace(child, organization_id="attacker")
    elif scenario == "expired_child":
        child = dataclasses.replace(child, expires_at=now)
    elif scenario == "time_widening":
        child = dataclasses.replace(child, expires_at=root.expires_at + 1)
    elif scenario == "delegation_cycle":
        child = dataclasses.replace(child, delegatee_id=root.delegatee_id)
    elif scenario == "wrong_audience":
        child = dataclasses.replace(child, audience="other-gateway")
    elif scenario == "unexpected_final_delegatee":
        expected_final = "agent:other"
    elif scenario == "delegation_truncation":
        chain_length = 1
    elif scenario == "forged_child_signature":
        child_signer = attacker

    verifier = DelegationChainVerifier(
        trust,
        signer_domains={
            utility.signer_id: "utility.example",
            contractor.signer_id: "contractor.example",
        },
        signer_organizations={
            utility.signer_id: "utility",
            contractor.signer_id: "contractor",
        },
        allowed_domain_edges=edges,
    )
    chain = (
        utility.sign("organization_delegation", root),
        child_signer.sign("organization_delegation", child),
    )[:chain_length]
    started = time.perf_counter_ns()
    decision = verifier.verify(
        chain,
        expected_audience="switch-gateway",
        expected_final_delegatee=expected_final,
        now=now,
    )
    latency_ns = time.perf_counter_ns() - started
    expected_accept = scenario == "valid"
    return {
        "seed": seed,
        "trial": trial,
        "scenario": scenario,
        "expected_accept": expected_accept,
        "accepted": decision.accepted,
        "correct": decision.accepted == expected_accept,
        "reasons": ";".join(decision.reasons),
        "effective_action_count": (
            len(decision.effective_scope.actions)
            if decision.effective_scope is not None
            else 0
        ),
        "effective_resource_count": (
            len(decision.effective_scope.resources)
            if decision.effective_scope is not None
            else 0
        ),
        "latency_ns": latency_ns,
    }


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: run_cross_organization_delegation.py SEED CYCLES OUTPUT_CSV",
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
