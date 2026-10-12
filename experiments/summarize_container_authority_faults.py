from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict
from pathlib import Path


def percentile(values: list[int], probability: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def rate(rows: list[dict[str, str]], field: str) -> str:
    applicable = [row for row in rows if row[field] != ""]
    if not applicable:
        return ""
    return f"{sum(row[field] == 'True' for row in applicable) / len(applicable):.6f}"


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_container_authority_faults.py OUTPUT_CSV INPUT_CSV [...]",
            file=sys.stderr,
        )
        return 2
    rows: list[dict[str, str]] = []
    for input_name in sys.argv[2:]:
        with Path(input_name).open(newline="") as handle:
            rows.extend(csv.DictReader(handle))
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[row["scenario"]].append(row)

    fields = (
        "scenario",
        "cases",
        "correct_rate",
        "initial_quarantine_rate",
        "final_authorization_rate",
        "recovery_rate",
        "barrier_valid_rate",
        "forged_endpoint_rejection_rate",
        "pre_barrier_old_commit_rate",
        "pre_barrier_successor_rejection_rate",
        "post_barrier_old_attempts",
        "post_barrier_old_commits",
        "unresolved_effect_calls",
        "transport_retries",
        "exactly_once_rate",
        "complete_durable_ack_rate",
        "latency_p50_us",
        "latency_p95_us",
        "latency_p99_us",
    )
    output = Path(sys.argv[1])
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for scenario in sorted(groups):
            group = groups[scenario]
            latencies = [int(row["latency_ns"]) for row in group]
            writer.writerow(
                {
                    "scenario": scenario,
                    "cases": len(group),
                    "correct_rate": rate(group, "correct"),
                    "initial_quarantine_rate": rate(group, "initial_quarantined"),
                    "final_authorization_rate": rate(group, "final_authorized"),
                    "recovery_rate": rate(group, "recovered_after_retry"),
                    "barrier_valid_rate": rate(group, "barrier_valid"),
                    "forged_endpoint_rejection_rate": rate(
                        group, "forged_endpoint_rejected"
                    ),
                    "pre_barrier_old_commit_rate": rate(
                        group, "pre_barrier_old_commit"
                    ),
                    "pre_barrier_successor_rejection_rate": rate(
                        group, "pre_barrier_successor_rejected"
                    ),
                    "post_barrier_old_attempts": sum(
                        int(row["post_barrier_old_attempts"]) for row in group
                    ),
                    "post_barrier_old_commits": sum(
                        int(row["post_barrier_old_commits"]) for row in group
                    ),
                    "unresolved_effect_calls": sum(
                        int(row["unresolved_effect_calls"]) for row in group
                    ),
                    "transport_retries": sum(
                        int(row["transport_retries"]) for row in group
                    ),
                    "exactly_once_rate": rate(group, "exactly_once"),
                    "complete_durable_ack_rate": rate(
                        group, "complete_durable_acknowledgement_set"
                    ),
                    "latency_p50_us": (
                        f"{percentile(latencies, 0.50) / 1_000:.2f}"
                    ),
                    "latency_p95_us": (
                        f"{percentile(latencies, 0.95) / 1_000:.2f}"
                    ),
                    "latency_p99_us": (
                        f"{percentile(latencies, 0.99) / 1_000:.2f}"
                    ),
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
