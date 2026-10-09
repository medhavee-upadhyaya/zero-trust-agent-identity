from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict
from pathlib import Path


def percentile(values: list[int], probability: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def boolean_rate(rows: list[dict[str, str]], field: str) -> str:
    applicable = [row for row in rows if row[field] != ""]
    if not applicable:
        return ""
    return f"{sum(row[field] == 'True' for row in applicable) / len(applicable):.6f}"


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_networked_authority_faults.py OUTPUT_CSV "
            "INPUT_CSV [...]",
            file=sys.stderr,
        )
        return 2
    rows: list[dict[str, str]] = []
    for input_name in sys.argv[2:]:
        with Path(input_name).open(newline="") as handle:
            rows.extend(csv.DictReader(handle))
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups["all"].append(row)
        groups[row["scenario"]].append(row)

    fields = (
        "scenario",
        "cases",
        "initial_quarantine_rate",
        "final_authorized_rate",
        "correct_rate",
        "barrier_valid_rate",
        "recovered_after_retry_rate",
        "forged_endpoint_rejection_rate",
        "pre_barrier_old_commit_rate",
        "post_barrier_old_attempts",
        "post_barrier_old_commits",
        "successor_replay_rate",
        "exactly_once_rate",
        "durable_transition_rate",
        "latency_p50_us",
        "latency_p95_us",
        "latency_p99_us",
    )
    output = Path(sys.argv[1])
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for scenario, group in sorted(groups.items()):
            latencies = [int(row["latency_ns"]) for row in group]
            successor_total = sum(int(row["successor_replays"]) for row in group)
            writer.writerow(
                {
                    "scenario": scenario,
                    "cases": len(group),
                    "initial_quarantine_rate": boolean_rate(
                        group, "initial_quarantined"
                    ),
                    "final_authorized_rate": boolean_rate(
                        group, "final_authorized"
                    ),
                    "correct_rate": boolean_rate(group, "correct"),
                    "barrier_valid_rate": boolean_rate(group, "barrier_valid"),
                    "recovered_after_retry_rate": boolean_rate(
                        [
                            row
                            for row in group
                            if row["expected_initial_quarantine"] == "True"
                        ],
                        "recovered_after_retry",
                    ),
                    "forged_endpoint_rejection_rate": boolean_rate(
                        group, "forged_endpoint_rejected"
                    ),
                    "pre_barrier_old_commit_rate": boolean_rate(
                        group, "pre_barrier_old_commit"
                    ),
                    "post_barrier_old_attempts": sum(
                        int(row["post_barrier_old_attempts"]) for row in group
                    ),
                    "post_barrier_old_commits": sum(
                        int(row["post_barrier_old_commits"]) for row in group
                    ),
                    "successor_replay_rate": (
                        f"{successor_total / (len(group) * 4):.6f}"
                    ),
                    "exactly_once_rate": boolean_rate(group, "exactly_once"),
                    "durable_transition_rate": boolean_rate(
                        group, "durable_transition_after_reopen"
                    ),
                    "latency_p50_us": f"{percentile(latencies, 0.50) / 1_000:.2f}",
                    "latency_p95_us": f"{percentile(latencies, 0.95) / 1_000:.2f}",
                    "latency_p99_us": f"{percentile(latencies, 0.99) / 1_000:.2f}",
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
