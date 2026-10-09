from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict
from pathlib import Path


BOOLEAN_FIELDS = (
    "expected_authorized",
    "initial_quarantined",
    "final_authorized",
    "correct",
    "barrier_valid",
    "recovered_after_heal",
    "successor_without_barrier",
    "exactly_once",
    "queued_old_rejected",
    "durable_transition_after_reopen",
)
COUNT_FIELDS = (
    "propagation_rounds",
    "old_effect_attempts_after_barrier",
    "old_effect_commits_after_barrier",
    "successor_effects",
    "unresolved_old_providers",
)


def observed_rate(rows: list[dict[str, str]], field: str) -> tuple[int, str]:
    values = [row[field] for row in rows if row[field] != ""]
    if not values:
        return 0, ""
    return len(values), f"{sum(value == 'True' for value in values) / len(values):.6f}"


def percentile(values: list[int], probability: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_distributed_authority_faults.py OUTPUT_CSV INPUT_CSV [...]",
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
        *(item for field in BOOLEAN_FIELDS for item in (f"{field}_n", f"{field}_rate")),
        *(f"{field}_mean" for field in COUNT_FIELDS),
        "latency_p50_us",
        "latency_p95_us",
        "latency_p99_us",
    )
    output = Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for scenario, group in sorted(groups.items()):
            latencies = [int(row["latency_ns"]) for row in group]
            result: dict[str, object] = {
                "scenario": scenario,
                "cases": len(group),
                "latency_p50_us": f"{percentile(latencies, 0.50) / 1_000:.2f}",
                "latency_p95_us": f"{percentile(latencies, 0.95) / 1_000:.2f}",
                "latency_p99_us": f"{percentile(latencies, 0.99) / 1_000:.2f}",
            }
            for field in BOOLEAN_FIELDS:
                observed, rate = observed_rate(group, field)
                result[f"{field}_n"] = observed
                result[f"{field}_rate"] = rate
            for field in COUNT_FIELDS:
                mean = sum(int(row[field]) for row in group) / len(group)
                result[f"{field}_mean"] = f"{mean:.6f}"
            writer.writerow(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
