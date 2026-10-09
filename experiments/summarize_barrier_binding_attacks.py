from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict
from pathlib import Path


def percentile(values: list[int], probability: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_barrier_binding_attacks.py OUTPUT_CSV INPUT_CSV [...]",
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

    output = Path(sys.argv[1])
    fields = (
        "scenario",
        "cases",
        "expected_authorized_rate",
        "authorized_rate",
        "correct_rate",
        "latency_p50_us",
        "latency_p95_us",
        "latency_p99_us",
    )
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for scenario, group in sorted(groups.items()):
            latencies = [int(row["latency_ns"]) for row in group]
            writer.writerow(
                {
                    "scenario": scenario,
                    "cases": len(group),
                    "expected_authorized_rate": (
                        f"{sum(row['expected_authorized'] == 'True' for row in group) / len(group):.6f}"
                    ),
                    "authorized_rate": (
                        f"{sum(row['authorized'] == 'True' for row in group) / len(group):.6f}"
                    ),
                    "correct_rate": (
                        f"{sum(row['correct'] == 'True' for row in group) / len(group):.6f}"
                    ),
                    "latency_p50_us": f"{percentile(latencies, 0.50) / 1_000:.2f}",
                    "latency_p95_us": f"{percentile(latencies, 0.95) / 1_000:.2f}",
                    "latency_p99_us": f"{percentile(latencies, 0.99) / 1_000:.2f}",
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
