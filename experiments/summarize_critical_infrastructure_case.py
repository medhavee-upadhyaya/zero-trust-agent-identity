from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict
from pathlib import Path


def percentile(values: list[int], probability: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def true_rate(rows: list[dict[str, str]], field: str) -> str:
    return f"{sum(row[field] == 'True' for row in rows) / len(rows):.6f}"


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_critical_infrastructure_case.py OUTPUT_CSV INPUT_CSV [...]",
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
        "target_authorization_rate",
        "unsafe_isolations",
        "replay_success_rate",
        "latency_p50_us",
        "latency_p95_us",
        "latency_p99_us",
        "execution_mode",
    )
    with Path(sys.argv[1]).open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for scenario in sorted(groups):
            group = groups[scenario]
            latencies = [int(row["latency_ns"]) for row in group]
            writer.writerow(
                {
                    "scenario": scenario,
                    "cases": len(group),
                    "correct_rate": true_rate(group, "correct"),
                    "target_authorization_rate": true_rate(
                        group, "authorized_target"
                    ),
                    "unsafe_isolations": sum(
                        row["unsafe_isolation"] == "True" for row in group
                    ),
                    "replay_success_rate": true_rate(group, "replayed"),
                    "latency_p50_us": f"{percentile(latencies, 0.50) / 1_000:.2f}",
                    "latency_p95_us": f"{percentile(latencies, 0.95) / 1_000:.2f}",
                    "latency_p99_us": f"{percentile(latencies, 0.99) / 1_000:.2f}",
                    "execution_mode": group[0]["execution_mode"],
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
