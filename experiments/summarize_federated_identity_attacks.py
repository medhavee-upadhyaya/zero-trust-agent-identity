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
            "usage: summarize_federated_identity_attacks.py OUTPUT_CSV INPUT_CSV [...]",
            file=sys.stderr,
        )
        return 2
    rows: list[dict[str, str]] = []
    for input_name in sys.argv[2:]:
        with Path(input_name).open(newline="") as handle:
            rows.extend(csv.DictReader(handle))
    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[(row["cloud_profile"], row["scenario"])].append(row)
    fields = (
        "cloud_profile",
        "scenario",
        "cases",
        "acceptance_rate",
        "correct_rate",
        "request_shape_valid_rate",
        "token_redacted_rate",
        "latency_p50_us",
        "latency_p95_us",
        "latency_p99_us",
        "execution_mode",
    )
    with Path(sys.argv[1]).open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for cloud, scenario in sorted(groups):
            group = groups[(cloud, scenario)]
            latencies = [int(row["latency_ns"]) for row in group]
            writer.writerow(
                {
                    "cloud_profile": cloud,
                    "scenario": scenario,
                    "cases": len(group),
                    "acceptance_rate": true_rate(group, "accepted"),
                    "correct_rate": true_rate(group, "correct"),
                    "request_shape_valid_rate": true_rate(
                        group, "request_shape_valid"
                    ),
                    "token_redacted_rate": true_rate(group, "token_redacted"),
                    "latency_p50_us": f"{percentile(latencies, 0.50) / 1_000:.2f}",
                    "latency_p95_us": f"{percentile(latencies, 0.95) / 1_000:.2f}",
                    "latency_p99_us": f"{percentile(latencies, 0.99) / 1_000:.2f}",
                    "execution_mode": group[0]["execution_mode"],
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
