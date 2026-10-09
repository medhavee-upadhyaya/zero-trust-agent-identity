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
    if not rows:
        return ""
    return f"{sum(row[field] == 'True' for row in rows) / len(rows):.6f}"


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_barrier_baseline_comparison.py OUTPUT_CSV "
            "INPUT_CSV [...]",
            file=sys.stderr,
        )
        return 2
    rows: list[dict[str, str]] = []
    for input_name in sys.argv[2:]:
        with Path(input_name).open(newline="") as handle:
            rows.extend(csv.DictReader(handle))

    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[(row["mechanism"], "all")].append(row)
        groups[(row["mechanism"], row["scenario"])].append(row)

    fields = (
        "mechanism",
        "scenario",
        "cases",
        "valid_cases",
        "attack_cases",
        "valid_acceptance_rate",
        "attack_acceptance_rate",
        "oracle_match_rate",
        "latency_p50_us",
        "latency_p95_us",
        "latency_p99_us",
    )
    output = Path(sys.argv[1])
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for (mechanism, scenario), group in sorted(groups.items()):
            valid = [row for row in group if row["attack"] == "False"]
            attacks = [row for row in group if row["attack"] == "True"]
            latencies = [int(row["latency_ns"]) for row in group]
            writer.writerow(
                {
                    "mechanism": mechanism,
                    "scenario": scenario,
                    "cases": len(group),
                    "valid_cases": len(valid),
                    "attack_cases": len(attacks),
                    "valid_acceptance_rate": rate(valid, "authorized"),
                    "attack_acceptance_rate": rate(attacks, "authorized"),
                    "oracle_match_rate": rate(group, "oracle_match"),
                    "latency_p50_us": f"{percentile(latencies, 0.50) / 1_000:.2f}",
                    "latency_p95_us": f"{percentile(latencies, 0.95) / 1_000:.2f}",
                    "latency_p99_us": f"{percentile(latencies, 0.99) / 1_000:.2f}",
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
