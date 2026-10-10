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
            "usage: summarize_self_healing_ablation.py OUTPUT_CSV "
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
        "recoverable_cases",
        "suspicious_cases",
        "final_authorized_rate",
        "recovery_success_rate",
        "false_recovery_rate",
        "false_quarantine_rate",
        "unsafe_release_rate",
        "oracle_match_rate",
        "barrier_valid_rate",
        "post_barrier_old_attempts",
        "post_barrier_old_commits",
        "latency_p50_us",
        "latency_p95_us",
        "latency_p99_us",
    )
    output = Path(sys.argv[1])
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for (mechanism, scenario), group in sorted(groups.items()):
            recoverable = [
                row for row in group if row["expected_recovered"] == "True"
            ]
            suspicious = [
                row for row in group if row["expected_authorized"] == "False"
            ]
            expected_authorized = [
                row for row in group if row["expected_authorized"] == "True"
            ]
            authorized = [
                row for row in group if row["final_authorized"] == "True"
            ]
            latencies = [int(row["latency_ns"]) for row in group]
            writer.writerow(
                {
                    "mechanism": mechanism,
                    "scenario": scenario,
                    "cases": len(group),
                    "recoverable_cases": len(recoverable),
                    "suspicious_cases": len(suspicious),
                    "final_authorized_rate": rate(group, "final_authorized"),
                    "recovery_success_rate": rate(recoverable, "recovered"),
                    "false_recovery_rate": rate(
                        suspicious, "false_recovery"
                    ),
                    "false_quarantine_rate": rate(
                        expected_authorized, "false_quarantine"
                    ),
                    "unsafe_release_rate": rate(group, "unsafe_release"),
                    "oracle_match_rate": rate(group, "oracle_match"),
                    "barrier_valid_rate": rate(authorized, "barrier_valid"),
                    "post_barrier_old_attempts": sum(
                        int(row["post_barrier_old_attempts"]) for row in group
                    ),
                    "post_barrier_old_commits": sum(
                        int(row["post_barrier_old_commits"]) for row in group
                    ),
                    "latency_p50_us": f"{percentile(latencies, 0.50) / 1_000:.2f}",
                    "latency_p95_us": f"{percentile(latencies, 0.95) / 1_000:.2f}",
                    "latency_p99_us": f"{percentile(latencies, 0.99) / 1_000:.2f}",
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
