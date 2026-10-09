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
            "usage: summarize_self_healing_faults.py OUTPUT_CSV INPUT_CSV [...]",
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
        if row["expected_recovered"] == "True":
            groups["slice_recoverable"].append(row)
        if row["expected_authorized"] == "False":
            groups["slice_suspicious_or_permanent"].append(row)

    fields = (
        "scenario",
        "cases",
        "expected_authorized_cases",
        "expected_recovery_cases",
        "final_authorized_rate",
        "recovery_success_rate",
        "correct_rate",
        "false_recovery_rate",
        "false_quarantine_rate",
        "unsafe_release_rate",
        "barrier_valid_rate",
        "audit_valid_rate",
        "attempts_mean",
        "repair_events",
        "transport_repairs",
        "accepted_key_rotations",
        "rejected_key_rotations",
        "post_healing_old_attempts",
        "post_healing_old_commits",
        "exactly_once_rate",
        "latency_p50_us",
        "latency_p95_us",
        "latency_p99_us",
    )
    output = Path(sys.argv[1])
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for scenario, group in sorted(groups.items()):
            expected_authorized = [
                row for row in group if row["expected_authorized"] == "True"
            ]
            expected_recovery = [
                row for row in group if row["expected_recovered"] == "True"
            ]
            suspicious = [
                row for row in group if row["expected_authorized"] == "False"
            ]
            authorized = [
                row for row in group if row["final_authorized"] == "True"
            ]
            latencies = [int(row["latency_ns"]) for row in group]
            writer.writerow(
                {
                    "scenario": scenario,
                    "cases": len(group),
                    "expected_authorized_cases": len(expected_authorized),
                    "expected_recovery_cases": len(expected_recovery),
                    "final_authorized_rate": rate(group, "final_authorized"),
                    "recovery_success_rate": rate(
                        expected_recovery, "recovered"
                    ),
                    "correct_rate": rate(group, "correct"),
                    "false_recovery_rate": rate(
                        suspicious, "false_recovery"
                    ),
                    "false_quarantine_rate": rate(
                        expected_authorized, "false_quarantine"
                    ),
                    "unsafe_release_rate": rate(group, "unsafe_release"),
                    "barrier_valid_rate": rate(authorized, "barrier_valid"),
                    "audit_valid_rate": rate(group, "audit_valid"),
                    "attempts_mean": (
                        f"{sum(int(row['attempts']) for row in group) / len(group):.6f}"
                    ),
                    "repair_events": sum(
                        int(row["repair_events"]) for row in group
                    ),
                    "transport_repairs": sum(
                        int(row["transport_repairs"]) for row in group
                    ),
                    "accepted_key_rotations": sum(
                        int(row["accepted_key_rotations"]) for row in group
                    ),
                    "rejected_key_rotations": sum(
                        int(row["rejected_key_rotations"]) for row in group
                    ),
                    "post_healing_old_attempts": sum(
                        int(row["post_healing_old_attempts"]) for row in group
                    ),
                    "post_healing_old_commits": sum(
                        int(row["post_healing_old_commits"]) for row in group
                    ),
                    "exactly_once_rate": rate(authorized, "exactly_once"),
                    "latency_p50_us": f"{percentile(latencies, 0.50) / 1_000:.2f}",
                    "latency_p95_us": f"{percentile(latencies, 0.95) / 1_000:.2f}",
                    "latency_p99_us": f"{percentile(latencies, 0.99) / 1_000:.2f}",
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
