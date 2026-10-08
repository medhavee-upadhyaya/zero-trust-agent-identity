from __future__ import annotations

import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path


BOOLEAN_FIELDS = (
    "recovery_decision_authorized",
    "workflow_completed",
    "expected_quarantine",
    "attack_attempted",
    "attack_blocked",
    "attack_accepted",
    "old_epochs_closed",
    "exact_once_workflow",
    "safe_outcome",
)


def rate(rows: list[dict[str, str]], field: str) -> str:
    values = [row[field] for row in rows]
    return f"{sum(value == 'True' for value in values) / len(values):.6f}"


def percentile(values: list[int], probability: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_secure_workflow_attacks.py OUTPUT_CSV INPUT_CSV [INPUT_CSV ...]",
            file=sys.stderr,
        )
        return 2
    output = Path(sys.argv[1])
    rows: list[dict[str, str]] = []
    for input_name in sys.argv[2:]:
        with Path(input_name).open(newline="") as handle:
            rows.extend(csv.DictReader(handle))
    if not rows:
        raise ValueError("no experiment rows")

    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[("scenario", row["scenario"])].append(row)
        groups[("fault", row["fault"])].append(row)
        groups[("crash_step", row["crash_step"])].append(row)
    groups[("all", "all")] = rows

    fields = (
        "slice",
        "slice_value",
        "cases",
        *(f"{field}_rate" for field in BOOLEAN_FIELDS),
        "stale_deliveries_accepted_mean",
        "incomplete_steps_mean",
        "latency_median_us",
        "latency_p95_us",
        "latency_p99_us",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for (slice_name, slice_value), group in sorted(groups.items()):
            latencies = [int(row["recovery_latency_ns"]) for row in group]
            result: dict[str, object] = {
                "slice": slice_name,
                "slice_value": slice_value,
                "cases": len(group),
                "stale_deliveries_accepted_mean": (
                    f"{statistics.mean(int(row['stale_deliveries_accepted']) for row in group):.6f}"
                ),
                "incomplete_steps_mean": (
                    f"{statistics.mean(int(row['incomplete_steps']) for row in group):.6f}"
                ),
                "latency_median_us": f"{statistics.median(latencies) / 1_000:.2f}",
                "latency_p95_us": f"{percentile(latencies, 0.95) / 1_000:.2f}",
                "latency_p99_us": f"{percentile(latencies, 0.99) / 1_000:.2f}",
            }
            result.update({f"{field}_rate": rate(group, field) for field in BOOLEAN_FIELDS})
            writer.writerow(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
