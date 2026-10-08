from __future__ import annotations

import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path


BOOLEAN_METRICS = (
    "resumed",
    "authorized",
    "certificate_valid",
    "scope_subset",
    "old_authority_after_incident",
    "old_epochs_closed",
    "outage_first_quarantined",
    "exact_once_workflow",
    "safe_completion",
)
COUNT_METRICS = (
    "stale_deliveries_accepted",
    "duplicate_step_count",
    "incomplete_step_count",
)


def _rate(rows: list[dict[str, str]], field: str) -> str:
    values = [row[field] for row in rows if row[field] != ""]
    if not values:
        return ""
    if any(value not in {"True", "False"} for value in values):
        raise ValueError(f"non-boolean value in {field}")
    return f"{sum(value == 'True' for value in values) / len(values):.6f}"


def _observed(rows: list[dict[str, str]], field: str) -> int:
    return sum(row[field] != "" for row in rows)


def _mean(rows: list[dict[str, str]], field: str) -> str:
    values = [int(row[field]) for row in rows]
    return f"{statistics.mean(values):.6f}"


def _percentile(values: list[int], probability: float) -> float:
    ordered = sorted(values)
    return float(ordered[max(0, math.ceil(probability * len(ordered)) - 1)])


def _groups(rows: list[dict[str, str]]):
    groups: dict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        base = (row["mode"], row["mechanism"])
        groups[(*base, "all", "all")].append(row)
        groups[(*base, "fault", row["fault"])].append(row)
        if row["mechanism"] in {
            "effect_closed_recovery",
            "effect_closed_compensation",
        }:
            groups[(*base, "outage", row["outage_injected"])].append(row)
            groups[(*base, "controller_restart", row["controller_restart"])].append(row)
        if row["mode"] == "forward" and row["mechanism"] == "effect_closed_recovery":
            groups[(*base, "crash_step", row["crash_step"])].append(row)
            groups[(*base, "crash_step_fault", f"{row['crash_step']}:{row['fault']}")].append(
                row
            )
            groups[(*base, "delayed_duplicates", row["delayed_duplicates"])].append(row)
    return groups


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_workflow_faults.py OUTPUT_CSV INPUT_CSV [INPUT_CSV ...]",
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

    fields = (
        "mode",
        "mechanism",
        "slice",
        "slice_value",
        "trials",
        *(item for metric in BOOLEAN_METRICS for item in (f"{metric}_n", f"{metric}_rate")),
        *(f"{metric}_mean" for metric in COUNT_METRICS),
        "latency_median_us",
        "latency_p95_us",
        "latency_p99_us",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for key, group in sorted(_groups(rows).items()):
            mode, mechanism, slice_name, slice_value = key
            latencies = [int(row["recovery_latency_ns"]) for row in group]
            result: dict[str, object] = {
                "mode": mode,
                "mechanism": mechanism,
                "slice": slice_name,
                "slice_value": slice_value,
                "trials": len(group),
                "latency_median_us": f"{statistics.median(latencies) / 1_000:.2f}",
                "latency_p95_us": f"{_percentile(latencies, 0.95) / 1_000:.2f}",
                "latency_p99_us": f"{_percentile(latencies, 0.99) / 1_000:.2f}",
            }
            result.update({f"{metric}_rate": _rate(group, metric) for metric in BOOLEAN_METRICS})
            result.update({f"{metric}_n": _observed(group, metric) for metric in BOOLEAN_METRICS})
            result.update({f"{metric}_mean": _mean(group, metric) for metric in COUNT_METRICS})
            writer.writerow(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
