from __future__ import annotations

import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path


BOOLEAN_METRICS = (
    "resumed",
    "old_authority_accepted_after_incident",
    "recovery_authorized",
    "signed_evidence_valid",
    "certificate_valid",
    "scope_subset",
    "exact_once",
    "duplicate_effect",
    "incomplete",
    "safe_completion",
)


def _rate(rows: list[dict[str, str]], field: str) -> str:
    observed = [row[field] for row in rows if row[field] != ""]
    if not observed:
        return ""
    if any(value not in {"True", "False"} for value in observed):
        raise ValueError(f"non-boolean value in {field}")
    return f"{sum(value == 'True' for value in observed) / len(observed):.6f}"


def _percentile(values: list[int], probability: float) -> float:
    ordered = sorted(values)
    return float(ordered[max(0, math.ceil(probability * len(ordered)) - 1)])


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_provider_faults.py OUTPUT_CSV INPUT_CSV [INPUT_CSV ...]",
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

    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[(row["mechanism"], "all")].append(row)
        grouped[(row["mechanism"], row["fault"])].append(row)

    fields = (
        "mechanism",
        "fault",
        "trials",
        *(f"{metric}_rate" for metric in BOOLEAN_METRICS),
        "latency_median_us",
        "latency_p95_us",
        "latency_p99_us",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for mechanism, fault in sorted(grouped):
            group = grouped[(mechanism, fault)]
            latencies = [int(row["recovery_latency_ns"]) for row in group]
            result: dict[str, object] = {
                "mechanism": mechanism,
                "fault": fault,
                "trials": len(group),
                "latency_median_us": f"{statistics.median(latencies) / 1_000:.2f}",
                "latency_p95_us": f"{_percentile(latencies, 0.95) / 1_000:.2f}",
                "latency_p99_us": f"{_percentile(latencies, 0.99) / 1_000:.2f}",
            }
            result.update({f"{metric}_rate": _rate(group, metric) for metric in BOOLEAN_METRICS})
            writer.writerow(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
