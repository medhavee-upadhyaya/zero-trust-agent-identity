from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict
from pathlib import Path


PROPOSED = "bounded_attested_healing"


def percentile(values: list[int], probability: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_self_healing_ablation_pairs.py OUTPUT_CSV "
            "INPUT_CSV [...]",
            file=sys.stderr,
        )
        return 2
    pairs: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for input_name in sys.argv[2:]:
        with Path(input_name).open(newline="") as handle:
            for row in csv.DictReader(handle):
                pairs[row["pair_id"]][row["mechanism"]] = row

    comparators = sorted(
        {
            mechanism
            for pair in pairs.values()
            for mechanism in pair
            if mechanism != PROPOSED
        }
    )
    fields = (
        "comparator",
        "paired_cases",
        "recoverable_pairs",
        "suspicious_pairs",
        "comparator_recovery_rate",
        "proposed_recovery_rate",
        "recovery_rate_difference",
        "comparator_false_recovery_rate",
        "proposed_false_recovery_rate",
        "false_recovery_rate_difference",
        "comparator_only_correct",
        "proposed_only_correct",
        "both_correct",
        "both_incorrect",
        "proposed_minus_comparator_latency_p50_us",
        "proposed_minus_comparator_latency_p95_us",
        "proposed_minus_comparator_latency_p99_us",
    )
    output = Path(sys.argv[1])
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for comparator in comparators:
            compared = []
            for pair_id, pair in pairs.items():
                if comparator not in pair or PROPOSED not in pair:
                    raise AssertionError(f"incomplete pair: {pair_id}")
                compared.append((pair[comparator], pair[PROPOSED]))
            recoverable = [
                pair
                for pair in compared
                if pair[0]["expected_recovered"] == "True"
            ]
            suspicious = [
                pair
                for pair in compared
                if pair[0]["expected_authorized"] == "False"
            ]
            comparator_recovery = sum(
                pair[0]["recovered"] == "True" for pair in recoverable
            ) / len(recoverable)
            proposed_recovery = sum(
                pair[1]["recovered"] == "True" for pair in recoverable
            ) / len(recoverable)
            comparator_false = sum(
                pair[0]["false_recovery"] == "True" for pair in suspicious
            ) / len(suspicious)
            proposed_false = sum(
                pair[1]["false_recovery"] == "True" for pair in suspicious
            ) / len(suspicious)
            comparator_only = sum(
                pair[0]["oracle_match"] == "True"
                and pair[1]["oracle_match"] == "False"
                for pair in compared
            )
            proposed_only = sum(
                pair[0]["oracle_match"] == "False"
                and pair[1]["oracle_match"] == "True"
                for pair in compared
            )
            both_correct = sum(
                pair[0]["oracle_match"] == "True"
                and pair[1]["oracle_match"] == "True"
                for pair in compared
            )
            latency_deltas = [
                int(pair[1]["latency_ns"]) - int(pair[0]["latency_ns"])
                for pair in compared
            ]
            writer.writerow(
                {
                    "comparator": comparator,
                    "paired_cases": len(compared),
                    "recoverable_pairs": len(recoverable),
                    "suspicious_pairs": len(suspicious),
                    "comparator_recovery_rate": f"{comparator_recovery:.6f}",
                    "proposed_recovery_rate": f"{proposed_recovery:.6f}",
                    "recovery_rate_difference": (
                        f"{proposed_recovery - comparator_recovery:.6f}"
                    ),
                    "comparator_false_recovery_rate": f"{comparator_false:.6f}",
                    "proposed_false_recovery_rate": f"{proposed_false:.6f}",
                    "false_recovery_rate_difference": (
                        f"{proposed_false - comparator_false:.6f}"
                    ),
                    "comparator_only_correct": comparator_only,
                    "proposed_only_correct": proposed_only,
                    "both_correct": both_correct,
                    "both_incorrect": (
                        len(compared)
                        - comparator_only
                        - proposed_only
                        - both_correct
                    ),
                    "proposed_minus_comparator_latency_p50_us": (
                        f"{percentile(latency_deltas, 0.50) / 1_000:.2f}"
                    ),
                    "proposed_minus_comparator_latency_p95_us": (
                        f"{percentile(latency_deltas, 0.95) / 1_000:.2f}"
                    ),
                    "proposed_minus_comparator_latency_p99_us": (
                        f"{percentile(latency_deltas, 0.99) / 1_000:.2f}"
                    ),
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
