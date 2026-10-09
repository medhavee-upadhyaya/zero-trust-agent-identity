from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict
from pathlib import Path


BARRIER_MECHANISM = "barrier_bound_principal_chain"


def percentile(values: list[int], probability: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_barrier_baseline_pairs.py OUTPUT_CSV "
            "INPUT_CSV [...]",
            file=sys.stderr,
        )
        return 2
    cases: dict[tuple[str, str], dict[str, dict[str, str]]] = defaultdict(dict)
    for input_name in sys.argv[2:]:
        with Path(input_name).open(newline="") as handle:
            for row in csv.DictReader(handle):
                cases[(row["seed"], row["trial"])][row["mechanism"]] = row

    mechanisms = sorted(
        {
            mechanism
            for case in cases.values()
            for mechanism in case
            if mechanism != BARRIER_MECHANISM
        }
    )
    fields = (
        "baseline",
        "paired_cases",
        "valid_pairs",
        "attack_pairs",
        "baseline_attack_acceptance_rate",
        "barrier_attack_acceptance_rate",
        "absolute_attack_acceptance_reduction",
        "baseline_only_unsafe",
        "barrier_only_unsafe",
        "both_unsafe",
        "both_safe",
        "barrier_minus_baseline_latency_p50_us",
        "barrier_minus_baseline_latency_p95_us",
        "barrier_minus_baseline_latency_p99_us",
    )
    output = Path(sys.argv[1])
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for mechanism in mechanisms:
            pairs = []
            for identity, case in cases.items():
                if mechanism not in case or BARRIER_MECHANISM not in case:
                    raise AssertionError(f"incomplete mechanism pair: {identity}")
                baseline = case[mechanism]
                barrier = case[BARRIER_MECHANISM]
                if baseline["scenario"] != barrier["scenario"]:
                    raise AssertionError(f"scenario mismatch: {identity}")
                pairs.append((baseline, barrier))

            valid = [pair for pair in pairs if pair[0]["attack"] == "False"]
            attacks = [pair for pair in pairs if pair[0]["attack"] == "True"]
            baseline_unsafe = sum(pair[0]["authorized"] == "True" for pair in attacks)
            barrier_unsafe = sum(pair[1]["authorized"] == "True" for pair in attacks)
            baseline_only = sum(
                pair[0]["authorized"] == "True"
                and pair[1]["authorized"] == "False"
                for pair in attacks
            )
            barrier_only = sum(
                pair[0]["authorized"] == "False"
                and pair[1]["authorized"] == "True"
                for pair in attacks
            )
            both_unsafe = sum(
                pair[0]["authorized"] == "True"
                and pair[1]["authorized"] == "True"
                for pair in attacks
            )
            both_safe = len(attacks) - baseline_only - barrier_only - both_unsafe
            deltas = [
                int(barrier["latency_ns"]) - int(baseline["latency_ns"])
                for baseline, barrier in pairs
            ]
            baseline_rate = baseline_unsafe / len(attacks)
            barrier_rate = barrier_unsafe / len(attacks)
            writer.writerow(
                {
                    "baseline": mechanism,
                    "paired_cases": len(pairs),
                    "valid_pairs": len(valid),
                    "attack_pairs": len(attacks),
                    "baseline_attack_acceptance_rate": f"{baseline_rate:.6f}",
                    "barrier_attack_acceptance_rate": f"{barrier_rate:.6f}",
                    "absolute_attack_acceptance_reduction": (
                        f"{baseline_rate - barrier_rate:.6f}"
                    ),
                    "baseline_only_unsafe": baseline_only,
                    "barrier_only_unsafe": barrier_only,
                    "both_unsafe": both_unsafe,
                    "both_safe": both_safe,
                    "barrier_minus_baseline_latency_p50_us": (
                        f"{percentile(deltas, 0.50) / 1_000:.2f}"
                    ),
                    "barrier_minus_baseline_latency_p95_us": (
                        f"{percentile(deltas, 0.95) / 1_000:.2f}"
                    ),
                    "barrier_minus_baseline_latency_p99_us": (
                        f"{percentile(deltas, 0.99) / 1_000:.2f}"
                    ),
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
