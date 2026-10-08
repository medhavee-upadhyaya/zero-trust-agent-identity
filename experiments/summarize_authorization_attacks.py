from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict
from pathlib import Path


def truth(value: str) -> bool:
    return value.lower() == "true"


def percentile(values: list[int], fraction: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: summarize_authorization_attacks.py OUTPUT_CSV INPUT_CSV [INPUT_CSV ...]",
            file=sys.stderr,
        )
        return 2
    output = Path(sys.argv[1])
    inputs = [Path(value) for value in sys.argv[2:]]
    rows: list[dict[str, str]] = []
    for path in inputs:
        with path.open(newline="") as handle:
            rows.extend(csv.DictReader(handle))

    by_mechanism: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_cell: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_mechanism[row["mechanism"]].append(row)
        by_cell[(row["mechanism"], row["scenario"])].append(row)

    output.parent.mkdir(parents=True, exist_ok=True)
    fields = ("mechanism", "scenario", "cases", "accepted", "acceptance_rate", "latency_p95_ns")
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for mechanism in sorted(by_mechanism):
            mechanism_rows = by_mechanism[mechanism]
            accepted = sum(truth(row["accepted"]) for row in mechanism_rows)
            writer.writerow(
                {
                    "mechanism": mechanism,
                    "scenario": "all",
                    "cases": len(mechanism_rows),
                    "accepted": accepted,
                    "acceptance_rate": f"{accepted / len(mechanism_rows):.6f}",
                    "latency_p95_ns": percentile(
                        [int(row["latency_ns"]) for row in mechanism_rows], 0.95
                    ),
                }
            )
            for scenario in sorted({key[1] for key in by_cell if key[0] == mechanism}):
                cell = by_cell[(mechanism, scenario)]
                cell_accepted = sum(truth(row["accepted"]) for row in cell)
                writer.writerow(
                    {
                        "mechanism": mechanism,
                        "scenario": scenario,
                        "cases": len(cell),
                        "accepted": cell_accepted,
                        "acceptance_rate": f"{cell_accepted / len(cell):.6f}",
                        "latency_p95_ns": percentile(
                            [int(row["latency_ns"]) for row in cell], 0.95
                        ),
                    }
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
