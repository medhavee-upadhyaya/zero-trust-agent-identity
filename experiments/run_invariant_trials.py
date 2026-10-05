from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

from ztai import ClosureVerdict, EffectState, Scope


def decide(
    *,
    closure: ClosureVerdict,
    attestation_fresh: bool,
    effect: EffectState,
    evidence_complete: bool,
) -> str:
    if closure is not ClosureVerdict.QUIESCENT:
        return "quarantined"
    if not attestation_fresh or not evidence_complete or effect is EffectState.AMBIGUOUS:
        return "quarantined"
    return "authorized"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: run_invariant_trials.py SEED OUTPUT_CSV", file=sys.stderr)
        return 2
    seed = int(sys.argv[1])
    output = Path(sys.argv[2])
    rng = random.Random(seed)
    output.parent.mkdir(parents=True, exist_ok=True)

    previous = Scope.of({"read", "write", "pay"}, {"a", "b"}, 1_000)
    fieldnames = [
        "trial",
        "seed",
        "closure",
        "attestation_fresh",
        "effect",
        "evidence_complete",
        "scope_subset",
        "decision",
    ]
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for trial in range(10_000):
            closure = rng.choice(tuple(ClosureVerdict))
            attestation_fresh = rng.choice((True, False))
            effect = rng.choice(tuple(EffectState))
            evidence_complete = rng.choice((True, False))
            current = Scope.of(
                rng.sample(tuple(previous.actions), rng.randrange(len(previous.actions) + 1)),
                rng.sample(tuple(previous.resources), rng.randrange(len(previous.resources) + 1)),
                rng.randrange(1_001),
            )
            recovered = previous.intersect(current)
            writer.writerow(
                {
                    "trial": trial,
                    "seed": seed,
                    "closure": closure.value,
                    "attestation_fresh": attestation_fresh,
                    "effect": effect.value,
                    "evidence_complete": evidence_complete,
                    "scope_subset": recovered.is_subset_of(previous) and recovered.is_subset_of(current),
                    "decision": decide(
                        closure=closure,
                        attestation_fresh=attestation_fresh,
                        effect=effect,
                        evidence_complete=evidence_complete,
                    ),
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
