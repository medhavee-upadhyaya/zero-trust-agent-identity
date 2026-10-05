from __future__ import annotations

import csv
import random
import sys
from dataclasses import dataclass
from pathlib import Path


SYSTEMS = (
    "restart_bearer",
    "revoke_restart",
    "heartbeat_bound",
    "single_effect_guard",
    "root_quiescence",
    "posture_checked_rotation",
    "effect_closed_recovery",
)


@dataclass(frozen=True)
class Trial:
    credential_live: bool
    durable_carrier_live: bool
    repaired_runtime_good: bool
    attestation_available: bool
    previous_actions: frozenset[str]
    current_actions: frozenset[str]
    effect_states: tuple[str, ...]
    provider_evidence_complete: bool


@dataclass(frozen=True)
class Outcome:
    resumed: bool
    authority_overlap: bool
    bad_runtime_authorized: bool
    privilege_rebound: bool
    duplicate_effect: bool
    safe_completion: bool
    unnecessary_quarantine: bool


def evaluate(system: str, trial: Trial) -> Outcome:
    old_authority_live = trial.credential_live or trial.durable_carrier_live
    all_effects_known = trial.provider_evidence_complete and "ambiguous" not in trial.effect_states
    objectively_safe = (
        not old_authority_live
        and trial.repaired_runtime_good
        and all_effects_known
    )

    if system == "restart_bearer":
        resumed = True
        granted = trial.previous_actions
        replay_states = trial.effect_states
    elif system == "revoke_restart":
        resumed = True
        granted = trial.current_actions
        replay_states = trial.effect_states
        old_authority_live = trial.durable_carrier_live
    elif system == "heartbeat_bound":
        resumed = True
        granted = trial.previous_actions
        replay_states = trial.effect_states
        old_authority_live = trial.durable_carrier_live
    elif system == "single_effect_guard":
        resumed = trial.provider_evidence_complete and trial.effect_states[0] != "ambiguous"
        granted = trial.previous_actions & trial.current_actions
        replay_states = ("skip",) + trial.effect_states[1:]
    elif system == "root_quiescence":
        resumed = not old_authority_live
        granted = trial.previous_actions & trial.current_actions
        replay_states = trial.effect_states
    elif system == "posture_checked_rotation":
        resumed = trial.attestation_available and trial.repaired_runtime_good
        granted = trial.current_actions
        replay_states = trial.effect_states
    elif system == "effect_closed_recovery":
        resumed = (
            not old_authority_live
            and trial.attestation_available
            and trial.repaired_runtime_good
            and all_effects_known
        )
        granted = trial.previous_actions & trial.current_actions
        replay_states = tuple("skip" if state == "committed" else state for state in trial.effect_states)
    else:
        raise ValueError(system)

    duplicate = resumed and any(state in {"committed", "ambiguous"} for state in replay_states)
    overlap = resumed and old_authority_live
    bad_runtime = resumed and not trial.repaired_runtime_good
    privilege_rebound = resumed and not granted <= (trial.previous_actions & trial.current_actions)
    safe_completion = resumed and not (overlap or bad_runtime or privilege_rebound or duplicate)
    unnecessary_quarantine = not resumed and objectively_safe
    return Outcome(
        resumed,
        overlap,
        bad_runtime,
        privilege_rebound,
        duplicate,
        safe_completion,
        unnecessary_quarantine,
    )


def make_trial(rng: random.Random) -> Trial:
    universe = ("read", "write", "pay", "refund", "notify")
    previous = frozenset(rng.sample(universe, rng.randrange(1, len(universe) + 1)))
    current = frozenset(rng.sample(universe, rng.randrange(1, len(universe) + 1)))
    states = tuple(
        rng.choice(("not_started", "no_effect", "committed", "ambiguous"))
        for _ in range(rng.randrange(2, 7))
    )
    return Trial(
        credential_live=rng.random() < 0.15,
        durable_carrier_live=rng.random() < 0.25,
        repaired_runtime_good=rng.random() < 0.9,
        attestation_available=rng.random() < 0.95,
        previous_actions=previous,
        current_actions=current,
        effect_states=states,
        provider_evidence_complete=rng.random() < 0.9,
    )


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: compare_baselines.py SEED TRIALS OUTPUT_CSV", file=sys.stderr)
        return 2
    seed = int(sys.argv[1])
    trials = int(sys.argv[2])
    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    fields = (
        "trial",
        "seed",
        "system",
        "resumed",
        "authority_overlap",
        "bad_runtime_authorized",
        "privilege_rebound",
        "duplicate_effect",
        "safe_completion",
        "unnecessary_quarantine",
    )
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for trial_id in range(trials):
            trial = make_trial(rng)
            for system in SYSTEMS:
                outcome = evaluate(system, trial)
                writer.writerow(
                    {
                        "trial": trial_id,
                        "seed": seed,
                        "system": system,
                        **outcome.__dict__,
                    }
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
