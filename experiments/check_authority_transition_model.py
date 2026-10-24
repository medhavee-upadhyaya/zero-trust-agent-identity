from __future__ import annotations

import argparse
import csv
from collections import deque
from dataclasses import dataclass
from pathlib import Path


PROVIDERS = 3
COMPLETE = (1 << PROVIDERS) - 1


@dataclass(frozen=True)
class State:
    retired_first: int = 0
    retired_second: int = 0
    barrier_first: bool = False
    barrier_second: bool = False
    released_first: bool = False
    released_second: bool = False
    attested_key_versions: int = 0
    trusted_key_version: int = 1


@dataclass(frozen=True)
class Model:
    name: str
    early_release: bool = False
    incomplete_barrier: bool = False
    blind_key_repair: bool = False


MODELS = (
    Model("protocol"),
    Model("mutant_release_without_barrier", early_release=True),
    Model("mutant_incomplete_provider_barrier", incomplete_barrier=True),
    Model("mutant_blind_key_repair", blind_key_repair=True),
)


def successors(state: State, model: Model) -> list[tuple[str, State]]:
    result: list[tuple[str, State]] = []
    for provider in range(PROVIDERS):
        bit = 1 << provider
        if not state.retired_first & bit:
            result.append(
                (
                    f"retire:first:p{provider}",
                    State(**{**state.__dict__, "retired_first": state.retired_first | bit}),
                )
            )
        if not state.retired_second & bit:
            result.append(
                (
                    f"retire:second:p{provider}",
                    State(**{**state.__dict__, "retired_second": state.retired_second | bit}),
                )
            )

    first_ready = (
        state.retired_first != 0 if model.incomplete_barrier else state.retired_first == COMPLETE
    )
    second_ready = (
        state.retired_second != 0
        if model.incomplete_barrier
        else state.retired_second == COMPLETE
    )
    if first_ready and not state.barrier_first:
        result.append(("form:first", State(**{**state.__dict__, "barrier_first": True})))
    if state.barrier_first and second_ready and not state.barrier_second:
        result.append(("form:second", State(**{**state.__dict__, "barrier_second": True})))

    if not state.released_first and (state.barrier_first or model.early_release):
        result.append(("release:first", State(**{**state.__dict__, "released_first": True})))
    if (
        not state.released_second
        and state.released_first
        and (state.barrier_second or model.early_release)
    ):
        result.append(("release:second", State(**{**state.__dict__, "released_second": True})))

    for version in (2, 3):
        version_bit = 1 << version
        if not state.attested_key_versions & version_bit:
            result.append(
                (
                    f"attest:key:v{version}",
                    State(
                        **{
                            **state.__dict__,
                            "attested_key_versions": (
                                state.attested_key_versions | version_bit
                            ),
                        }
                    ),
                )
            )
        if state.trusted_key_version != version and (
            state.attested_key_versions & version_bit or model.blind_key_repair
        ):
            result.append(
                (
                    f"trust:key:v{version}",
                    State(**{**state.__dict__, "trusted_key_version": version}),
                )
            )
    return result


def violations(state: State) -> tuple[str, ...]:
    failures: list[str] = []
    if state.barrier_first and state.retired_first != COMPLETE:
        failures.append("first_barrier_without_complete_retirement")
    if state.barrier_second and (
        not state.barrier_first or state.retired_second != COMPLETE
    ):
        failures.append("second_barrier_without_ordered_complete_retirement")
    if state.released_first and not state.barrier_first:
        failures.append("first_successor_released_without_barrier")
    if state.released_second and not (state.barrier_first and state.barrier_second):
        failures.append("second_successor_released_without_both_barriers")
    if (
        state.trusted_key_version != 1
        and not state.attested_key_versions & (1 << state.trusted_key_version)
    ):
        failures.append("provider_key_trusted_without_matching_attestation")
    return tuple(failures)


def explore(model: Model) -> dict[str, object]:
    initial = State()
    queue = deque([initial])
    traces: dict[State, tuple[str, ...]] = {initial: ()}
    transition_count = 0
    first_failure: tuple[str, tuple[str, ...]] | None = None
    while queue:
        state = queue.popleft()
        state_violations = violations(state)
        if state_violations and first_failure is None:
            first_failure = (";".join(state_violations), traces[state])
        for action, successor in successors(state, model):
            transition_count += 1
            if successor not in traces:
                traces[successor] = (*traces[state], action)
                queue.append(successor)
    return {
        "model": model.name,
        "providers": PROVIDERS,
        "states": len(traces),
        "transitions": transition_count,
        "violations": 0 if first_failure is None else 1,
        "first_violation": "" if first_failure is None else first_failure[0],
        "counterexample": "" if first_failure is None else " -> ".join(first_failure[1]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exhaustively check the bounded authority-transition safety model."
    )
    parser.add_argument("output_csv", type=Path)
    args = parser.parse_args()
    rows = [explore(model) for model in MODELS]
    if rows[0]["violations"] != 0:
        raise AssertionError(f"protocol model violated an invariant: {rows[0]}")
    if any(row["violations"] != 1 for row in rows[1:]):
        raise AssertionError(f"a seeded mutant escaped detection: {rows}")
    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.output_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys(), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
