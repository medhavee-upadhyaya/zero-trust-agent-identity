from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


SEEDS = (104729, 130363, 155921)


@dataclass(frozen=True)
class Experiment:
    experiment_id: str
    runner: str
    summarizers: tuple[tuple[str, str], ...]
    full_trials: int
    smoke_trials: int
    stem: str


EXPERIMENTS = (
    Experiment(
        "E006",
        "run_authorization_attacks.py",
        (("summarize_authorization_attacks.py", "authorization_attack_summary.csv"),),
        4800,
        32,
        "authorization",
    ),
    Experiment(
        "E009B",
        "run_barrier_binding_attacks.py",
        (("summarize_barrier_binding_attacks.py", "barrier_binding_summary.csv"),),
        2200,
        22,
        "barrier_binding",
    ),
    Experiment(
        "E010",
        "run_barrier_baseline_comparison.py",
        (
            ("summarize_barrier_baseline_comparison.py", "barrier_baseline_summary.csv"),
            ("summarize_barrier_baseline_pairs.py", "barrier_baseline_pairwise_summary.csv"),
        ),
        2200,
        22,
        "barrier_baseline",
    ),
    Experiment(
        "E011",
        "run_networked_authority_faults.py",
        (("summarize_networked_authority_faults.py", "networked_authority_summary.csv"),),
        550,
        22,
        "networked_authority",
    ),
    Experiment(
        "E012",
        "run_self_healing_faults.py",
        (("summarize_self_healing_faults.py", "self_healing_summary.csv"),),
        420,
        28,
        "self_healing",
    ),
    Experiment(
        "E013",
        "run_self_healing_ablation.py",
        (
            ("summarize_self_healing_ablation.py", "self_healing_ablation_summary.csv"),
            (
                "summarize_self_healing_ablation_pairs.py",
                "self_healing_ablation_pairwise_summary.csv",
            ),
        ),
        280,
        28,
        "self_healing_ablation",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reproduce the manuscript's principal authorization and recovery tables."
    )
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--smoke", action="store_true", help="run a small pipeline check")
    parser.add_argument("--skip-tests", action="store_true")
    return parser.parse_args()


def execute(command: list[str], *, root: Path, log: Path) -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root / "src")
    result = subprocess.run(
        command,
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    log.write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"command failed with status {result.returncode}; see {log}")


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def source_revision(root: Path) -> tuple[str, bool | None]:
    git = shutil.which("git")
    if git is None or not (root / ".git").exists():
        return os.environ.get("ZTAI_SOURCE_REVISION", "unavailable"), None
    revision = subprocess.run(
        [git, "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=False
    )
    dirty = subprocess.run(
        [git, "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return revision.stdout.strip(), bool(dirty.stdout.strip())


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_directory.resolve()
    output.mkdir(parents=True, exist_ok=False)
    logs = output / "logs"
    runs = output / "runs"
    logs.mkdir()
    runs.mkdir()

    if not args.skip_tests:
        execute(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            root=root,
            log=logs / "unit_tests.log",
        )

    summaries: list[Path] = []
    for experiment in EXPERIMENTS:
        inputs: list[Path] = []
        trials = experiment.smoke_trials if args.smoke else experiment.full_trials
        for seed in SEEDS:
            destination = runs / f"{experiment.stem}_seed_{seed}.csv"
            execute(
                [
                    sys.executable,
                    str(root / "experiments" / experiment.runner),
                    str(seed),
                    str(trials),
                    str(destination),
                ],
                root=root,
                log=logs / f"{experiment.experiment_id}_seed_{seed}.log",
            )
            inputs.append(destination)
        for summarizer, summary_name in experiment.summarizers:
            summary = output / summary_name
            execute(
                [
                    sys.executable,
                    str(root / "experiments" / summarizer),
                    str(summary),
                    *(str(path) for path in inputs),
                ],
                root=root,
                log=logs / f"{experiment.experiment_id}_{Path(summarizer).stem}.log",
            )
            summaries.append(summary)

    model_summary = output / "authority_transition_model_summary.csv"
    execute(
        [
            sys.executable,
            str(root / "experiments" / "check_authority_transition_model.py"),
            str(model_summary),
        ],
        root=root,
        log=logs / "E020_model_check.log",
    )
    summaries.append(model_summary)

    revision, dirty = source_revision(root)
    files = sorted(path for path in output.rglob("*") if path.is_file())
    manifest = {
        "schema_version": 1,
        "suite": "principal_tables",
        "profile": "smoke" if args.smoke else "full",
        "git_commit": revision,
        "git_dirty": dirty,
        "python": sys.version,
        "platform": platform.platform(),
        "seeds": list(SEEDS),
        "files": {str(path.relative_to(output)): sha256(path) for path in files},
        "summaries": [str(path.relative_to(output)) for path in summaries],
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
