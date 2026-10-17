from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


SEEDS = (104729, 130363, 155921)
EXPERIMENTS = (
    (
        "E015",
        "run_federated_identity_attacks.py",
        "summarize_federated_identity_attacks.py",
        "federated_identity",
    ),
    (
        "E017",
        "run_critical_infrastructure_case.py",
        "summarize_critical_infrastructure_case.py",
        "critical_infrastructure",
    ),
    (
        "E018",
        "run_cross_organization_delegation.py",
        "summarize_cross_organization_delegation.py",
        "cross_organization",
    ),
)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the offline standards, digital-twin, and delegation suite."
    )
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--cycles", type=int, default=100)
    parser.add_argument("--skip-tests", action="store_true")
    return parser.parse_args()


def run(command: list[str], *, root: Path, log: Path) -> None:
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


def git_revision(root: Path) -> tuple[str, bool | None]:
    git = shutil.which("git")
    if git is None or not (root / ".git").exists():
        return os.environ.get("ZTAI_SOURCE_REVISION", "unavailable"), None
    revision = subprocess.run(
        [git, "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
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
    args = arguments()
    if args.cycles < 1:
        raise ValueError("cycles must be positive")
    root = Path(__file__).resolve().parents[1]
    output = args.output_directory.resolve()
    output.mkdir(parents=True, exist_ok=False)
    logs = output / "logs"
    runs = output / "runs"
    logs.mkdir()
    runs.mkdir()
    if not args.skip_tests:
        run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            root=root,
            log=logs / "unit_tests.log",
        )

    summaries: list[Path] = []
    for experiment_id, runner, summarizer, stem in EXPERIMENTS:
        inputs: list[Path] = []
        for seed in SEEDS:
            destination = runs / f"{stem}_seed_{seed}.csv"
            run(
                [
                    sys.executable,
                    str(root / "experiments" / runner),
                    str(seed),
                    str(args.cycles),
                    str(destination),
                ],
                root=root,
                log=logs / f"{experiment_id}_seed_{seed}.log",
            )
            inputs.append(destination)
        summary = output / f"{stem}_summary.csv"
        run(
            [
                sys.executable,
                str(root / "experiments" / summarizer),
                str(summary),
                *(str(path) for path in inputs),
            ],
            root=root,
            log=logs / f"{experiment_id}_summary.log",
        )
        summaries.append(summary)

    revision, dirty = git_revision(root)
    files = sorted(path for path in output.rglob("*") if path.is_file())
    manifest = {
        "schema_version": 1,
        "git_commit": revision,
        "git_dirty": dirty,
        "python": sys.version,
        "platform": platform.platform(),
        "cycles_per_scenario_per_seed": args.cycles,
        "seeds": list(SEEDS),
        "live_cloud_executed": False,
        "external_validation_completed": False,
        "files": {
            str(path.relative_to(output)): sha256(path)
            for path in files
        },
        "summaries": [str(path.relative_to(output)) for path in summaries],
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
