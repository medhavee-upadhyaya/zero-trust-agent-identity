from __future__ import annotations

import argparse
import hashlib
import shutil
import tempfile
import zipfile
from pathlib import Path


VERSION = "1.2.0"
RAW_PATTERNS = ("*.csv", "live_cloud_*.json")
METADATA_NAMES = (
    "authorization_attack_summary.csv",
    "authority_transition_model_summary.csv",
    "barrier_baseline_pairwise_summary.csv",
    "barrier_baseline_summary.csv",
    "barrier_binding_summary.csv",
    "baseline_summary.csv",
    "container_authority_summary.csv",
    "critical_infrastructure_summary.csv",
    "cross_organization_summary.csv",
    "distributed_authority_summary.csv",
    "environment.csv",
    "experiment_registry.csv",
    "federated_identity_summary.csv",
    "live_cloud_attempt_log.csv",
    "live_cloud_summary.csv",
    "networked_authority_summary.csv",
    "provider_fault_summary.csv",
    "results_summary.csv",
    "revocation_key_summary.csv",
    "secure_workflow_attack_summary.csv",
    "self_healing_ablation_pairwise_summary.csv",
    "self_healing_ablation_summary.csv",
    "self_healing_summary.csv",
    "standards_conformance.csv",
    "workflow_fault_summary.csv",
)


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def copy_required(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def archive_text() -> str:
    return f"""ZERO-TRUST AGENT IDENTITY EXPERIMENTAL ARTIFACT v{VERSION}

This archive contains the raw local experiment traces retained by the authors,
the versioned aggregate summaries, the bounded authority-transition model
result, the evidence-traceable literature matrix and screening log, and the
repository's execution instructions.

RUN.txt describes the one-command principal-table reproduction path. Raw files
are deterministic conditional on their recorded seeds and the implementation,
except for operating-system scheduling and latency. Latencies from different
machines must not be pooled as one performance population.

The archive does not constitute independent reproduction. E016 live-cloud
records contain only non-secret identifiers, hashes, status codes, and timing;
no JWT-SVID, cloud bearer token, private key, or cloud credential is included.

Verify integrity with SHA256SUMS.txt before using any result.
"""


def write_zip(tree: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(tree.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(tree.parent)
            info = zipfile.ZipInfo(str(relative), date_time=(2026, 10, 28, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the public experimental artifact ZIP.")
    parser.add_argument("output_zip", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="ztai-artifact-") as temporary:
        tree = Path(temporary) / f"ztai-artifact-v{VERSION}"
        raw = tree / "raw"
        metadata = tree / "metadata"
        raw.mkdir(parents=True)
        metadata.mkdir()

        for name in ("LICENSE", "RUN.txt", "requirements.lock"):
            copy_required(root / name, tree / name)
        for name in METADATA_NAMES:
            copy_required(root / "experiments" / name, metadata / name)
        copy_required(
            root / "journal" / "literature_matrix.csv",
            metadata / "literature_matrix.csv",
        )
        copy_required(
            root / "journal" / "literature_screening.csv",
            metadata / "literature_screening.csv",
        )
        for pattern in RAW_PATTERNS:
            for source in sorted((root / "experiments" / "runs").glob(pattern)):
                copy_required(source, raw / source.name)

        (tree / "ARTIFACT_README.txt").write_text(archive_text(), encoding="utf-8")
        entries = sorted(
            path for path in tree.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt"
        )
        checksum_lines = [
            f"{sha256(path)}  {path.relative_to(tree)}" for path in entries
        ]
        (tree / "SHA256SUMS.txt").write_text(
            "\n".join(checksum_lines) + "\n", encoding="utf-8"
        )
        write_zip(tree, args.output_zip.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
