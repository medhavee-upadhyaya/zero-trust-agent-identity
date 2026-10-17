from __future__ import annotations

import argparse
import hashlib
import json
import time
import uuid
from pathlib import Path

from ztai import (
    AzureBlobStorageAdapter,
    GoogleCloudStorageAdapter,
    GoogleFederationClient,
    GoogleWorkloadFederationConfig,
    MicrosoftEntraFederationConfig,
    MicrosoftFederationClient,
    UrllibTransport,
)


CONFIRMATION = "CONFIRM_SANDBOX_CLOUD_WRITE"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Exchange a JWT-SVID with a real cloud identity service and write one "
            "non-secret canary object to an author-controlled sandbox resource."
        )
    )
    result.add_argument("--provider", choices=("google", "microsoft"), required=True)
    result.add_argument("--jwt-svid-file", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--confirm-live-write", required=True)
    result.add_argument("--project-number")
    result.add_argument("--pool-id")
    result.add_argument("--provider-id")
    result.add_argument("--bucket")
    result.add_argument("--tenant-id")
    result.add_argument("--client-id")
    result.add_argument("--storage-account")
    result.add_argument("--container")
    result.add_argument("--timeout", type=float, default=15.0)
    return result


def require(value: str | None, name: str) -> str:
    if not value:
        raise ValueError(f"{name} is required for the selected provider")
    return value


def main() -> int:
    args = parser().parse_args()
    if args.confirm_live_write != CONFIRMATION:
        raise PermissionError(
            f"live execution requires --confirm-live-write {CONFIRMATION}"
        )
    jwt_svid = args.jwt_svid_file.read_text(encoding="utf-8").strip()
    if not jwt_svid or jwt_svid.count(".") != 2:
        raise ValueError("jwt-svid-file does not contain one compact JWT")
    run_id = f"live-cloud-{uuid.uuid4()}"
    object_name = f"ztai-artifact-evaluation/{run_id}.json"
    canary = json.dumps(
        {
            "run_id": run_id,
            "purpose": "zero-trust-agent-identity artifact evaluation",
            "contains_secret": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    transport = UrllibTransport()
    started = time.perf_counter_ns()
    if args.provider == "google":
        config = GoogleWorkloadFederationConfig(
            require(args.project_number, "--project-number"),
            require(args.pool_id, "--pool-id"),
            require(args.provider_id, "--provider-id"),
        )
        token = GoogleFederationClient(transport, timeout=args.timeout).exchange(
            config, jwt_svid
        )
        exchanged = time.perf_counter_ns()
        effect = GoogleCloudStorageAdapter(transport, timeout=args.timeout).put_object(
            token=token,
            bucket=require(args.bucket, "--bucket"),
            object_name=object_name,
            payload=canary,
            allow_live_effect=True,
        )
    else:
        config = MicrosoftEntraFederationConfig(
            require(args.tenant_id, "--tenant-id"),
            require(args.client_id, "--client-id"),
            "https://storage.azure.com/.default",
        )
        token = MicrosoftFederationClient(transport, timeout=args.timeout).exchange(
            config, jwt_svid
        )
        exchanged = time.perf_counter_ns()
        effect = AzureBlobStorageAdapter(transport, timeout=args.timeout).put_blob(
            token=token,
            account=require(args.storage_account, "--storage-account"),
            container=require(args.container, "--container"),
            blob_name=object_name,
            payload=canary,
            allow_live_effect=True,
        )
    finished = time.perf_counter_ns()
    record = {
        "schema_version": 1,
        "run_id": run_id,
        "provider": args.provider,
        "execution_mode": "live_cloud_sandbox",
        "resource": effect.resource,
        "http_status": effect.status,
        "committed": effect.committed,
        "payload_sha256": hashlib.sha256(canary).hexdigest(),
        "cloud_request_id": effect.response_request_id,
        "token_type": token.token_type,
        "token_expires_in_seconds": token.expires_in,
        "token_exchange_latency_ns": exchanged - started,
        "effect_latency_ns": finished - exchanged,
        "total_latency_ns": finished - started,
        "jwt_svid_sha256": hashlib.sha256(jwt_svid.encode()).hexdigest(),
        "secrets_logged": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return 0 if effect.committed else 1


if __name__ == "__main__":
    raise SystemExit(main())
