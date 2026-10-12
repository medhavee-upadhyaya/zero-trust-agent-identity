from __future__ import annotations

import argparse
import base64
from http.server import ThreadingHTTPServer

from ztai import Ed25519Signer, ProviderDatabase
from ztai.provider import _make_handler


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Container entry point for the E014 isolated-provider experiment."
    )
    parser.add_argument("--database", required=True)
    parser.add_argument("--provider-id", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--transition-signer-id", required=True)
    parser.add_argument("--transition-public-key", required=True)
    parser.add_argument("--barrier-signer-id", required=True)
    parser.add_argument("--barrier-public-key", required=True)
    parser.add_argument("--initial-workload", required=True)
    parser.add_argument("--initial-epoch", required=True, type=int)
    parser.add_argument("--initial-changed-at", required=True, type=int)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    arguments = parser.parse_args()

    signer = Ed25519Signer.from_private_bytes(
        arguments.provider_id,
        decode(arguments.private_key),
    )
    database = ProviderDatabase(arguments.database)
    current_epoch = database.active_epoch(arguments.initial_workload)
    if current_epoch is None:
        database.establish_epoch(
            arguments.initial_workload,
            arguments.initial_epoch,
            arguments.initial_changed_at,
        )
    handler = _make_handler(
        arguments.database,
        arguments.provider_id,
        signer,
        True,
        {arguments.transition_signer_id: decode(arguments.transition_public_key)},
        {arguments.barrier_signer_id: decode(arguments.barrier_public_key)},
    )
    server = ThreadingHTTPServer((arguments.host, arguments.port), handler)
    server.serve_forever(poll_interval=0.05)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
