#!/usr/bin/env python3
"""Request a one-time collector attestation challenge from the receiver."""

from __future__ import annotations

import argparse
import json
import os
import sys

from telemetry_shipper import ReceiverClient


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--collector-id", required=True)
    parser.add_argument("--token-env", default="AC_RECEIVER_TOKEN")
    parser.add_argument("--ca-file")
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")
    parser.add_argument("--allow-insecure-http", action="store_true")
    arguments = parser.parse_args()

    token = os.environ.get(arguments.token_env, "")
    if len(token) < 32:
        print(
            f"{arguments.token_env} must contain at least 32 characters",
            file=sys.stderr,
        )
        return 2
    client = ReceiverClient(
        arguments.endpoint,
        token,
        ca_file=arguments.ca_file,
        client_cert=arguments.client_cert,
        client_key=arguments.client_key,
        allow_insecure_http=arguments.allow_insecure_http,
    )
    challenge = client.request(
        "/v1/attestations/challenges",
        {"collector_id": arguments.collector_id},
    )
    print(json.dumps(challenge, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
