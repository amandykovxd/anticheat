---
layout: default
title: Authenticated Transport Integration
---

# Authenticated transport integration

## Components

`telemetry_shipper.py` is a process-isolated delivery sidecar. It tails the
collector JSONL stream, verifies every local chain transition, writes immutable
batches to a bounded SQLite spool, and sends them to an authenticated receiver.
Network operations never execute in the collector or kernel callback path.

`reference_receiver.py` supplies the protocol reference implementation. It
assigns server session identifiers, accepts batches idempotently, independently
recomputes the chain, persists remote anchors, and records heartbeat state.
Production integrations may replace the receiver while preserving the protocol
and validation contract below.

## Security configuration

Production endpoints must use HTTPS. The shipper validates the receiver
certificate with the operating-system trust store or `--ca-file`. Optional
mutual TLS is enabled with `--client-cert` and `--client-key`; the receiver
requires client certificates when started with `--client-ca`.

Every request also carries a bearer credential from `AC_RECEIVER_TOKEN` by
default. The value must contain at least 32 characters. Supply credentials
through the process environment or a service secret manager. Do not place
tokens, private keys, or production certificates in command lines, repository
files, logs, or CI configuration.

Plain HTTP is rejected unless both components are explicitly started with
`--allow-insecure-http`. That option is limited to loopback integration tests.

## Receiver deployment

Create a database directory writable only by the receiver service account and
start the service with its certificate chain and private key:

```text
AC_RECEIVER_TOKEN=<service-secret>
python tools/reference_receiver.py \
  --listen 0.0.0.0 \
  --port 8443 \
  --database /var/lib/anticheat/anchors.sqlite3 \
  --cert /etc/anticheat/tls/server-chain.pem \
  --key /etc/anticheat/tls/server-key.pem \
  --client-ca /etc/anticheat/tls/client-ca.pem \
  --heartbeat-ms 15000 \
  --trusted-collector launcher-node-017:<collector-file-sha256>:<mapped-image-sha256>:0.4.0:<collector-build-sha256>
```

Obtain the two trusted digests from the exact signed release binary on a clean
Windows build host with `anticheat.exe --print-attestation-digest`. Register
them through protected receiver configuration, not endpoint storage.

Before launching the collector, request a fresh challenge:

```text
python tools/request_attestation_challenge.py \
  --endpoint https://telemetry.example.internal:8443 \
  --collector-id launcher-node-017 \
  --ca-file /etc/anticheat/receiver-ca.pem
```

Pass the returned `challenge_id`, `nonce`, and reserved `session_id` to
`--attestation-challenge`, `--attestation-nonce`, `--attestation-session`, and
`--require-attestation`. The nonce is not written to the event stream; the
collector logs its digest and a domain-separated response over the challenge,
nonce, reserved server session, semantic version, immutable build digest, file
digest, and normalized mapped-image digest. The shipper extracts the reserved
session from the chained attestation event and uses it during registration.

The unauthenticated `GET /healthz` endpoint reports process availability. All
session endpoints require the bearer credential. Place the service behind
network rate limits and a production reverse proxy when exposed outside a
private service network. Back up the SQLite database to append-only or
object-locked storage; local database access by itself is not an append-only
security boundary.

## Shipper deployment

Start the collector with bounded local rotation, then start one shipper for the
same active JSONL path:

```powershell
$env:AC_RECEIVER_TOKEN = '<service-secret>'

python tools\telemetry_shipper.py `
  --log C:\ProgramData\Anticheat\events.jsonl `
  --spool C:\ProgramData\Anticheat\transport.sqlite3 `
  --endpoint https://telemetry.example.internal:8443 `
  --collector-id launcher-node-017 `
  --ca-file C:\ProgramData\Anticheat\receiver-ca.pem `
  --client-cert C:\ProgramData\Anticheat\client-cert.pem `
  --client-key C:\ProgramData\Anticheat\client-key.pem `
  --max-spool-bytes 67108864 `
  --max-spool-age-seconds 86400
```

`--collector-id` is an integrator-assigned stable deployment identity. It is
not an authentication credential. Bind its permitted value to the bearer or
client-certificate identity in production authorization policy.

Run `--once` to ingest the currently retained records, flush all available
batches, send one heartbeat, and exit. Continuous mode polls for new records
and retries transient transport failures with bounded exponential backoff.

## Protocol

Protocol version 1 uses JSON requests and responses. Batch `records` are JSON
strings containing the exact UTF-8 record bytes without the line terminator.
The receiver must not reconstruct or normalize these records before chain
verification.

| Method and path | Function |
| --- | --- |
| `POST /v1/attestations/challenges` | Issue a short-lived one-time nonce for a registered collector identity. |
| `POST /v1/sessions` | Idempotently register a client session and return a server session ID. |
| `POST /v1/sessions/{id}/batches` | Verify and anchor the next ordered event batch. |
| `POST /v1/sessions/{id}/heartbeat` | Confirm liveness and the latest accepted remote anchor. |
| `GET /v1/sessions/{id}` | Return authenticated session state for operations. |
| `GET /healthz` | Return receiver process health. |

For configured trusted collectors, the receiver validates
`collector_attestation_observed` inside the authenticated hash chain, consumes
the challenge for exactly one server session, and rejects heartbeat until the
attestation is anchored. A response containing a different release digest,
mapped image, nonce, or session replay is rejected.

Session registration includes:

- `protocol_version`;
- idempotency key `client_session_id`;
- deployment `collector_id`;
- event `schema_version`;
- `chain_algorithm` set to `sha256`;
- `chain_seed` extracted from `log_segment_opened`.

The receiver returns `session_id`, `next_batch_seq`, `next_event_seq`, the
current `chain_head`, and `heartbeat_interval_ms`. Reusing a
`client_session_id` with changed immutable metadata returns HTTP 409.

Each batch includes:

- monotonically increasing `batch_seq`;
- `first_event_seq` and `last_event_seq`;
- previously acknowledged `previous_chain`;
- claimed final `chain_head`;
- one or more exact `records`.

The receiver accepts only the next batch and event sequence. It recalculates
every transition as:

```text
chain[i] = SHA256(chain[i-1] || exact_record_body[i])
```

Replaying identical content under the same batch sequence is successful and
returns `duplicate: true`. Reusing the sequence with different content,
skipping or reordering a sequence, changing a retained record, or supplying a
wrong anchor returns a permanent 4xx response.

A heartbeat contains its own monotonic sequence plus the last acknowledged
batch sequence, event sequence, and chain head. The receiver rejects a
heartbeat that does not exactly match remotely retained state. Operations
should alert after two negotiated heartbeat intervals without a successful
heartbeat and retain the last remote anchor for investigation.

## Spool and backpressure policy

The spool tracks source file identity and byte offset and follows retained
collector rotations by file identity. A rotated file that disappears before
ingestion is reported as a permanent source gap.

Unacknowledged batches are never silently evicted. When `--max-spool-bytes` is
reached or the oldest batch exceeds `--max-spool-age-seconds`, ingestion stops
before advancing the source cursor. Delivery continues to be retried and the
collector remains independent. This fail-closed backpressure policy preserves
the evidence already retained and makes coverage loss observable instead of
creating a valid-looking truncated session.

Size limits describe the logical queued payload. Provision additional disk for
SQLite pages, its WAL, collector JSONL generations, and operating-system
overhead. Monitor free space independently.

## Failure handling

The shipper uses these exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Requested delivery cycle completed. |
| `2` | Configuration or credential error. |
| `3` | `--once` encountered a transient transport failure. |
| `4` | Receiver permanently rejected protocol content. |
| `5` | Chain, source continuity, spool, or local state failure. |

HTTP 4xx responses are permanent and require configuration or evidence
investigation. Connection failures, timeouts, and HTTP 5xx responses are
transient. Do not automatically reset the spool or create a replacement
session after a permanent chain or sequence failure.

## Verification

Run the transport suite directly:

```text
python -m unittest -v tests/test_transport.py
```

The suite verifies authentication, idempotent registration and batches,
sequence-gap detection, record tamper detection, anchor validation, heartbeat
state, log rotation, collector restart handling, spool limits, and end-to-end
delivery into the reference receiver.
