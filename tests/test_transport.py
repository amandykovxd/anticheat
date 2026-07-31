#!/usr/bin/env python3
"""Protocol and persistence tests for issue #14 remote anchoring."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import threading
import unittest
from http import HTTPStatus
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from reference_receiver import (  # noqa: E402
    ReceiverError,
    ReceiverHttpServer,
    ReceiverStore,
)
from telemetry_shipper import (  # noqa: E402
    ReceiverClient,
    RemoteRejectedError,
    SpoolLimitError,
    TelemetryShipper,
    TransportSpool,
)
from transport_common import (  # noqa: E402
    PROTOCOL_VERSION,
    ProtocolError,
    chain_seed_from_open_record,
    verify_record,
)


def make_record(
    sequence: int,
    event: str,
    details: dict[str, Any],
    previous_chain: str,
) -> tuple[bytes, str]:
    body = (
        f'{{"seq":{sequence},"timestamp":"2026-07-31T00:00:00.000Z",'
        f'"severity":"info","event":"{event}","pid":0,"details":'
        + json.dumps(details, sort_keys=True, separators=(",", ":"))
    ).encode("utf-8")
    chain = hashlib.sha256(bytes.fromhex(previous_chain) + body).hexdigest()
    return body + f',"chain":"{chain}"}}'.encode("ascii"), chain


def make_session_records(count: int = 4, seed_byte: int = 0x42) -> tuple[str, list[bytes]]:
    seed = bytes([seed_byte]) * 32
    seed_hex = seed.hex()
    records: list[bytes] = []
    chain = seed_hex
    first, chain = make_record(
        1,
        "log_segment_opened",
        {"schema": 4, "chain_seed": seed_hex},
        chain,
    )
    records.append(first)
    for sequence in range(2, count + 1):
        record, chain = make_record(
            sequence, "scan_completed", {"scan_id": sequence - 1}, chain
        )
        records.append(record)
    return seed_hex, records


def session_request(seed: str, client_session_id: str = "a" * 32) -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "client_session_id": client_session_id,
        "collector_id": "test-endpoint",
        "schema_version": 4,
        "chain_algorithm": "sha256",
        "chain_seed": seed,
    }


def batch_request(
    seed: str, records: list[bytes], batch_sequence: int = 1
) -> dict[str, Any]:
    return {
        "batch_seq": batch_sequence,
        "first_event_seq": int(json.loads(records[0])["seq"]),
        "last_event_seq": int(json.loads(records[-1])["seq"]),
        "previous_chain": seed,
        "chain_head": str(json.loads(records[-1])["chain"]),
        "records": [record.decode("utf-8") for record in records],
    }


class DirectStoreClient:
    def __init__(self, store: ReceiverStore):
        self.store = store

    def request(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if path == "/v1/sessions":
            _, response = self.store.create_session(payload)
            return response
        session_id = path.split("/")[3]
        if path.endswith("/batches"):
            _, response = self.store.append_batch(session_id, payload)
            return response
        if path.endswith("/heartbeat"):
            _, response = self.store.append_heartbeat(session_id, payload)
            return response
        raise AssertionError(f"unexpected path {path}")


class RecordVerificationTests(unittest.TestCase):
    def test_open_record_exposes_seed_and_verifies(self) -> None:
        seed, records = make_session_records(1)
        self.assertEqual(chain_seed_from_open_record(records[0], 4), seed)
        verified = verify_record(records[0], seed, 1)
        self.assertEqual(verified.sequence, 1)
        self.assertEqual(verified.event, "log_segment_opened")

    def test_modified_record_is_rejected(self) -> None:
        seed, records = make_session_records(1)
        modified = records[0].replace(b'"schema":4', b'"schema":5')
        with self.assertRaisesRegex(ProtocolError, "chain mismatch"):
            verify_record(modified, seed, 1)

    def test_missing_event_sequence_is_rejected(self) -> None:
        seed, records = make_session_records(2)
        first = verify_record(records[0], seed, 1)
        with self.assertRaisesRegex(ProtocolError, "sequence mismatch"):
            verify_record(records[1], first.chain, 3)


class ReceiverStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = ReceiverStore(Path(self.temporary.name) / "receiver.sqlite3")
        self.seed, self.records = make_session_records(4)
        status, response = self.store.create_session(session_request(self.seed))
        self.assertEqual(status, HTTPStatus.CREATED)
        self.session_id = response["session_id"]

    def test_session_registration_is_idempotent(self) -> None:
        status, response = self.store.create_session(session_request(self.seed))
        self.assertEqual(status, HTTPStatus.OK)
        self.assertTrue(response["duplicate"])
        self.assertEqual(response["session_id"], self.session_id)

    def test_session_idempotency_key_cannot_change_metadata(self) -> None:
        request = session_request(self.seed)
        request["collector_id"] = "different-endpoint"
        with self.assertRaises(ReceiverError) as captured:
            self.store.create_session(request)
        self.assertEqual(captured.exception.status, HTTPStatus.CONFLICT)

    def test_batch_is_verified_and_duplicate_is_idempotent(self) -> None:
        request = batch_request(self.seed, self.records)
        status, response = self.store.append_batch(self.session_id, request)
        self.assertEqual(status, HTTPStatus.ACCEPTED)
        self.assertFalse(response["duplicate"])

        status, response = self.store.append_batch(self.session_id, request)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertTrue(response["duplicate"])
        self.assertEqual(response["chain_head"], request["chain_head"])

    def test_duplicate_batch_with_changed_content_is_rejected(self) -> None:
        request = batch_request(self.seed, self.records)
        self.store.append_batch(self.session_id, request)
        changed = dict(request)
        changed["records"] = list(request["records"])
        changed["records"][-1] = changed["records"][-1].replace("scan_id", "scan_ix")
        with self.assertRaises(ReceiverError) as captured:
            self.store.append_batch(self.session_id, changed)
        self.assertEqual(captured.exception.code, "batch_idempotency_conflict")

    def test_reordered_batch_is_rejected(self) -> None:
        request = batch_request(self.seed, self.records, batch_sequence=2)
        with self.assertRaises(ReceiverError) as captured:
            self.store.append_batch(self.session_id, request)
        self.assertEqual(captured.exception.code, "batch_sequence_gap")

    def test_tampered_record_is_rejected(self) -> None:
        request = batch_request(self.seed, self.records)
        request["records"] = list(request["records"])
        request["records"][1] = request["records"][1].replace("scan_id", "scan_ix")
        with self.assertRaises(ReceiverError) as captured:
            self.store.append_batch(self.session_id, request)
        self.assertEqual(captured.exception.code, "event_chain_invalid")

    def test_wrong_previous_anchor_is_rejected(self) -> None:
        request = batch_request(self.seed, self.records)
        request["previous_chain"] = (b"wrong anchor".ljust(32, b"!")).hex()
        with self.assertRaises(ReceiverError) as captured:
            self.store.append_batch(self.session_id, request)
        self.assertEqual(captured.exception.code, "anchor_mismatch")

    def test_heartbeat_anchors_current_remote_head(self) -> None:
        request = batch_request(self.seed, self.records)
        self.store.append_batch(self.session_id, request)
        heartbeat = {
            "heartbeat_seq": 1,
            "last_batch_seq": 1,
            "last_event_seq": 4,
            "chain_head": request["chain_head"],
        }
        status, response = self.store.append_heartbeat(self.session_id, heartbeat)
        self.assertEqual(status, HTTPStatus.ACCEPTED)
        self.assertFalse(response["duplicate"])
        status, response = self.store.append_heartbeat(self.session_id, heartbeat)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertTrue(response["duplicate"])

    def test_heartbeat_with_stale_anchor_is_rejected(self) -> None:
        request = batch_request(self.seed, self.records)
        self.store.append_batch(self.session_id, request)
        heartbeat = {
            "heartbeat_seq": 1,
            "last_batch_seq": 0,
            "last_event_seq": 0,
            "chain_head": self.seed,
        }
        with self.assertRaises(ReceiverError) as captured:
            self.store.append_heartbeat(self.session_id, heartbeat)
        self.assertEqual(captured.exception.code, "heartbeat_anchor_mismatch")


class SpoolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.log = self.directory / "events.jsonl"
        self.database = self.directory / "spool.sqlite3"

    def _write_records(self, records: list[bytes]) -> None:
        self.log.write_bytes(b"\n".join(records) + b"\n")

    def test_spool_batches_and_preserves_exact_records(self) -> None:
        _, records = make_session_records(5)
        self._write_records(records)
        spool = TransportSpool(self.database, self.log, "collector", 1024 * 1024, 3600)
        result = spool.ingest_available(batch_records=2, batch_bytes=64 * 1024)
        self.assertEqual(result.records, 5)
        self.assertEqual(result.batches, 3)
        self.assertEqual(spool.pending_count(), 3)
        first = spool.next_pending_batch()
        self.assertIsNone(first)  # registration is required before delivery

    def test_spool_limit_pauses_without_advancing_cursor(self) -> None:
        _, records = make_session_records(3)
        self._write_records(records)
        spool = TransportSpool(self.database, self.log, "collector", 128, 3600)
        with self.assertRaises(SpoolLimitError):
            spool.ingest_available(batch_records=3, batch_bytes=64 * 1024)
        self.assertEqual(spool.pending_count(), 0)

        resumed = TransportSpool(
            self.database, self.log, "collector", 1024 * 1024, 3600
        )
        result = resumed.ingest_available(batch_records=3, batch_bytes=64 * 1024)
        self.assertEqual(result.records, 3)

    def test_log_rotation_continues_the_same_chain(self) -> None:
        _, records = make_session_records(4)
        self._write_records(records[:2])
        spool = TransportSpool(self.database, self.log, "collector", 1024 * 1024, 3600)
        first = spool.ingest_available(batch_records=8, batch_bytes=64 * 1024)
        self.assertEqual(first.records, 2)

        self.log.rename(Path(f"{self.log}.1"))
        self._write_records(records[2:])
        second = spool.ingest_available(batch_records=8, batch_bytes=64 * 1024)
        self.assertEqual(second.records, 2)

    def test_appended_collector_restart_creates_a_new_session(self) -> None:
        _, first = make_session_records(2, 0x11)
        _, second = make_session_records(2, 0x22)
        self._write_records(first + second)
        spool = TransportSpool(self.database, self.log, "collector", 1024 * 1024, 3600)
        result = spool.ingest_available(batch_records=8, batch_bytes=64 * 1024)
        self.assertEqual(result.records, 4)
        self.assertEqual(len(spool.unregistered_sessions()), 2)

    def test_end_to_end_delivery_clears_spool_and_sends_heartbeat(self) -> None:
        _, records = make_session_records(5)
        self._write_records(records)
        spool = TransportSpool(self.database, self.log, "collector", 1024 * 1024, 3600)
        spool.ingest_available(batch_records=2, batch_bytes=64 * 1024)
        receiver = ReceiverStore(self.directory / "receiver.sqlite3")
        shipper = TelemetryShipper(spool, DirectStoreClient(receiver))

        registered, delivered, heartbeat = shipper.flush(heartbeat=True)
        self.assertEqual(registered, 1)
        self.assertEqual(delivered, 3)
        self.assertTrue(heartbeat)
        self.assertEqual(spool.pending_count(), 0)

        session = spool.heartbeat_candidate(force=True)
        self.assertIsNotNone(session)
        assert session is not None
        remote = receiver.session_status(session["server_session_id"])
        self.assertEqual(remote["last_batch_seq"], 3)
        self.assertEqual(remote["last_event_seq"], 5)
        self.assertEqual(remote["last_heartbeat_seq"], 1)
        self.assertEqual(remote["chain_head"], session["acknowledged_chain_head"])

    def test_delivery_recovers_from_size_backpressure(self) -> None:
        _, records = make_session_records(8)
        self._write_records(records)
        spool = TransportSpool(self.database, self.log, "collector", 900, 3600)
        receiver = ReceiverStore(self.directory / "receiver.sqlite3")
        shipper = TelemetryShipper(spool, DirectStoreClient(receiver))
        observed_backpressure = False
        reached_end = False

        for _ in range(10):
            try:
                result = spool.ingest_available(
                    batch_records=2, batch_bytes=64 * 1024
                )
                reached_end = result.at_end
            except SpoolLimitError:
                observed_backpressure = True
            shipper.flush(heartbeat=False)
            if reached_end and spool.pending_count() == 0:
                break

        self.assertTrue(observed_backpressure)
        self.assertTrue(reached_end)
        session = spool.heartbeat_candidate(force=True)
        self.assertIsNotNone(session)
        assert session is not None
        remote = receiver.session_status(session["server_session_id"])
        self.assertEqual(remote["last_event_seq"], 8)


class HttpAuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        store = ReceiverStore(Path(self.temporary.name) / "receiver.sqlite3")
        self.server = ReceiverHttpServer(("127.0.0.1", 0), store, "t" * 32)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.seed, _ = make_session_records(1)

    def _stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_authenticated_http_request_reaches_reference_receiver(self) -> None:
        client = ReceiverClient(
            self.endpoint, "t" * 32, allow_insecure_http=True
        )
        response = client.request("/v1/sessions", session_request(self.seed))
        self.assertEqual(len(response["session_id"]), 32)

    def test_invalid_bearer_token_is_rejected(self) -> None:
        client = ReceiverClient(
            self.endpoint, "x" * 32, allow_insecure_http=True
        )
        with self.assertRaises(RemoteRejectedError) as captured:
            client.request("/v1/sessions", session_request(self.seed))
        self.assertEqual(captured.exception.status, HTTPStatus.UNAUTHORIZED)

    def test_plain_http_requires_explicit_development_override(self) -> None:
        with self.assertRaisesRegex(Exception, "must use HTTPS"):
            ReceiverClient(self.endpoint, "t" * 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
