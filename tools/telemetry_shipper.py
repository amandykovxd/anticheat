#!/usr/bin/env python3
"""Non-blocking sidecar for authenticated telemetry delivery and anchoring."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from transport_common import (
    CHAIN_ALGORITHM,
    PROTOCOL_VERSION,
    ProtocolError,
    canonical_json,
    chain_seed_from_open_record,
    decode_record,
    require_integer,
    require_sha256,
    require_string,
    verify_record,
)


DEFAULT_MAX_SPOOL_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_SPOOL_AGE_SECONDS = 24 * 60 * 60
DEFAULT_BATCH_RECORDS = 128
DEFAULT_BATCH_BYTES = 1024 * 1024
MAX_ROTATION_GENERATIONS = 64


class ShipperError(RuntimeError):
    pass


class SourceGapError(ShipperError):
    pass


class SpoolLimitError(ShipperError):
    pass


class RemoteRejectedError(ShipperError):
    def __init__(self, status: int, response: dict[str, Any]):
        self.status = status
        self.response = response
        super().__init__(f"receiver rejected request with HTTP {status}: {response}")


class _ClosingConnection(sqlite3.Connection):
    """Commit or roll back a context, then release its OS file handle."""

    def __exit__(self, *arguments: Any) -> bool | None:
        try:
            return super().__exit__(*arguments)
        finally:
            self.close()


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass(frozen=True)
class IngestResult:
    records: int
    batches: int
    spool_bytes: int
    at_end: bool


class TransportSpool:
    """Durable queue and source cursor with strict size and age backpressure."""

    def __init__(
        self,
        database: str | Path,
        source: str | Path,
        collector_id: str,
        max_bytes: int = DEFAULT_MAX_SPOOL_BYTES,
        max_age_seconds: int = DEFAULT_MAX_SPOOL_AGE_SECONDS,
    ) -> None:
        self.database = str(database)
        self.source = Path(source).resolve()
        self.collector_id = collector_id
        self.max_bytes = max_bytes
        self.max_age_ms = max_age_seconds * 1000
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database,
            timeout=10.0,
            factory=_ClosingConnection,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS source_cursor (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    source_path TEXT NOT NULL,
                    device INTEGER NOT NULL,
                    inode INTEGER NOT NULL,
                    byte_offset INTEGER NOT NULL,
                    active_local_session_id TEXT,
                    file_identity TEXT
                );
                CREATE TABLE IF NOT EXISTS local_sessions (
                    local_session_id TEXT PRIMARY KEY,
                    collector_id TEXT NOT NULL,
                    schema_version INTEGER NOT NULL,
                    chain_seed TEXT NOT NULL,
                    local_chain_head TEXT NOT NULL,
                    next_event_seq INTEGER NOT NULL,
                    next_batch_seq INTEGER NOT NULL,
                    server_session_id TEXT,
                    requested_server_session_id TEXT,
                    acknowledged_batch_seq INTEGER NOT NULL DEFAULT 0,
                    acknowledged_event_seq INTEGER NOT NULL DEFAULT 0,
                    acknowledged_chain_head TEXT NOT NULL,
                    heartbeat_seq INTEGER NOT NULL DEFAULT 0,
                    heartbeat_interval_ms INTEGER NOT NULL DEFAULT 15000,
                    last_heartbeat_at_ms INTEGER NOT NULL DEFAULT 0,
                    created_at_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pending_batches (
                    local_session_id TEXT NOT NULL,
                    batch_seq INTEGER NOT NULL,
                    first_event_seq INTEGER NOT NULL,
                    last_event_seq INTEGER NOT NULL,
                    previous_chain TEXT NOT NULL,
                    chain_head TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_bytes INTEGER NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (local_session_id, batch_seq),
                    FOREIGN KEY (local_session_id)
                        REFERENCES local_sessions(local_session_id)
                );
                """
            )
            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(local_sessions)"
                ).fetchall()
            }
            if "requested_server_session_id" not in columns:
                connection.execute(
                    "ALTER TABLE local_sessions "
                    "ADD COLUMN requested_server_session_id TEXT"
                )
            # Windows reports 128-bit ReFS file IDs through st_ino, which do
            # not fit SQLite INTEGER. The identity is kept as exact text; the
            # legacy integer columns are retained only for schema compatibility.
            cursor_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(source_cursor)"
                ).fetchall()
            }
            if "file_identity" not in cursor_columns:
                connection.execute(
                    "ALTER TABLE source_cursor ADD COLUMN file_identity TEXT"
                )
                connection.execute(
                    "UPDATE source_cursor "
                    "SET file_identity = CAST(device AS TEXT) || ':' || "
                    "CAST(inode AS TEXT) WHERE file_identity IS NULL"
                )

    @staticmethod
    def _identity(path: Path) -> tuple[str, int]:
        status = path.stat()
        return f"{int(status.st_dev)}:{int(status.st_ino)}", int(status.st_size)

    def _matching_rotated_path(self, identity: str) -> Path | None:
        for generation in range(1, MAX_ROTATION_GENERATIONS + 1):
            candidate = Path(f"{self.source}.{generation}")
            try:
                candidate_identity, _ = self._identity(candidate)
            except FileNotFoundError:
                continue
            if candidate_identity == identity:
                return candidate
        return None

    @staticmethod
    def _spool_bytes(connection: sqlite3.Connection) -> int:
        row = connection.execute(
            "SELECT COALESCE(SUM(payload_bytes), 0) AS total FROM pending_batches"
        ).fetchone()
        return int(row["total"])

    def spool_bytes(self) -> int:
        with self._connect() as connection:
            return self._spool_bytes(connection)

    def pending_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM pending_batches"
            ).fetchone()
            return int(row["count"])

    def _check_age_limit(self, connection: sqlite3.Connection, now: int) -> None:
        row = connection.execute(
            "SELECT MIN(created_at_ms) AS oldest FROM pending_batches"
        ).fetchone()
        if row["oldest"] is not None and now - int(row["oldest"]) > self.max_age_ms:
            raise SpoolLimitError(
                "oldest unacknowledged batch exceeds the configured spool age; "
                "ingestion is paused without deleting evidence"
            )

    def _initialize_cursor(
        self, connection: sqlite3.Connection
    ) -> sqlite3.Row:
        cursor = connection.execute(
            "SELECT * FROM source_cursor WHERE singleton = 1"
        ).fetchone()
        if cursor is not None:
            if cursor["source_path"] != str(self.source):
                raise SourceGapError("spool database belongs to a different source path")
            return cursor

        identity, _ = self._identity(self.source)
        connection.execute(
            """
            INSERT INTO source_cursor (
                singleton, source_path, device, inode, byte_offset, file_identity
            ) VALUES (1, ?, 0, 0, 0, ?)
            """,
            (str(self.source), identity),
        )
        cursor = connection.execute(
            "SELECT * FROM source_cursor WHERE singleton = 1"
        ).fetchone()
        assert cursor is not None
        return cursor

    def _resolve_cursor_path(
        self, connection: sqlite3.Connection, cursor: sqlite3.Row
    ) -> tuple[Path, bool]:
        current_identity, _ = self._identity(self.source)
        if cursor["file_identity"] == current_identity:
            return self.source, True

        rotated = self._matching_rotated_path(cursor["file_identity"])
        if rotated is None:
            raise SourceGapError(
                "the source rotated beyond retained generations before it was spooled"
            )
        return rotated, False

    def _start_local_session(
        self,
        connection: sqlite3.Connection,
        raw: bytes,
        schema_version: int,
        now: int,
    ) -> sqlite3.Row:
        chain_seed = chain_seed_from_open_record(raw, schema_version)
        local_session_id = uuid.uuid4().hex
        connection.execute(
            """
            INSERT INTO local_sessions (
                local_session_id, collector_id, schema_version, chain_seed,
                local_chain_head, next_event_seq, next_batch_seq,
                acknowledged_chain_head, created_at_ms
            ) VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)
            """,
            (
                local_session_id,
                self.collector_id,
                schema_version,
                chain_seed,
                chain_seed,
                chain_seed,
                now,
            ),
        )
        connection.execute(
            """
            UPDATE source_cursor SET active_local_session_id = ?
             WHERE singleton = 1
            """,
            (local_session_id,),
        )
        session = connection.execute(
            "SELECT * FROM local_sessions WHERE local_session_id = ?",
            (local_session_id,),
        ).fetchone()
        assert session is not None
        return session

    def ingest_available(
        self,
        batch_records: int = DEFAULT_BATCH_RECORDS,
        batch_bytes: int = DEFAULT_BATCH_BYTES,
    ) -> IngestResult:
        total_records = 0
        total_batches = 0
        at_end = False

        while True:
            now = _now_ms()
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._check_age_limit(connection, now)
                cursor = self._initialize_cursor(connection)
                cursor_path, is_current = self._resolve_cursor_path(connection, cursor)
                offset = int(cursor["byte_offset"])
                _, source_size = self._identity(cursor_path)
                if offset > source_size:
                    raise SourceGapError("source was truncated before it was spooled")

                if offset == source_size:
                    if not is_current:
                        identity, _ = self._identity(self.source)
                        connection.execute(
                            """
                            UPDATE source_cursor
                               SET file_identity = ?, byte_offset = 0
                             WHERE singleton = 1
                            """,
                            (identity,),
                        )
                        connection.commit()
                        continue
                    connection.commit()
                    at_end = True
                    break

                session = None
                if cursor["active_local_session_id"] is not None:
                    session = connection.execute(
                        "SELECT * FROM local_sessions WHERE local_session_id = ?",
                        (cursor["active_local_session_id"],),
                    ).fetchone()

                records: list[str] = []
                first_event_seq = 0
                previous_chain = ""
                chain_head = ""
                last_event_seq = 0
                batch_start_offset = offset
                final_offset = offset

                with cursor_path.open("rb") as source_file:
                    source_file.seek(offset)
                    while len(records) < batch_records:
                        line_offset = source_file.tell()
                        raw = source_file.readline()
                        if not raw:
                            break
                        if not raw.endswith(b"\n"):
                            source_file.seek(line_offset)
                            break
                        if raw in (b"\n", b"\r\n"):
                            raise ProtocolError("blank lines are not valid telemetry records")

                        document = decode_record(raw)
                        event_sequence = require_integer(
                            document.get("seq"), "event.seq", 1
                        )
                        event_name = require_string(
                            document.get("event"), "event.event", 255
                        )
                        new_collector_session = (
                            event_sequence == 1
                            and event_name == "log_segment_opened"
                            and session is not None
                            and (
                                bool(records)
                                or int(session["next_event_seq"]) != 1
                            )
                        )
                        if new_collector_session and records:
                            source_file.seek(line_offset)
                            break
                        if new_collector_session:
                            session = None
                        if session is None:
                            details = document.get("details")
                            if not isinstance(details, dict):
                                raise ProtocolError(
                                    "log_segment_opened.details must be an object"
                                )
                            schema_version = require_integer(
                                details.get("schema"), "details.schema", 1
                            )
                            session = self._start_local_session(
                                connection, raw, schema_version, now
                            )

                        if not records:
                            first_event_seq = int(session["next_event_seq"])
                            previous_chain = str(session["local_chain_head"])
                            chain_head = previous_chain
                        verified = verify_record(
                            raw, chain_head, first_event_seq + len(records)
                        )
                        encoded = verified.raw.decode("utf-8")
                        projected_bytes = sum(len(item.encode("utf-8")) for item in records)
                        if records and projected_bytes + len(verified.raw) > batch_bytes:
                            source_file.seek(line_offset)
                            break
                        records.append(encoded)
                        if verified.event == "collector_attestation_observed":
                            details = verified.document.get("details")
                            if not isinstance(details, dict):
                                raise ProtocolError(
                                    "collector attestation details must be an object"
                                )
                            requested_session = require_string(
                                details.get("server_session_id"),
                                "details.server_session_id",
                                32,
                            )
                            if session["requested_server_session_id"] not in (
                                None,
                                requested_session,
                            ):
                                raise ProtocolError(
                                    "collector session contains conflicting server bindings"
                                )
                            connection.execute(
                                """
                                UPDATE local_sessions
                                   SET requested_server_session_id = ?
                                 WHERE local_session_id = ?
                                """,
                                (requested_session, session["local_session_id"]),
                            )
                        chain_head = verified.chain
                        last_event_seq = verified.sequence
                        final_offset = source_file.tell()

                if not records:
                    connection.commit()
                    at_end = final_offset == source_size
                    break

                batch_seq = int(session["next_batch_seq"])
                request = {
                    "batch_seq": batch_seq,
                    "first_event_seq": first_event_seq,
                    "last_event_seq": last_event_seq,
                    "previous_chain": previous_chain,
                    "chain_head": chain_head,
                    "records": records,
                }
                payload = canonical_json(request)
                used = self._spool_bytes(connection)
                if used + len(payload) > self.max_bytes:
                    connection.rollback()
                    raise SpoolLimitError(
                        "spool size limit reached; ingestion is paused without deleting evidence"
                    )

                connection.execute(
                    """
                    INSERT INTO pending_batches (
                        local_session_id, batch_seq, first_event_seq,
                        last_event_seq, previous_chain, chain_head,
                        payload, payload_bytes, created_at_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session["local_session_id"],
                        batch_seq,
                        first_event_seq,
                        last_event_seq,
                        previous_chain,
                        chain_head,
                        payload,
                        len(payload),
                        now,
                    ),
                )
                connection.execute(
                    """
                    UPDATE local_sessions
                       SET local_chain_head = ?, next_event_seq = ?,
                           next_batch_seq = ?
                     WHERE local_session_id = ?
                    """,
                    (
                        chain_head,
                        last_event_seq + 1,
                        batch_seq + 1,
                        session["local_session_id"],
                    ),
                )
                connection.execute(
                    """
                    UPDATE source_cursor SET byte_offset = ? WHERE singleton = 1
                    """,
                    (final_offset,),
                )
                connection.commit()
                total_records += len(records)
                total_batches += 1
                if final_offset == batch_start_offset:
                    raise AssertionError("ingestion did not advance the source cursor")

        return IngestResult(
            total_records,
            total_batches,
            self.spool_bytes(),
            at_end,
        )

    def unregistered_sessions(self) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return list(
                connection.execute(
                    """
                    SELECT * FROM local_sessions
                     WHERE server_session_id IS NULL
                     ORDER BY created_at_ms, local_session_id
                    """
                )
            )

    def register_session(
        self,
        local_session_id: str,
        server_session_id: str,
        heartbeat_interval_ms: int,
        next_batch_seq: int,
        next_event_seq: int,
        chain_head: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            session = connection.execute(
                "SELECT * FROM local_sessions WHERE local_session_id = ?",
                (local_session_id,),
            ).fetchone()
            if session is None:
                raise ShipperError("local session disappeared during registration")

            remote_batch = next_batch_seq - 1
            remote_event = next_event_seq - 1
            if remote_batch < int(session["acknowledged_batch_seq"]):
                raise ShipperError("receiver session state moved backwards")
            if remote_batch == 0:
                if remote_event != 0 or chain_head != session["chain_seed"]:
                    raise ShipperError("receiver returned an invalid initial anchor")
            elif remote_batch > int(session["acknowledged_batch_seq"]):
                anchor = connection.execute(
                    """
                    SELECT * FROM pending_batches
                     WHERE local_session_id = ? AND batch_seq = ?
                    """,
                    (local_session_id, remote_batch),
                ).fetchone()
                if (
                    anchor is None
                    or int(anchor["last_event_seq"]) != remote_event
                    or anchor["chain_head"] != chain_head
                ):
                    raise ShipperError(
                        "receiver anchor cannot be reconciled with the durable spool"
                    )
                connection.execute(
                    """
                    DELETE FROM pending_batches
                     WHERE local_session_id = ? AND batch_seq <= ?
                    """,
                    (local_session_id, remote_batch),
                )

            connection.execute(
                """
                UPDATE local_sessions
                   SET server_session_id = ?, heartbeat_interval_ms = ?,
                       acknowledged_batch_seq = ?, acknowledged_event_seq = ?,
                       acknowledged_chain_head = ?
                 WHERE local_session_id = ?
                """,
                (
                    server_session_id,
                    heartbeat_interval_ms,
                    remote_batch,
                    remote_event,
                    chain_head,
                    local_session_id,
                ),
            )

    def next_pending_batch(self) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT b.*, s.server_session_id
                  FROM pending_batches AS b
                  JOIN local_sessions AS s USING (local_session_id)
                 WHERE s.server_session_id IS NOT NULL
                 ORDER BY s.created_at_ms, b.batch_seq
                 LIMIT 1
                """
            ).fetchone()

    def acknowledge_batch(
        self,
        local_session_id: str,
        batch_seq: int,
        last_event_seq: int,
        chain_head: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            batch = connection.execute(
                """
                SELECT * FROM pending_batches
                 WHERE local_session_id = ? AND batch_seq = ?
                """,
                (local_session_id, batch_seq),
            ).fetchone()
            if batch is None:
                raise ShipperError("acknowledged batch is not present in the spool")
            if (
                int(batch["last_event_seq"]) != last_event_seq
                or batch["chain_head"] != chain_head
            ):
                raise ShipperError("receiver acknowledgement does not match the batch")
            connection.execute(
                """
                UPDATE local_sessions
                   SET acknowledged_batch_seq = ?, acknowledged_event_seq = ?,
                       acknowledged_chain_head = ?
                 WHERE local_session_id = ?
                """,
                (batch_seq, last_event_seq, chain_head, local_session_id),
            )
            connection.execute(
                """
                DELETE FROM pending_batches
                 WHERE local_session_id = ? AND batch_seq = ?
                """,
                (local_session_id, batch_seq),
            )

    def heartbeat_candidate(self, force: bool = False) -> sqlite3.Row | None:
        now = _now_ms()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT s.* FROM local_sessions AS s
                 JOIN source_cursor AS c
                   ON c.active_local_session_id = s.local_session_id
                 WHERE s.server_session_id IS NOT NULL
                """
            ).fetchone()
            if row is None:
                return None
            due = now - int(row["last_heartbeat_at_ms"]) >= int(
                row["heartbeat_interval_ms"]
            )
            return row if force or due else None

    def acknowledge_heartbeat(self, local_session_id: str, heartbeat_seq: int) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE local_sessions
                   SET heartbeat_seq = ?, last_heartbeat_at_ms = ?
                 WHERE local_session_id = ? AND heartbeat_seq = ?
                """,
                (heartbeat_seq, _now_ms(), local_session_id, heartbeat_seq - 1),
            )
            if connection.total_changes != 1:
                raise ShipperError("heartbeat acknowledgement is out of sequence")


class ReceiverClient:
    def __init__(
        self,
        endpoint: str,
        bearer_token: str,
        ca_file: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        allow_insecure_http: bool = False,
        timeout_seconds: float = 10.0,
    ) -> None:
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme not in ({"https", "http"} if allow_insecure_http else {"https"}):
            raise ShipperError("receiver endpoint must use HTTPS")
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ShipperError("receiver endpoint is malformed")
        self.endpoint = endpoint.rstrip("/")
        self.bearer_token = bearer_token
        self.timeout_seconds = timeout_seconds
        self.ssl_context: ssl.SSLContext | None = None
        if parsed.scheme == "https":
            self.ssl_context = ssl.create_default_context(cafile=ca_file)
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            if client_cert:
                self.ssl_context.load_cert_chain(client_cert, client_key)

    def request(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = canonical_json(payload)
        request = urllib.request.Request(
            f"{self.endpoint}{path}",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "anticheat-telemetry-shipper/1",
            },
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout_seconds, context=self.ssl_context
            ) as response:
                value = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            try:
                try:
                    value = json.loads(error.read().decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    value = {"error": {"code": "invalid_error_response"}}
            finally:
                error.close()
            if 400 <= error.code < 500:
                raise RemoteRejectedError(error.code, value) from error
            raise OSError(f"receiver returned HTTP {error.code}") from error
        if not isinstance(value, dict):
            raise OSError("receiver returned a non-object response")
        return value


class TelemetryShipper:
    def __init__(self, spool: TransportSpool, receiver: ReceiverClient):
        self.spool = spool
        self.receiver = receiver

    def register_sessions(self) -> int:
        registered = 0
        for session in self.spool.unregistered_sessions():
            request = {
                "protocol_version": PROTOCOL_VERSION,
                "client_session_id": session["local_session_id"],
                "collector_id": session["collector_id"],
                "schema_version": int(session["schema_version"]),
                "chain_algorithm": CHAIN_ALGORITHM,
                "chain_seed": session["chain_seed"],
            }
            if session["requested_server_session_id"] is not None:
                request["requested_session_id"] = session[
                    "requested_server_session_id"
                ]
            response = self.receiver.request("/v1/sessions", request)
            server_session_id = require_string(
                response.get("session_id"), "response.session_id", 32
            )
            heartbeat_interval_ms = require_integer(
                response.get("heartbeat_interval_ms"),
                "response.heartbeat_interval_ms",
                1_000,
                3_600_000,
            )
            next_batch_seq = require_integer(
                response.get("next_batch_seq"), "response.next_batch_seq", 1
            )
            next_event_seq = require_integer(
                response.get("next_event_seq"), "response.next_event_seq", 1
            )
            chain_head = require_sha256(
                response.get("chain_head"), "response.chain_head"
            )
            self.spool.register_session(
                session["local_session_id"],
                server_session_id,
                heartbeat_interval_ms,
                next_batch_seq,
                next_event_seq,
                chain_head,
            )
            registered += 1
        return registered

    def flush_batches(self) -> int:
        delivered = 0
        while True:
            batch = self.spool.next_pending_batch()
            if batch is None:
                break
            payload = json.loads(bytes(batch["payload"]).decode("utf-8"))
            response = self.receiver.request(
                f"/v1/sessions/{batch['server_session_id']}/batches", payload
            )
            if response.get("accepted") is not True:
                raise ShipperError("receiver did not acknowledge the batch")
            response_batch_seq = require_integer(
                response.get("batch_seq"), "response.batch_seq", 1
            )
            response_chain = require_sha256(
                response.get("chain_head"), "response.chain_head"
            )
            if response_batch_seq != int(batch["batch_seq"]):
                raise ShipperError("receiver acknowledged a different batch sequence")
            self.spool.acknowledge_batch(
                batch["local_session_id"],
                response_batch_seq,
                int(batch["last_event_seq"]),
                response_chain,
            )
            delivered += 1
        return delivered

    def send_heartbeat(self, force: bool = False) -> bool:
        session = self.spool.heartbeat_candidate(force)
        if session is None:
            return False
        heartbeat_seq = int(session["heartbeat_seq"]) + 1
        request = {
            "heartbeat_seq": heartbeat_seq,
            "last_batch_seq": int(session["acknowledged_batch_seq"]),
            "last_event_seq": int(session["acknowledged_event_seq"]),
            "chain_head": session["acknowledged_chain_head"],
        }
        response = self.receiver.request(
            f"/v1/sessions/{session['server_session_id']}/heartbeat", request
        )
        if response.get("accepted") is not True:
            raise ShipperError("receiver did not acknowledge the heartbeat")
        response_sequence = require_integer(
            response.get("heartbeat_seq"), "response.heartbeat_seq", 1
        )
        if response_sequence != heartbeat_seq:
            raise ShipperError("receiver acknowledged a different heartbeat sequence")
        self.spool.acknowledge_heartbeat(session["local_session_id"], heartbeat_seq)
        return True

    def flush(self, heartbeat: bool = False) -> tuple[int, int, bool]:
        registered = self.register_sessions()
        delivered = self.flush_batches()
        sent_heartbeat = self.send_heartbeat(force=heartbeat)
        return registered, delivered, sent_heartbeat


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, help="collector JSONL path")
    parser.add_argument("--spool", default="telemetry-spool.sqlite3")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument(
        "--collector-id",
        default=socket.gethostname(),
        help="stable deployment-specific collector identity",
    )
    parser.add_argument("--token-env", default="AC_RECEIVER_TOKEN")
    parser.add_argument("--ca-file")
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")
    parser.add_argument("--max-spool-bytes", type=int, default=DEFAULT_MAX_SPOOL_BYTES)
    parser.add_argument(
        "--max-spool-age-seconds",
        type=int,
        default=DEFAULT_MAX_SPOOL_AGE_SECONDS,
    )
    parser.add_argument("--batch-records", type=int, default=DEFAULT_BATCH_RECORDS)
    parser.add_argument("--batch-bytes", type=int, default=DEFAULT_BATCH_BYTES)
    parser.add_argument("--poll-ms", type=int, default=1_000)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--allow-insecure-http", action="store_true")
    return parser.parse_args()


def _validate_arguments(arguments: argparse.Namespace) -> None:
    if not 1 <= arguments.batch_records <= 512:
        raise ShipperError("--batch-records must be between 1 and 512")
    if not 1024 <= arguments.batch_bytes <= 8 * 1024 * 1024:
        raise ShipperError("--batch-bytes must be between 1024 and 8388608")
    if not 64 * 1024 <= arguments.max_spool_bytes <= 4 * 1024 * 1024 * 1024:
        raise ShipperError("--max-spool-bytes is outside the accepted range")
    if not 60 <= arguments.max_spool_age_seconds <= 30 * 24 * 60 * 60:
        raise ShipperError("--max-spool-age-seconds is outside the accepted range")
    if not 100 <= arguments.poll_ms <= 60_000:
        raise ShipperError("--poll-ms must be between 100 and 60000")
    if bool(arguments.client_cert) != bool(arguments.client_key):
        raise ShipperError("--client-cert and --client-key must be supplied together")


def main() -> int:
    arguments = _parse_arguments()
    try:
        _validate_arguments(arguments)
        token = os.environ.get(arguments.token_env, "")
        if len(token) < 32:
            raise ShipperError(
                f"{arguments.token_env} must contain at least 32 characters"
            )
        spool = TransportSpool(
            arguments.spool,
            arguments.log,
            arguments.collector_id,
            arguments.max_spool_bytes,
            arguments.max_spool_age_seconds,
        )
        receiver = ReceiverClient(
            arguments.endpoint,
            token,
            arguments.ca_file,
            arguments.client_cert,
            arguments.client_key,
            arguments.allow_insecure_http,
        )
        shipper = TelemetryShipper(spool, receiver)
    except (OSError, ShipperError) as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return 2

    stop = False

    def request_stop(_signal: int, _frame: Any) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    backoff_seconds = 1.0
    while not stop:
        try:
            # Drain durable work before reading more input. Backpressure can
            # therefore recover without dropping evidence or blocking the
            # collector that owns the JSONL file.
            registered = shipper.register_sessions()
            delivered = shipper.flush_batches()
            try:
                ingested = spool.ingest_available(
                    arguments.batch_records, arguments.batch_bytes
                )
            except SpoolLimitError as error:
                if spool.pending_count() == 0:
                    raise
                print(f"transport backpressure: {error}", file=sys.stderr)
                if not arguments.once:
                    time.sleep(arguments.poll_ms / 1000.0)
                continue

            post_registered, post_delivered, heartbeat = shipper.flush(
                heartbeat=arguments.once
            )
            registered += post_registered
            delivered += post_delivered
            print(
                json.dumps(
                    {
                        "event": "transport_cycle_completed",
                        "records_spooled": ingested.records,
                        "batches_spooled": ingested.batches,
                        "sessions_registered": registered,
                        "batches_delivered": delivered,
                        "heartbeat_sent": heartbeat,
                        "pending_batches": spool.pending_count(),
                        "spool_bytes": spool.spool_bytes(),
                    },
                    separators=(",", ":"),
                ),
                flush=True,
            )
            backoff_seconds = 1.0
            if arguments.once:
                return 0
            time.sleep(arguments.poll_ms / 1000.0)
        except RemoteRejectedError as error:
            print(f"permanent receiver rejection: {error}", file=sys.stderr)
            return 4
        except (OSError, TimeoutError) as error:
            print(f"transient transport failure: {error}", file=sys.stderr)
            if arguments.once:
                return 3
            time.sleep(backoff_seconds)
            backoff_seconds = min(backoff_seconds * 2.0, 60.0)
        except (ProtocolError, SourceGapError, SpoolLimitError, ShipperError) as error:
            print(f"transport halted: {error}", file=sys.stderr)
            return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
