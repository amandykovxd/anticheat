#!/usr/bin/env python3
"""Reference authenticated receiver for remotely anchored telemetry batches."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import ssl
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from transport_common import (
    CHAIN_ALGORITHM,
    CLIENT_SESSION_ID_RE,
    PROTOCOL_VERSION,
    SESSION_ID_RE,
    SUPPORTED_SCHEMA_VERSIONS,
    ProtocolError,
    canonical_json,
    payload_digest,
    require_integer,
    require_sha256,
    require_string,
    verify_batch_records,
)


MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_BATCH_RECORDS = 512
SESSION_PATH = re.compile(r"^/v1/sessions/([0-9a-f]{32})$")
BATCH_PATH = re.compile(r"^/v1/sessions/([0-9a-f]{32})/batches$")
HEARTBEAT_PATH = re.compile(r"^/v1/sessions/([0-9a-f]{32})/heartbeat$")


class _ClosingConnection(sqlite3.Connection):
    """Commit or roll back a context, then release its OS file handle."""

    def __exit__(self, *arguments: Any) -> bool | None:
        try:
            return super().__exit__(*arguments)
        finally:
            self.close()


class ReceiverError(RuntimeError):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


class ReceiverStore:
    """SQLite-backed append-only session, batch, and heartbeat state."""

    def __init__(self, database: str | Path, heartbeat_interval_ms: int = 15_000):
        self.database = str(database)
        self.heartbeat_interval_ms = heartbeat_interval_ms
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
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    client_session_id TEXT NOT NULL UNIQUE,
                    collector_id TEXT NOT NULL,
                    protocol_version INTEGER NOT NULL,
                    schema_version INTEGER NOT NULL,
                    chain_algorithm TEXT NOT NULL,
                    chain_seed TEXT NOT NULL,
                    chain_head TEXT NOT NULL,
                    last_event_seq INTEGER NOT NULL DEFAULT 0,
                    last_batch_seq INTEGER NOT NULL DEFAULT 0,
                    last_heartbeat_seq INTEGER NOT NULL DEFAULT 0,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS batches (
                    session_id TEXT NOT NULL,
                    batch_seq INTEGER NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    first_event_seq INTEGER NOT NULL,
                    last_event_seq INTEGER NOT NULL,
                    previous_chain TEXT NOT NULL,
                    chain_head TEXT NOT NULL,
                    record_count INTEGER NOT NULL,
                    payload BLOB NOT NULL,
                    received_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (session_id, batch_seq),
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                );
                CREATE TABLE IF NOT EXISTS heartbeats (
                    session_id TEXT NOT NULL,
                    heartbeat_seq INTEGER NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    last_batch_seq INTEGER NOT NULL,
                    last_event_seq INTEGER NOT NULL,
                    chain_head TEXT NOT NULL,
                    received_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (session_id, heartbeat_seq),
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                );
                """
            )

    @staticmethod
    def _session_response(row: sqlite3.Row, duplicate: bool) -> dict[str, Any]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "session_id": row["session_id"],
            "heartbeat_interval_ms": 15_000,
            "next_batch_seq": row["last_batch_seq"] + 1,
            "next_event_seq": row["last_event_seq"] + 1,
            "chain_head": row["chain_head"],
            "duplicate": duplicate,
        }

    def create_session(self, request: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        try:
            protocol_version = require_integer(
                request.get("protocol_version"), "protocol_version", 1
            )
            if protocol_version != PROTOCOL_VERSION:
                raise ReceiverError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "protocol_version_unsupported",
                    "the requested transport protocol is not supported",
                    {"supported": [PROTOCOL_VERSION]},
                )
            schema_version = require_integer(
                request.get("schema_version"), "schema_version", 1
            )
            if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
                raise ReceiverError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "schema_version_unsupported",
                    "the requested event schema is not supported",
                    {"supported": sorted(SUPPORTED_SCHEMA_VERSIONS)},
                )
            client_session_id = require_string(
                request.get("client_session_id"), "client_session_id", 64
            )
            if CLIENT_SESSION_ID_RE.fullmatch(client_session_id) is None:
                raise ProtocolError("client_session_id has an invalid format")
            collector_id = require_string(
                request.get("collector_id"), "collector_id", 255
            )
            chain_algorithm = require_string(
                request.get("chain_algorithm"), "chain_algorithm", 32
            )
            if chain_algorithm != CHAIN_ALGORITHM:
                raise ProtocolError("chain_algorithm must be sha256")
            chain_seed = require_sha256(request.get("chain_seed"), "chain_seed")
        except ProtocolError as error:
            raise ReceiverError(
                HTTPStatus.BAD_REQUEST, "request_invalid", str(error)
            ) from error

        now = _now_ms()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM sessions WHERE client_session_id = ?",
                (client_session_id,),
            ).fetchone()
            if existing is not None:
                immutable = (
                    existing["collector_id"] == collector_id
                    and existing["protocol_version"] == protocol_version
                    and existing["schema_version"] == schema_version
                    and existing["chain_algorithm"] == chain_algorithm
                    and existing["chain_seed"] == chain_seed
                )
                if not immutable:
                    raise ReceiverError(
                        HTTPStatus.CONFLICT,
                        "client_session_conflict",
                        "client_session_id was already registered with different metadata",
                    )
                response = self._session_response(existing, True)
                response["heartbeat_interval_ms"] = self.heartbeat_interval_ms
                return HTTPStatus.OK, response

            session_id = secrets.token_hex(16)
            connection.execute(
                """
                INSERT INTO sessions (
                    session_id, client_session_id, collector_id,
                    protocol_version, schema_version, chain_algorithm,
                    chain_seed, chain_head, created_at_ms, updated_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    client_session_id,
                    collector_id,
                    protocol_version,
                    schema_version,
                    chain_algorithm,
                    chain_seed,
                    chain_seed,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            assert row is not None
            response = self._session_response(row, False)
            response["heartbeat_interval_ms"] = self.heartbeat_interval_ms
            return HTTPStatus.CREATED, response

    @staticmethod
    def _load_session(
        connection: sqlite3.Connection, session_id: str
    ) -> sqlite3.Row:
        if SESSION_ID_RE.fullmatch(session_id) is None:
            raise ReceiverError(
                HTTPStatus.NOT_FOUND, "session_not_found", "session does not exist"
            )
        row = connection.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            raise ReceiverError(
                HTTPStatus.NOT_FOUND, "session_not_found", "session does not exist"
            )
        return row

    def append_batch(
        self, session_id: str, request: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        try:
            batch_seq = require_integer(request.get("batch_seq"), "batch_seq", 1)
            first_event_seq = require_integer(
                request.get("first_event_seq"), "first_event_seq", 1
            )
            last_event_seq = require_integer(
                request.get("last_event_seq"), "last_event_seq", 1
            )
            previous_chain = require_sha256(
                request.get("previous_chain"), "previous_chain"
            )
            claimed_chain_head = require_sha256(
                request.get("chain_head"), "chain_head"
            )
            records = request.get("records")
            if not isinstance(records, list) or not records:
                raise ProtocolError("records must be a non-empty array")
            if len(records) > MAX_BATCH_RECORDS:
                raise ProtocolError("records exceeds the batch record limit")
        except ProtocolError as error:
            raise ReceiverError(
                HTTPStatus.BAD_REQUEST, "request_invalid", str(error)
            ) from error

        digest = payload_digest(request)
        payload = canonical_json(request)
        now = _now_ms()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            session = self._load_session(connection, session_id)
            duplicate = connection.execute(
                "SELECT request_sha256 FROM batches WHERE session_id = ? AND batch_seq = ?",
                (session_id, batch_seq),
            ).fetchone()
            if duplicate is not None:
                if not hmac.compare_digest(duplicate["request_sha256"], digest):
                    raise ReceiverError(
                        HTTPStatus.CONFLICT,
                        "batch_idempotency_conflict",
                        "batch sequence was already accepted with different content",
                    )
                return HTTPStatus.OK, {
                    "accepted": True,
                    "duplicate": True,
                    "session_id": session_id,
                    "batch_seq": batch_seq,
                    "next_batch_seq": session["last_batch_seq"] + 1,
                    "next_event_seq": session["last_event_seq"] + 1,
                    "chain_head": session["chain_head"],
                }

            expected_batch = session["last_batch_seq"] + 1
            expected_event = session["last_event_seq"] + 1
            if batch_seq != expected_batch:
                raise ReceiverError(
                    HTTPStatus.CONFLICT,
                    "batch_sequence_gap",
                    "batch sequence is missing or reordered",
                    {"expected_batch_seq": expected_batch},
                )
            if first_event_seq != expected_event:
                raise ReceiverError(
                    HTTPStatus.CONFLICT,
                    "event_sequence_gap",
                    "event sequence is missing or reordered",
                    {"expected_event_seq": expected_event},
                )
            if not hmac.compare_digest(previous_chain, session["chain_head"]):
                raise ReceiverError(
                    HTTPStatus.CONFLICT,
                    "anchor_mismatch",
                    "batch does not continue from the remotely anchored chain head",
                    {"expected_chain_head": session["chain_head"]},
                )
            try:
                verified, computed_chain_head = verify_batch_records(
                    records, previous_chain, first_event_seq
                )
            except ProtocolError as error:
                raise ReceiverError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "event_chain_invalid",
                    str(error),
                ) from error
            computed_last_event = verified[-1].sequence
            if computed_last_event != last_event_seq:
                raise ReceiverError(
                    HTTPStatus.BAD_REQUEST,
                    "last_event_seq_invalid",
                    "last_event_seq does not match the retained records",
                )
            if not hmac.compare_digest(computed_chain_head, claimed_chain_head):
                raise ReceiverError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "chain_head_invalid",
                    "chain_head does not match the retained records",
                )

            connection.execute(
                """
                INSERT INTO batches (
                    session_id, batch_seq, request_sha256, first_event_seq,
                    last_event_seq, previous_chain, chain_head, record_count,
                    payload, received_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    batch_seq,
                    digest,
                    first_event_seq,
                    last_event_seq,
                    previous_chain,
                    claimed_chain_head,
                    len(verified),
                    payload,
                    now,
                ),
            )
            connection.execute(
                """
                UPDATE sessions
                   SET last_batch_seq = ?, last_event_seq = ?,
                       chain_head = ?, updated_at_ms = ?
                 WHERE session_id = ?
                """,
                (batch_seq, last_event_seq, claimed_chain_head, now, session_id),
            )
            return HTTPStatus.ACCEPTED, {
                "accepted": True,
                "duplicate": False,
                "session_id": session_id,
                "batch_seq": batch_seq,
                "next_batch_seq": batch_seq + 1,
                "next_event_seq": last_event_seq + 1,
                "chain_head": claimed_chain_head,
            }

    def append_heartbeat(
        self, session_id: str, request: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        try:
            heartbeat_seq = require_integer(
                request.get("heartbeat_seq"), "heartbeat_seq", 1
            )
            last_batch_seq = require_integer(
                request.get("last_batch_seq"), "last_batch_seq"
            )
            last_event_seq = require_integer(
                request.get("last_event_seq"), "last_event_seq"
            )
            chain_head = require_sha256(request.get("chain_head"), "chain_head")
        except ProtocolError as error:
            raise ReceiverError(
                HTTPStatus.BAD_REQUEST, "request_invalid", str(error)
            ) from error

        digest = payload_digest(request)
        now = _now_ms()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            session = self._load_session(connection, session_id)
            duplicate = connection.execute(
                """
                SELECT request_sha256 FROM heartbeats
                 WHERE session_id = ? AND heartbeat_seq = ?
                """,
                (session_id, heartbeat_seq),
            ).fetchone()
            if duplicate is not None:
                if not hmac.compare_digest(duplicate["request_sha256"], digest):
                    raise ReceiverError(
                        HTTPStatus.CONFLICT,
                        "heartbeat_idempotency_conflict",
                        "heartbeat sequence was already accepted with different content",
                    )
                return HTTPStatus.OK, {
                    "accepted": True,
                    "duplicate": True,
                    "heartbeat_seq": heartbeat_seq,
                }

            expected_heartbeat = session["last_heartbeat_seq"] + 1
            if heartbeat_seq != expected_heartbeat:
                raise ReceiverError(
                    HTTPStatus.CONFLICT,
                    "heartbeat_sequence_gap",
                    "heartbeat sequence is missing or reordered",
                    {"expected_heartbeat_seq": expected_heartbeat},
                )
            anchor_matches = (
                last_batch_seq == session["last_batch_seq"]
                and last_event_seq == session["last_event_seq"]
                and hmac.compare_digest(chain_head, session["chain_head"])
            )
            if not anchor_matches:
                raise ReceiverError(
                    HTTPStatus.CONFLICT,
                    "heartbeat_anchor_mismatch",
                    "heartbeat does not match the remotely anchored session state",
                    {
                        "expected_batch_seq": session["last_batch_seq"],
                        "expected_event_seq": session["last_event_seq"],
                        "expected_chain_head": session["chain_head"],
                    },
                )
            connection.execute(
                """
                INSERT INTO heartbeats (
                    session_id, heartbeat_seq, request_sha256,
                    last_batch_seq, last_event_seq, chain_head, received_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    heartbeat_seq,
                    digest,
                    last_batch_seq,
                    last_event_seq,
                    chain_head,
                    now,
                ),
            )
            connection.execute(
                """
                UPDATE sessions
                   SET last_heartbeat_seq = ?, updated_at_ms = ?
                 WHERE session_id = ?
                """,
                (heartbeat_seq, now, session_id),
            )
            return HTTPStatus.ACCEPTED, {
                "accepted": True,
                "duplicate": False,
                "heartbeat_seq": heartbeat_seq,
                "server_time_ms": now,
            }

    def session_status(self, session_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = self._load_session(connection, session_id)
            return {
                "session_id": row["session_id"],
                "client_session_id": row["client_session_id"],
                "collector_id": row["collector_id"],
                "schema_version": row["schema_version"],
                "last_batch_seq": row["last_batch_seq"],
                "last_event_seq": row["last_event_seq"],
                "last_heartbeat_seq": row["last_heartbeat_seq"],
                "chain_head": row["chain_head"],
                "updated_at_ms": row["updated_at_ms"],
            }


class ReceiverHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        store: ReceiverStore,
        bearer_token: str,
    ) -> None:
        super().__init__(address, ReceiverRequestHandler)
        self.store = store
        self.bearer_token = bearer_token


class ReceiverRequestHandler(BaseHTTPRequestHandler):
    server: ReceiverHttpServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format_string: str, *args: Any) -> None:
        sys.stderr.write(
            "%s - - [%s] %s\n"
            % (self.address_string(), self.log_date_time_string(), format_string % args)
        )

    def _write_json(self, status: int, value: dict[str, Any]) -> None:
        body = canonical_json(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _write_error(self, error: ReceiverError) -> None:
        self._write_json(
            error.status,
            {
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                }
            },
        )

    def _authenticated(self) -> bool:
        expected = f"Bearer {self.server.bearer_token}"
        supplied = self.headers.get("Authorization", "")
        return hmac.compare_digest(supplied.encode(), expected.encode())

    def _require_authentication(self) -> bool:
        if self._authenticated():
            return True
        self._write_json(
            HTTPStatus.UNAUTHORIZED,
            {"error": {"code": "authentication_required", "message": "invalid token"}},
        )
        return False

    def _read_request(self) -> dict[str, Any]:
        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            raise ReceiverError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "content_type_invalid",
                "Content-Type must be application/json",
            )
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError as error:
            raise ReceiverError(
                HTTPStatus.BAD_REQUEST, "content_length_invalid", "invalid Content-Length"
            ) from error
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ReceiverError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request_too_large",
                "request exceeds the configured limit",
            )
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReceiverError(
                HTTPStatus.BAD_REQUEST, "json_invalid", "request body is not valid JSON"
            ) from error
        if not isinstance(value, dict):
            raise ReceiverError(
                HTTPStatus.BAD_REQUEST, "json_invalid", "request body must be an object"
            )
        return value

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path == "/healthz":
            self._write_json(HTTPStatus.OK, {"status": "ok"})
            return
        if not self._require_authentication():
            return
        match = SESSION_PATH.fullmatch(self.path)
        if match is None:
            self._write_json(
                HTTPStatus.NOT_FOUND,
                {"error": {"code": "route_not_found", "message": "route not found"}},
            )
            return
        try:
            self._write_json(
                HTTPStatus.OK, self.server.store.session_status(match.group(1))
            )
        except ReceiverError as error:
            self._write_error(error)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if not self._require_authentication():
            return
        try:
            request = self._read_request()
            if self.path == "/v1/sessions":
                status, response = self.server.store.create_session(request)
            else:
                batch_match = BATCH_PATH.fullmatch(self.path)
                heartbeat_match = HEARTBEAT_PATH.fullmatch(self.path)
                if batch_match is not None:
                    status, response = self.server.store.append_batch(
                        batch_match.group(1), request
                    )
                elif heartbeat_match is not None:
                    status, response = self.server.store.append_heartbeat(
                        heartbeat_match.group(1), request
                    )
                else:
                    raise ReceiverError(
                        HTTPStatus.NOT_FOUND, "route_not_found", "route not found"
                    )
            self._write_json(status, response)
        except ReceiverError as error:
            self._write_error(error)


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default="receiver.sqlite3")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", help="PEM server certificate chain")
    parser.add_argument("--key", help="PEM server private key")
    parser.add_argument("--client-ca", help="PEM CA used to require client certificates")
    parser.add_argument("--token-env", default="AC_RECEIVER_TOKEN")
    parser.add_argument("--heartbeat-ms", type=int, default=15_000)
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="development only: serve plaintext HTTP",
    )
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    token = os.environ.get(arguments.token_env, "")
    if len(token) < 32:
        print(
            f"{arguments.token_env} must contain at least 32 characters",
            file=sys.stderr,
        )
        return 2
    if not 1_000 <= arguments.heartbeat_ms <= 3_600_000:
        print("--heartbeat-ms must be between 1000 and 3600000", file=sys.stderr)
        return 2
    if bool(arguments.cert) != bool(arguments.key):
        print("--cert and --key must be supplied together", file=sys.stderr)
        return 2
    if not arguments.allow_insecure_http and not arguments.cert:
        print("TLS is required; supply --cert and --key", file=sys.stderr)
        return 2

    store = ReceiverStore(arguments.database, arguments.heartbeat_ms)
    server = ReceiverHttpServer((arguments.listen, arguments.port), store, token)
    if arguments.cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(arguments.cert, arguments.key)
        if arguments.client_ca:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(arguments.client_ca)
        server.socket = context.wrap_socket(server.socket, server_side=True)

    scheme = "http" if arguments.allow_insecure_http and not arguments.cert else "https"
    print(f"receiver listening on {scheme}://{arguments.listen}:{arguments.port}")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
