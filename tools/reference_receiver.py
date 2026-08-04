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
from correlation_rules import CorrelationEngine, CorrelationError


MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_BATCH_RECORDS = 512
SESSION_PATH = re.compile(r"^/v1/sessions/([0-9a-f]{32})$")
BATCH_PATH = re.compile(r"^/v1/sessions/([0-9a-f]{32})/batches$")
HEARTBEAT_PATH = re.compile(r"^/v1/sessions/([0-9a-f]{32})/heartbeat$")
SESSION_DECISIONS_PATH = re.compile(
    r"^/v1/sessions/([0-9a-f]{32})/decisions$"
)
RULE_PATH = re.compile(r"^/v1/rules/([a-z][a-z0-9_.-]{2,63})$")
RULE_PROMOTE_PATH = re.compile(
    r"^/v1/rules/([a-z][a-z0-9_.-]{2,63})/promote$"
)
RULE_ROLLBACK_PATH = re.compile(
    r"^/v1/rules/([a-z][a-z0-9_.-]{2,63})/rollback$"
)
DECISION_FEEDBACK_PATH = re.compile(
    r"^/v1/decisions/([0-9a-f]{64})/feedback$"
)
ATTESTATION_CHALLENGE_PATH = "/v1/attestations/challenges"
ATTESTATION_DOMAIN = b"ac-collector-attestation-v2"
ATTESTATION_CHALLENGE_BYTES = 16
ATTESTATION_NONCE_BYTES = 32


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

    def __init__(
        self,
        database: str | Path,
        heartbeat_interval_ms: int = 15_000,
        trusted_collectors: dict[str, tuple[str, ...]] | None = None,
        attestation_ttl_ms: int = 300_000,
    ):
        self.database = str(database)
        self.heartbeat_interval_ms = heartbeat_interval_ms
        self.trusted_collectors = trusted_collectors or {}
        self.attestation_ttl_ms = attestation_ttl_ms
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
                    attestation_verified INTEGER NOT NULL DEFAULT 0,
                    attestation_challenge_id TEXT,
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
                CREATE TABLE IF NOT EXISTS attestation_challenges (
                    challenge_id TEXT PRIMARY KEY,
                    collector_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    reserved_session_id TEXT,
                    expires_at_ms INTEGER NOT NULL,
                    consumed_session_id TEXT,
                    validated_at_ms INTEGER,
                    created_at_ms INTEGER NOT NULL,
                    FOREIGN KEY (consumed_session_id) REFERENCES sessions(session_id)
                );
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(sessions)").fetchall()
            }
            if "attestation_verified" not in columns:
                connection.execute(
                    "ALTER TABLE sessions ADD COLUMN attestation_verified "
                    "INTEGER NOT NULL DEFAULT 0"
                )
            if "attestation_challenge_id" not in columns:
                connection.execute(
                    "ALTER TABLE sessions ADD COLUMN attestation_challenge_id TEXT"
                )
            challenge_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(attestation_challenges)"
                ).fetchall()
            }
            if "reserved_session_id" not in challenge_columns:
                connection.execute(
                    "ALTER TABLE attestation_challenges "
                    "ADD COLUMN reserved_session_id TEXT"
                )
            CorrelationEngine.initialize(connection)

    def create_attestation_challenge(
        self, request: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        try:
            collector_id = require_string(
                request.get("collector_id"), "collector_id", 255
            )
        except ProtocolError as error:
            raise ReceiverError(
                HTTPStatus.BAD_REQUEST, "request_invalid", str(error)
            ) from error
        if collector_id not in self.trusted_collectors:
            raise ReceiverError(
                HTTPStatus.FORBIDDEN,
                "collector_not_trusted",
                "collector identity is not registered for attestation",
            )

        now = _now_ms()
        challenge_id = secrets.token_hex(ATTESTATION_CHALLENGE_BYTES)
        nonce = secrets.token_hex(ATTESTATION_NONCE_BYTES)
        session_id = secrets.token_hex(16)
        expires_at_ms = now + self.attestation_ttl_ms
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO attestation_challenges (
                    challenge_id, collector_id, nonce, reserved_session_id,
                    expires_at_ms, created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_id,
                    collector_id,
                    nonce,
                    session_id,
                    expires_at_ms,
                    now,
                ),
            )
        return HTTPStatus.CREATED, {
            "challenge_id": challenge_id,
            "nonce": nonce,
            "session_id": session_id,
            "expires_at_ms": expires_at_ms,
            "algorithm": "sha256",
        }

    def _validate_attestations(
        self,
        connection: sqlite3.Connection,
        session: sqlite3.Row,
        records: list[Any],
        now: int,
    ) -> None:
        trusted = self.trusted_collectors.get(session["collector_id"])
        if trusted is None:
            return

        for record in records:
            if record.event != "collector_attestation_observed":
                continue
            try:
                details = record.document.get("details")
                if not isinstance(details, dict):
                    raise ProtocolError("attestation details must be an object")
                challenge_id = require_string(
                    details.get("challenge_id"), "details.challenge_id", 32
                )
                if (
                    len(challenge_id) != ATTESTATION_CHALLENGE_BYTES * 2
                    or challenge_id.lower() != challenge_id
                ):
                    raise ProtocolError("details.challenge_id has an invalid format")
                try:
                    bytes.fromhex(challenge_id)
                except ValueError as error:
                    raise ProtocolError(
                        "details.challenge_id has an invalid format"
                    ) from error
                nonce_sha256 = require_sha256(
                    details.get("nonce_sha256"), "details.nonce_sha256"
                )
                file_sha256 = require_sha256(
                    details.get("file_sha256"), "details.file_sha256"
                )
                expected_mapped = require_sha256(
                    details.get("expected_mapped_sha256"),
                    "details.expected_mapped_sha256",
                )
                observed_mapped = require_sha256(
                    details.get("observed_mapped_sha256"),
                    "details.observed_mapped_sha256",
                )
                response_sha256 = require_sha256(
                    details.get("response_sha256"), "details.response_sha256"
                )
                attested_session_id = require_string(
                    details.get("server_session_id"),
                    "details.server_session_id",
                    32,
                )
                if SESSION_ID_RE.fullmatch(attested_session_id) is None:
                    raise ProtocolError(
                        "details.server_session_id has an invalid format"
                    )
                collector_version = require_string(
                    details.get("collector_version"),
                    "details.collector_version",
                    64,
                )
                collector_build_id = require_sha256(
                    details.get("collector_build_id"),
                    "details.collector_build_id",
                )
                if details.get("mapped_matches_disk") is not True:
                    raise ProtocolError("mapped collector image does not match disk")
                if details.get("complete") is not True:
                    raise ProtocolError("collector attestation is incomplete")
            except ProtocolError as error:
                raise ReceiverError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "collector_attestation_invalid",
                    str(error),
                ) from error

            challenge = connection.execute(
                "SELECT * FROM attestation_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
            if challenge is None or challenge["collector_id"] != session["collector_id"]:
                raise ReceiverError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "collector_attestation_invalid",
                    "attestation challenge is unknown for this collector",
                )
            if (
                challenge["reserved_session_id"] != session["session_id"]
                or not hmac.compare_digest(
                    attested_session_id, session["session_id"]
                )
            ):
                raise ReceiverError(
                    HTTPStatus.CONFLICT,
                    "collector_attestation_wrong_session",
                    "attestation challenge is bound to a different server session",
                )
            consumed = challenge["consumed_session_id"]
            if challenge["expires_at_ms"] < now and consumed is None:
                raise ReceiverError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "collector_attestation_expired",
                    "attestation challenge has expired",
                )
            if consumed is not None:
                raise ReceiverError(
                    HTTPStatus.CONFLICT,
                    "collector_attestation_replayed",
                    "attestation challenge was already consumed",
                )

            trusted_file, trusted_mapped = trusted[:2]
            trusted_version = trusted[2] if len(trusted) >= 3 else "0.4.0"
            trusted_build_id = trusted[3] if len(trusted) >= 4 else trusted_file
            expected_nonce_digest = hashlib.sha256(
                bytes.fromhex(challenge["nonce"])
            ).hexdigest()
            expected_response = hashlib.sha256(
                ATTESTATION_DOMAIN
                + bytes.fromhex(challenge_id)
                + bytes.fromhex(challenge["nonce"])
                + bytes.fromhex(session["session_id"])
                + bytes([len(collector_version.encode("utf-8"))])
                + collector_version.encode("utf-8")
                + bytes.fromhex(collector_build_id)
                + bytes.fromhex(file_sha256)
                + bytes.fromhex(observed_mapped)
            ).hexdigest()
            identity_matches = (
                hmac.compare_digest(file_sha256, trusted_file)
                and hmac.compare_digest(collector_version, trusted_version)
                and hmac.compare_digest(collector_build_id, trusted_build_id)
                and hmac.compare_digest(expected_mapped, trusted_mapped)
                and hmac.compare_digest(observed_mapped, trusted_mapped)
                and hmac.compare_digest(expected_mapped, observed_mapped)
                and hmac.compare_digest(nonce_sha256, expected_nonce_digest)
                and hmac.compare_digest(response_sha256, expected_response)
            )
            if not identity_matches:
                raise ReceiverError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "collector_attestation_invalid",
                    "collector identity or nonce response is invalid",
                )

            connection.execute(
                """
                UPDATE attestation_challenges
                   SET consumed_session_id = ?, validated_at_ms = ?
                 WHERE challenge_id = ?
                """,
                (session["session_id"], now, challenge_id),
            )
            connection.execute(
                """
                UPDATE sessions
                   SET attestation_verified = 1, attestation_challenge_id = ?
                 WHERE session_id = ?
                """,
                (challenge_id, session["session_id"]),
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
            requested_session_id_value = request.get("requested_session_id")
            requested_session_id = None
            if requested_session_id_value is not None:
                requested_session_id = require_string(
                    requested_session_id_value, "requested_session_id", 32
                )
                if SESSION_ID_RE.fullmatch(requested_session_id) is None:
                    raise ProtocolError("requested_session_id has an invalid format")
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

            if requested_session_id is not None:
                reservation = connection.execute(
                    """
                    SELECT collector_id, expires_at_ms, consumed_session_id
                      FROM attestation_challenges
                     WHERE reserved_session_id = ?
                    """,
                    (requested_session_id,),
                ).fetchone()
                if (
                    reservation is None
                    or reservation["collector_id"] != collector_id
                    or reservation["expires_at_ms"] < now
                    or reservation["consumed_session_id"] is not None
                ):
                    raise ReceiverError(
                        HTTPStatus.CONFLICT,
                        "session_reservation_invalid",
                        "requested server session is absent, expired, or already used",
                    )
                session_id = requested_session_id
            else:
                if collector_id in self.trusted_collectors:
                    raise ReceiverError(
                        HTTPStatus.CONFLICT,
                        "attestation_session_required",
                        "trusted collectors must use a challenge-reserved session",
                    )
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

            self._validate_attestations(connection, session, verified, now)
            session = self._load_session(connection, session_id)
            CorrelationEngine.retain_and_correlate(
                connection, session, verified, now
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
            if (
                session["collector_id"] in self.trusted_collectors
                and session["attestation_verified"] != 1
            ):
                raise ReceiverError(
                    HTTPStatus.CONFLICT,
                    "collector_attestation_required",
                    "a verified collector attestation must be anchored before heartbeat",
                )
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
                "attestation_required": row["collector_id"] in self.trusted_collectors,
                "attestation_verified": bool(row["attestation_verified"]),
                "attestation_challenge_id": row["attestation_challenge_id"],
                "correlation_decisions": len(
                    CorrelationEngine.decisions(connection, session_id)
                ),
            }

    def install_rule(self, definition: dict[str, Any]) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return CorrelationEngine.install_rule(connection, definition)

    def promote_rule(self, rule_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return CorrelationEngine.promote_rule(connection, rule_id)

    def rollback_rule(self, rule_id: str, version: int) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return CorrelationEngine.rollback_rule(connection, rule_id, version)

    def record_decision_feedback(
        self, decision_id: str, false_positive: bool
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            CorrelationEngine.record_feedback(
                connection, decision_id, false_positive
            )

    def rule_status(self, rule_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            return CorrelationEngine.rule_status(connection, rule_id)

    def correlation_decisions(self, session_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            self._load_session(connection, session_id)
            return CorrelationEngine.decisions(connection, session_id)


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
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if 0 < length <= MAX_REQUEST_BYTES:
            self.rfile.read(length)
        elif length != 0:
            self.close_connection = True
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
        decisions_match = SESSION_DECISIONS_PATH.fullmatch(self.path)
        rule_match = RULE_PATH.fullmatch(self.path)
        if decisions_match is not None:
            try:
                self._write_json(
                    HTTPStatus.OK,
                    {
                        "decisions": self.server.store.correlation_decisions(
                            decisions_match.group(1)
                        )
                    },
                )
            except ReceiverError as error:
                self._write_error(error)
            return
        if rule_match is not None:
            try:
                self._write_json(
                    HTTPStatus.OK,
                    self.server.store.rule_status(rule_match.group(1)),
                )
            except CorrelationError as error:
                self._write_error(
                    ReceiverError(
                        HTTPStatus.NOT_FOUND,
                        "correlation_rule_not_found",
                        str(error),
                    )
                )
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
            if self.path == ATTESTATION_CHALLENGE_PATH:
                status, response = self.server.store.create_attestation_challenge(
                    request
                )
            elif self.path == "/v1/sessions":
                status, response = self.server.store.create_session(request)
            elif self.path == "/v1/rules":
                response = self.server.store.install_rule(request)
                status = HTTPStatus.CREATED
            else:
                batch_match = BATCH_PATH.fullmatch(self.path)
                heartbeat_match = HEARTBEAT_PATH.fullmatch(self.path)
                promote_match = RULE_PROMOTE_PATH.fullmatch(self.path)
                rollback_match = RULE_ROLLBACK_PATH.fullmatch(self.path)
                feedback_match = DECISION_FEEDBACK_PATH.fullmatch(self.path)
                if batch_match is not None:
                    status, response = self.server.store.append_batch(
                        batch_match.group(1), request
                    )
                elif heartbeat_match is not None:
                    status, response = self.server.store.append_heartbeat(
                        heartbeat_match.group(1), request
                    )
                elif promote_match is not None:
                    response = self.server.store.promote_rule(
                        promote_match.group(1)
                    )
                    status = HTTPStatus.OK
                elif rollback_match is not None:
                    version = require_integer(
                        request.get("version"), "version", 1
                    )
                    response = self.server.store.rollback_rule(
                        rollback_match.group(1), version
                    )
                    status = HTTPStatus.OK
                elif feedback_match is not None:
                    false_positive = request.get("false_positive")
                    if not isinstance(false_positive, bool):
                        raise ProtocolError(
                            "false_positive must be a boolean"
                        )
                    self.server.store.record_decision_feedback(
                        feedback_match.group(1), false_positive
                    )
                    response = {"accepted": True}
                    status = HTTPStatus.ACCEPTED
                else:
                    raise ReceiverError(
                        HTTPStatus.NOT_FOUND, "route_not_found", "route not found"
                    )
            self._write_json(status, response)
        except ReceiverError as error:
            self._write_error(error)
        except (CorrelationError, ProtocolError) as error:
            self._write_error(
                ReceiverError(
                    HTTPStatus.CONFLICT,
                    "correlation_request_invalid",
                    str(error),
                )
            )


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
    parser.add_argument("--attestation-ttl-ms", type=int, default=300_000)
    parser.add_argument(
        "--trusted-collector",
        action="append",
        default=[],
        metavar="ID:FILE_SHA256:MAPPED_SHA256[:VERSION[:BUILD_SHA256]]",
        help="trusted collector identity and release version; may be repeated",
    )
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
    if not 10_000 <= arguments.attestation_ttl_ms <= 3_600_000:
        print("--attestation-ttl-ms must be between 10000 and 3600000", file=sys.stderr)
        return 2
    if bool(arguments.cert) != bool(arguments.key):
        print("--cert and --key must be supplied together", file=sys.stderr)
        return 2
    if not arguments.allow_insecure_http and not arguments.cert:
        print("TLS is required; supply --cert and --key", file=sys.stderr)
        return 2

    trusted_collectors: dict[str, tuple[str, ...]] = {}
    try:
        for value in arguments.trusted_collector:
            parts = value.split(":")
            if len(parts) < 3 or len(parts) > 5:
                raise ValueError("expected 3 to 5 colon-separated fields")
            collector_id, file_digest, mapped_digest = parts[:3]
            collector_version = parts[3] if len(parts) >= 4 else "0.4.0"
            build_digest = parts[4] if len(parts) >= 5 else file_digest
            if not collector_id or collector_id in trusted_collectors:
                raise ValueError("collector ID is empty or duplicated")
            if (
                not collector_version
                or len(collector_version.encode("utf-8")) > 64
                or "\x00" in collector_version
            ):
                raise ValueError("collector version is empty or too long")
            trusted_collectors[collector_id] = (
                require_sha256(file_digest, "file SHA-256"),
                require_sha256(mapped_digest, "mapped SHA-256"),
                collector_version,
                require_sha256(build_digest, "build SHA-256"),
            )
    except (ValueError, ProtocolError) as error:
        print(f"invalid --trusted-collector: {error}", file=sys.stderr)
        return 2

    store = ReceiverStore(
        arguments.database,
        arguments.heartbeat_ms,
        trusted_collectors,
        arguments.attestation_ttl_ms,
    )
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
