"""Shared protocol primitives for remote anticheat telemetry anchoring."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable


PROTOCOL_VERSION = 1
SUPPORTED_SCHEMA_VERSIONS = frozenset({4, 5})
CHAIN_ALGORITHM = "sha256"
CHAIN_MARKER = b',"chain":"'
CHAIN_HEX_LENGTH = 64
SESSION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
CLIENT_SESSION_ID_RE = re.compile(r"^[0-9a-f-]{16,64}$")


class ProtocolError(ValueError):
    """Raised when a request or retained event violates the wire protocol."""


@dataclass(frozen=True)
class VerifiedRecord:
    raw: bytes
    sequence: int
    event: str
    chain: str
    document: dict[str, Any]


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def payload_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def require_integer(
    value: Any,
    name: str,
    minimum: int = 0,
    maximum: int = (1 << 63) - 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ProtocolError(f"{name} is outside the accepted range")
    return value


def require_string(value: Any, name: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ProtocolError(f"{name} must be a non-empty string")
    return value


def require_sha256(value: Any, name: str) -> str:
    text = require_string(value, name, CHAIN_HEX_LENGTH)
    if len(text) != CHAIN_HEX_LENGTH:
        raise ProtocolError(f"{name} must contain 64 hexadecimal characters")
    try:
        bytes.fromhex(text)
    except ValueError as error:
        raise ProtocolError(f"{name} must contain hexadecimal characters") from error
    if text.lower() != text:
        raise ProtocolError(f"{name} must use lowercase hexadecimal characters")
    return text


def split_record(raw: bytes) -> tuple[bytes, str]:
    line = raw.rstrip(b"\r\n")
    marker_offset = line.rfind(CHAIN_MARKER)
    if marker_offset < 0:
        raise ProtocolError("event record is missing the chain suffix")

    suffix = line[marker_offset + len(CHAIN_MARKER) :]
    if len(suffix) != CHAIN_HEX_LENGTH + 2 or suffix[-2:] != b'"}':
        raise ProtocolError("event record has a malformed chain suffix")

    try:
        chain = suffix[:CHAIN_HEX_LENGTH].decode("ascii")
    except UnicodeDecodeError as error:
        raise ProtocolError("event chain is not ASCII") from error
    require_sha256(chain, "event.chain")
    return line[:marker_offset], chain


def decode_record(raw: bytes) -> dict[str, Any]:
    line = raw.rstrip(b"\r\n")
    try:
        value = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("event record is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ProtocolError("event record must be a JSON object")
    return value


def chain_seed_from_open_record(raw: bytes, schema_version: int) -> str:
    document = decode_record(raw)
    if document.get("event") != "log_segment_opened":
        raise ProtocolError("a session must begin with log_segment_opened")
    if require_integer(document.get("seq"), "event.seq", 1) != 1:
        raise ProtocolError("the first event sequence must be 1")
    details = document.get("details")
    if not isinstance(details, dict):
        raise ProtocolError("log_segment_opened.details must be an object")
    if require_integer(details.get("schema"), "details.schema", 1) != schema_version:
        raise ProtocolError("event schema does not match the session schema")
    return require_sha256(details.get("chain_seed"), "details.chain_seed")


def verify_record(raw: bytes, previous_chain: str, expected_sequence: int) -> VerifiedRecord:
    body, recorded_chain = split_record(raw)
    document = decode_record(raw)
    sequence = require_integer(document.get("seq"), "event.seq", 1)
    if sequence != expected_sequence:
        raise ProtocolError(
            f"event sequence mismatch: expected {expected_sequence}, received {sequence}"
        )
    event = require_string(document.get("event"), "event.event", 255)
    expected_chain = hashlib.sha256(bytes.fromhex(previous_chain) + body).hexdigest()
    if recorded_chain != expected_chain:
        raise ProtocolError(f"event chain mismatch at sequence {sequence}")
    return VerifiedRecord(raw.rstrip(b"\r\n"), sequence, event, recorded_chain, document)


def verify_batch_records(
    records: Iterable[str],
    previous_chain: str,
    first_event_sequence: int,
) -> tuple[list[VerifiedRecord], str]:
    chain = require_sha256(previous_chain, "previous_chain")
    sequence = require_integer(first_event_sequence, "first_event_seq", 1)
    verified: list[VerifiedRecord] = []

    for encoded in records:
        if not isinstance(encoded, str):
            raise ProtocolError("batch records must be JSON strings")
        record = verify_record(encoded.encode("utf-8"), chain, sequence)
        verified.append(record)
        chain = record.chain
        sequence += 1

    if not verified:
        raise ProtocolError("a batch must contain at least one record")
    return verified, chain
