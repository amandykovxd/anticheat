"""Versioned, audit-first correlation rules for retained telemetry events."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from typing import Any, Iterable

from transport_common import ProtocolError, VerifiedRecord, canonical_json, require_integer


RULE_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,63}$")
RULE_MODES = frozenset({"audit_only", "active"})
MAX_REQUIRED_EVENTS = 32
MAX_WINDOW_EVENTS = 100_000


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


class CorrelationError(ValueError):
    """Raised when a rule lifecycle request is invalid or unsafe."""


class CorrelationEngine:
    """Persists raw events and emits traceable server-side decisions."""

    @staticmethod
    def initialize(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS correlation_events (
                event_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                event_seq INTEGER NOT NULL,
                event_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                pid INTEGER NOT NULL,
                details_json BLOB NOT NULL,
                raw_json BLOB NOT NULL,
                received_at_ms INTEGER NOT NULL,
                UNIQUE (session_id, event_seq),
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );
            CREATE INDEX IF NOT EXISTS correlation_events_lookup
                ON correlation_events(session_id, event_name, event_seq DESC);
            CREATE TABLE IF NOT EXISTS correlation_rule_versions (
                rule_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                definition_json BLOB NOT NULL,
                mode TEXT NOT NULL CHECK (mode IN ('audit_only', 'active')),
                min_samples INTEGER NOT NULL,
                max_false_positive_rate REAL NOT NULL,
                created_at_ms INTEGER NOT NULL,
                PRIMARY KEY (rule_id, version)
            );
            CREATE TABLE IF NOT EXISTS correlation_rule_heads (
                rule_id TEXT PRIMARY KEY,
                current_version INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                FOREIGN KEY (rule_id, current_version)
                    REFERENCES correlation_rule_versions(rule_id, version)
            );
            CREATE TABLE IF NOT EXISTS correlation_decisions (
                decision_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_version INTEGER NOT NULL,
                outcome TEXT NOT NULL,
                audit_only INTEGER NOT NULL,
                input_event_ids_json BLOB NOT NULL,
                created_at_ms INTEGER NOT NULL,
                UNIQUE (
                    session_id, rule_id, rule_version, input_event_ids_json
                ),
                FOREIGN KEY (session_id) REFERENCES sessions(session_id),
                FOREIGN KEY (rule_id, rule_version)
                    REFERENCES correlation_rule_versions(rule_id, version)
            );
            CREATE TABLE IF NOT EXISTS correlation_feedback (
                decision_id TEXT PRIMARY KEY,
                false_positive INTEGER NOT NULL,
                recorded_at_ms INTEGER NOT NULL,
                FOREIGN KEY (decision_id)
                    REFERENCES correlation_decisions(decision_id)
            );
            CREATE TABLE IF NOT EXISTS correlation_rule_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                rule_version INTEGER NOT NULL,
                action TEXT NOT NULL,
                details_json BLOB NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            """
        )

    @staticmethod
    def _validated_definition(definition: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(definition, dict):
            raise CorrelationError("rule definition must be an object")
        rule_id = definition.get("rule_id")
        if not isinstance(rule_id, str) or RULE_ID_RE.fullmatch(rule_id) is None:
            raise CorrelationError("rule_id has an invalid format")
        try:
            version = require_integer(definition.get("version"), "version", 1)
            window_events = require_integer(
                definition.get("window_events", 4096),
                "window_events",
                1,
                MAX_WINDOW_EVENTS,
            )
            min_samples = require_integer(
                definition.get("min_samples", 100), "min_samples", 1, 1_000_000
            )
        except ProtocolError as error:
            raise CorrelationError(str(error)) from error
        required_events = definition.get("required_events")
        if (
            not isinstance(required_events, list)
            or not required_events
            or len(required_events) > MAX_REQUIRED_EVENTS
            or any(
                not isinstance(name, str) or not name or len(name) > 255
                for name in required_events
            )
            or len(set(required_events)) != len(required_events)
        ):
            raise CorrelationError("required_events must contain unique event names")
        outcome = definition.get("outcome", "suspicious_session")
        if not isinstance(outcome, str) or not outcome or len(outcome) > 128:
            raise CorrelationError("outcome has an invalid format")
        maximum_rate = definition.get("max_false_positive_rate", 0.01)
        if (
            isinstance(maximum_rate, bool)
            or not isinstance(maximum_rate, (int, float))
            or not 0.0 <= float(maximum_rate) <= 1.0
        ):
            raise CorrelationError("max_false_positive_rate must be between 0 and 1")
        require_attestation = definition.get("require_attestation", False)
        if not isinstance(require_attestation, bool):
            raise CorrelationError("require_attestation must be a boolean")
        return {
            "rule_id": rule_id,
            "version": version,
            "required_events": required_events,
            "window_events": window_events,
            "outcome": outcome,
            "require_attestation": require_attestation,
            "min_samples": min_samples,
            "max_false_positive_rate": float(maximum_rate),
        }

    @classmethod
    def install_rule(
        cls,
        connection: sqlite3.Connection,
        definition: dict[str, Any],
        now_ms: int | None = None,
    ) -> dict[str, Any]:
        normalized = cls._validated_definition(definition)
        now = _now_ms() if now_ms is None else now_ms
        rule_id = normalized["rule_id"]
        version = normalized["version"]
        existing = connection.execute(
            "SELECT 1 FROM correlation_rule_versions WHERE rule_id = ? AND version = ?",
            (rule_id, version),
        ).fetchone()
        if existing is not None:
            raise CorrelationError("rule version is immutable and already exists")
        current = connection.execute(
            "SELECT current_version FROM correlation_rule_heads WHERE rule_id = ?",
            (rule_id,),
        ).fetchone()
        if current is not None and version <= int(current["current_version"]):
            raise CorrelationError("new rule version must increase monotonically")
        encoded = canonical_json(normalized)
        connection.execute(
            """
            INSERT INTO correlation_rule_versions (
                rule_id, version, definition_json, mode, min_samples,
                max_false_positive_rate, created_at_ms
            ) VALUES (?, ?, ?, 'audit_only', ?, ?, ?)
            """,
            (
                rule_id,
                version,
                encoded,
                normalized["min_samples"],
                normalized["max_false_positive_rate"],
                now,
            ),
        )
        connection.execute(
            """
            INSERT INTO correlation_rule_heads (rule_id, current_version, updated_at_ms)
            VALUES (?, ?, ?)
            ON CONFLICT(rule_id) DO UPDATE SET
                current_version = excluded.current_version,
                updated_at_ms = excluded.updated_at_ms
            """,
            (rule_id, version, now),
        )
        cls._audit(connection, rule_id, version, "installed_audit_only", {}, now)
        return cls.rule_status(connection, rule_id)

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        rule_id: str,
        version: int,
        action: str,
        details: dict[str, Any],
        now: int,
    ) -> None:
        connection.execute(
            """
            INSERT INTO correlation_rule_audit (
                rule_id, rule_version, action, details_json, created_at_ms
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (rule_id, version, action, canonical_json(details), now),
        )

    @classmethod
    def record_feedback(
        cls,
        connection: sqlite3.Connection,
        decision_id: str,
        false_positive: bool,
        now_ms: int | None = None,
    ) -> None:
        if not isinstance(false_positive, bool):
            raise CorrelationError("false_positive must be a boolean")
        decision = connection.execute(
            "SELECT rule_id, rule_version FROM correlation_decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        if decision is None:
            raise CorrelationError("decision does not exist")
        now = _now_ms() if now_ms is None else now_ms
        connection.execute(
            """
            INSERT INTO correlation_feedback (decision_id, false_positive, recorded_at_ms)
            VALUES (?, ?, ?)
            ON CONFLICT(decision_id) DO UPDATE SET
                false_positive = excluded.false_positive,
                recorded_at_ms = excluded.recorded_at_ms
            """,
            (decision_id, int(false_positive), now),
        )
        cls._audit(
            connection,
            decision["rule_id"],
            int(decision["rule_version"]),
            "feedback_recorded",
            {"decision_id": decision_id, "false_positive": false_positive},
            now,
        )

    @classmethod
    def promote_rule(
        cls,
        connection: sqlite3.Connection,
        rule_id: str,
        now_ms: int | None = None,
    ) -> dict[str, Any]:
        status = cls.rule_status(connection, rule_id)
        if status["mode"] == "active":
            return status
        if status["reviewed_count"] < status["min_samples"]:
            raise CorrelationError("rule has not reached its reviewed sample count")
        if status["false_positive_rate"] > status["max_false_positive_rate"]:
            raise CorrelationError("rule exceeds its false-positive threshold")
        now = _now_ms() if now_ms is None else now_ms
        connection.execute(
            """
            UPDATE correlation_rule_versions SET mode = 'active'
             WHERE rule_id = ? AND version = ?
            """,
            (rule_id, status["version"]),
        )
        cls._audit(
            connection,
            rule_id,
            status["version"],
            "promoted_after_metrics",
            {
                "decision_count": status["decision_count"],
                "reviewed_count": status["reviewed_count"],
                "false_positive_rate": status["false_positive_rate"],
            },
            now,
        )
        return cls.rule_status(connection, rule_id)

    @classmethod
    def rollback_rule(
        cls,
        connection: sqlite3.Connection,
        rule_id: str,
        target_version: int,
        now_ms: int | None = None,
    ) -> dict[str, Any]:
        target = connection.execute(
            """
            SELECT 1 FROM correlation_rule_versions
             WHERE rule_id = ? AND version = ?
            """,
            (rule_id, target_version),
        ).fetchone()
        if target is None:
            raise CorrelationError("rollback target does not exist")
        now = _now_ms() if now_ms is None else now_ms
        previous = cls.rule_status(connection, rule_id)["version"]
        connection.execute(
            """
            UPDATE correlation_rule_heads
               SET current_version = ?, updated_at_ms = ?
             WHERE rule_id = ?
            """,
            (target_version, now, rule_id),
        )
        cls._audit(
            connection,
            rule_id,
            target_version,
            "rolled_back",
            {"from_version": previous},
            now,
        )
        return cls.rule_status(connection, rule_id)

    @staticmethod
    def rule_status(connection: sqlite3.Connection, rule_id: str) -> dict[str, Any]:
        row = connection.execute(
            """
            SELECT v.* FROM correlation_rule_heads AS h
            JOIN correlation_rule_versions AS v
              ON v.rule_id = h.rule_id AND v.version = h.current_version
            WHERE h.rule_id = ?
            """,
            (rule_id,),
        ).fetchone()
        if row is None:
            raise CorrelationError("rule does not exist")
        metrics = connection.execute(
            """
            SELECT COUNT(*) AS decisions,
                   COALESCE(SUM(CASE WHEN f.false_positive = 1 THEN 1 ELSE 0 END), 0)
                       AS false_positives,
                   COUNT(f.decision_id) AS reviewed
              FROM correlation_decisions AS d
              LEFT JOIN correlation_feedback AS f USING (decision_id)
             WHERE d.rule_id = ? AND d.rule_version = ?
            """,
            (rule_id, row["version"]),
        ).fetchone()
        reviewed = int(metrics["reviewed"])
        false_positives = int(metrics["false_positives"])
        return {
            "rule_id": rule_id,
            "version": int(row["version"]),
            "mode": row["mode"],
            "decision_count": int(metrics["decisions"]),
            "reviewed_count": reviewed,
            "false_positive_count": false_positives,
            "false_positive_rate": false_positives / reviewed if reviewed else 0.0,
            "min_samples": int(row["min_samples"]),
            "max_false_positive_rate": float(row["max_false_positive_rate"]),
        }

    @staticmethod
    def _active_rules(connection: sqlite3.Connection) -> Iterable[sqlite3.Row]:
        return connection.execute(
            """
            SELECT v.* FROM correlation_rule_heads AS h
            JOIN correlation_rule_versions AS v
              ON v.rule_id = h.rule_id AND v.version = h.current_version
            ORDER BY v.rule_id
            """
        ).fetchall()

    @classmethod
    def retain_and_correlate(
        cls,
        connection: sqlite3.Connection,
        session: sqlite3.Row,
        records: list[VerifiedRecord],
        now_ms: int,
    ) -> list[str]:
        for record in records:
            event_id = f"{session['session_id']}:{record.sequence}"
            details = record.document.get("details")
            severity_value = record.document.get("severity", "unknown")
            severity = (
                severity_value
                if isinstance(severity_value, str) and len(severity_value) <= 32
                else "unknown"
            )
            pid_value = record.document.get("pid", 0)
            pid = (
                pid_value
                if isinstance(pid_value, int)
                and not isinstance(pid_value, bool)
                and 0 <= pid_value <= 0xFFFFFFFF
                else 0
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO correlation_events (
                    event_id, session_id, event_seq, event_name, severity, pid,
                    details_json, raw_json, received_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    session["session_id"],
                    record.sequence,
                    record.event,
                    severity,
                    pid,
                    canonical_json(details),
                    record.raw,
                    now_ms,
                ),
            )

        created: list[str] = []
        last_sequence = records[-1].sequence
        for rule in cls._active_rules(connection):
            definition = json.loads(bytes(rule["definition_json"]).decode("utf-8"))
            if (
                definition["require_attestation"]
                and int(session["attestation_verified"]) != 1
            ):
                continue
            minimum_sequence = max(1, last_sequence - definition["window_events"] + 1)
            inputs: list[str] = []
            for event_name in definition["required_events"]:
                event = connection.execute(
                    """
                    SELECT event_id FROM correlation_events
                     WHERE session_id = ? AND event_name = ? AND event_seq >= ?
                     ORDER BY event_seq DESC LIMIT 1
                    """,
                    (session["session_id"], event_name, minimum_sequence),
                ).fetchone()
                if event is None:
                    inputs = []
                    break
                inputs.append(event["event_id"])
            if not inputs:
                continue
            inputs.sort()
            encoded_inputs = canonical_json(inputs)
            decision_id = hashlib.sha256(
                canonical_json(
                    {
                        "session_id": session["session_id"],
                        "rule_id": rule["rule_id"],
                        "version": int(rule["version"]),
                        "inputs": inputs,
                    }
                )
            ).hexdigest()
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO correlation_decisions (
                    decision_id, session_id, rule_id, rule_version, outcome,
                    audit_only, input_event_ids_json, created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    session["session_id"],
                    rule["rule_id"],
                    int(rule["version"]),
                    definition["outcome"],
                    int(rule["mode"] == "audit_only"),
                    encoded_inputs,
                    now_ms,
                ),
            )
            if cursor.rowcount == 1:
                created.append(decision_id)
        return created

    @staticmethod
    def decisions(connection: sqlite3.Connection, session_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            """
            SELECT * FROM correlation_decisions
             WHERE session_id = ? ORDER BY created_at_ms, decision_id
            """,
            (session_id,),
        ).fetchall()
        return [
            {
                "decision_id": row["decision_id"],
                "session_id": row["session_id"],
                "rule_id": row["rule_id"],
                "rule_version": int(row["rule_version"]),
                "outcome": row["outcome"],
                "audit_only": bool(row["audit_only"]),
                "input_event_ids": json.loads(
                    bytes(row["input_event_ids_json"]).decode("utf-8")
                ),
            }
            for row in rows
        ]
