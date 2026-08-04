#!/usr/bin/env python3
"""Supervise collector and shipper processes without enforcing on the target."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from telemetry_shipper import ReceiverClient, RemoteRejectedError
from transport_common import ProtocolError, require_integer, require_sha256, require_string


MAX_COMMAND_ARGUMENTS = 256
MAX_ARGUMENT_LENGTH = 32_768
ATTESTATION_PLACEHOLDERS = {
    "{challenge_id}": "challenge_id",
    "{nonce}": "nonce",
    "{session_id}": "session_id",
}


class WatchdogError(RuntimeError):
    pass


class ChildProcess(Protocol):
    pid: int

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


@dataclass(frozen=True)
class ProcessSpec:
    role: str
    argv: tuple[str, ...]
    identity_path: Path
    expected_sha256: str
    require_authenticode: bool = False


@dataclass
class ManagedProcess:
    spec: ProcessSpec
    process: ChildProcess
    creation_time_ms: int
    observed_sha256: str


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _authenticode_valid(path: Path) -> bool:
    if os.name != "nt":
        return False
    environment = dict(os.environ)
    environment["AC_WATCHDOG_IDENTITY_PATH"] = str(path)
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-AuthenticodeSignature -LiteralPath "
            "$env:AC_WATCHDOG_IDENTITY_PATH).Status -eq 'Valid'",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    return result.returncode == 0 and result.stdout.strip().lower() == "true"


def _spool_server_session(database: Path) -> str | None:
    if not database.exists():
        return None
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            """
            SELECT server_session_id FROM local_sessions
             WHERE server_session_id IS NOT NULL
             ORDER BY created_at_ms DESC LIMIT 1
            """
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        connection.close()
    return None if row is None else str(row["server_session_id"])


class WatchdogSupervisor:
    """Bounded restart state machine with durable terminal notifications."""

    def __init__(
        self,
        specs: tuple[ProcessSpec, ...],
        state_path: Path,
        source_log: Path,
        session_resolver: Callable[[], str | None],
        notifier: Callable[[str, dict[str, Any]], None],
        restart_limit: int = 3,
        restart_window_ms: int = 60_000,
        process_factory: Callable[[tuple[str, ...]], ChildProcess] | None = None,
        argument_resolver: Callable[[str, tuple[str, ...]], tuple[str, ...]] | None = None,
        clock: Callable[[], int] = _now_ms,
    ) -> None:
        roles = {spec.role for spec in specs}
        if roles != {"collector", "shipper"} or len(specs) != 2:
            raise WatchdogError("exactly one collector and one shipper are required")
        if restart_limit < 0 or restart_limit > 1000 or restart_window_ms < 1000:
            raise WatchdogError("restart policy is outside safe bounds")
        self.specs = {spec.role: spec for spec in specs}
        self.state_path = state_path
        self.source_log = source_log
        self.session_resolver = session_resolver
        self.notifier = notifier
        self.restart_limit = restart_limit
        self.restart_window_ms = restart_window_ms
        self.process_factory = process_factory or self._spawn
        self.argument_resolver = argument_resolver or (lambda _role, argv: argv)
        self.clock = clock
        self.processes: dict[str, ManagedProcess] = {}
        self.state = self._load_state()

    @staticmethod
    def _spawn(argv: tuple[str, ...]) -> ChildProcess:
        return subprocess.Popen(
            argv,
            shell=False,
            close_fds=True,
            stdin=subprocess.DEVNULL,
        )

    def _load_state(self) -> dict[str, Any]:
        default = {
            "restart_timestamps_ms": [],
            "pending_terminal": [],
            "terminal_sessions": [],
            "active_session_id": None,
            "generation": 0,
            "processes": {},
        }
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return default
        except (OSError, json.JSONDecodeError) as error:
            raise WatchdogError("watchdog state is unreadable") from error
        if not isinstance(value, dict):
            raise WatchdogError("watchdog state must be an object")
        for key, fallback in default.items():
            value.setdefault(key, fallback)
        return value

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(self.state, output, sort_keys=True, separators=(",", ":"))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.state_path)
        except Exception:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise

    def _validate_identity(self, spec: ProcessSpec) -> str:
        observed = _hash_file(spec.identity_path)
        if observed != spec.expected_sha256:
            raise WatchdogError(f"{spec.role} build identity does not match policy")
        if spec.require_authenticode and not _authenticode_valid(spec.identity_path):
            raise WatchdogError(f"{spec.role} Authenticode signature is not valid")
        return observed

    def _start_role(self, role: str) -> ManagedProcess:
        spec = self.specs[role]
        observed = self._validate_identity(spec)
        argv = self.argument_resolver(role, spec.argv)
        process = self.process_factory(argv)
        managed = ManagedProcess(spec, process, self.clock(), observed)
        self.processes[role] = managed
        self.state.setdefault("processes", {})[role] = {
            "pid": int(process.pid),
            "creation_time_ms": managed.creation_time_ms,
            "observed_sha256": observed,
        }
        return managed

    def start(self) -> None:
        previous_session = self.state.get("active_session_id")
        if isinstance(previous_session, str) and previous_session:
            self._queue_terminal(
                previous_session,
                "collector_loss",
                "watchdog service restarted before a terminal transition",
            )
        self.state["generation"] = int(self.state.get("generation", 0)) + 1
        try:
            self._start_role("collector")
            self._start_role("shipper")
        except Exception:
            self.stop(mark_clean=False)
            raise
        self._refresh_session()
        self._save_state()
        self.flush_notifications()

    def _refresh_session(self) -> str | None:
        session_id = self.session_resolver()
        if session_id is not None:
            self.state["active_session_id"] = session_id
        return session_id

    def _restart_count(self, now: int) -> int:
        retained = [
            int(value)
            for value in self.state.get("restart_timestamps_ms", [])
            if now - int(value) <= self.restart_window_ms
        ]
        self.state["restart_timestamps_ms"] = retained
        return len(retained)

    def _queue_terminal(self, session_id: str, state: str, reason: str) -> None:
        terminal = set(self.state.get("terminal_sessions", []))
        if session_id in terminal:
            return
        pending = self.state.setdefault("pending_terminal", [])
        if any(item.get("session_id") == session_id for item in pending):
            return
        pending.append(
            {
                "session_id": session_id,
                "state": state,
                "reason": reason,
                "restart_count": self._restart_count(self.clock()),
                "processes": {
                    role: dict(identity)
                    for role, identity in self.state.get("processes", {}).items()
                    if isinstance(role, str) and isinstance(identity, dict)
                },
            }
        )

    def flush_notifications(self) -> None:
        pending = list(self.state.get("pending_terminal", []))
        remaining: list[dict[str, Any]] = []
        terminal = set(self.state.get("terminal_sessions", []))
        for item in pending:
            try:
                self.notifier(
                    item["session_id"],
                    {
                        "state": item["state"],
                        "reason": item["reason"],
                        "restart_count": int(item["restart_count"]),
                        "processes": item.get("processes", {}),
                    },
                )
            except (OSError, urllib.error.URLError):
                remaining.append(item)
                continue
            except RemoteRejectedError as error:
                raise WatchdogError(
                    f"receiver permanently rejected terminal state: {error}"
                ) from error
            terminal.add(item["session_id"])
        self.state["pending_terminal"] = remaining
        self.state["terminal_sessions"] = sorted(terminal)
        self._save_state()

    def poll_once(self) -> str | None:
        self._refresh_session()
        session_id = self.state.get("active_session_id")
        if isinstance(session_id, str) and session_id and not self.source_log.exists():
            self._queue_terminal(
                session_id,
                "shipper_loss",
                "collector log disappeared while the session was active",
            )

        transition: str | None = None
        notifications_flushed = False
        for role in ("collector", "shipper"):
            managed = self.processes.get(role)
            if managed is None:
                continue
            exit_code = managed.process.poll()
            if exit_code is None:
                continue
            transition = f"{role}_exit"
            if isinstance(session_id, str) and session_id:
                terminal_state = (
                    "target_exit"
                    if role == "collector" and exit_code == 0
                    else "collector_loss"
                    if role == "collector"
                    else "shipper_loss"
                )
                self._queue_terminal(
                    session_id,
                    terminal_state,
                    f"{role} exited with code {exit_code}",
                )
            if role == "collector" and exit_code == 0:
                self.processes.pop(role, None)
                self._stop_children()
                transition = "target_exit"
                break
            now = self.clock()
            restart_count = self._restart_count(now)
            if restart_count >= self.restart_limit:
                if isinstance(session_id, str) and session_id:
                    pending = self.state.setdefault("pending_terminal", [])
                    for item in pending:
                        if item.get("session_id") == session_id:
                            item["state"] = "restart_budget_exhausted"
                            item["reason"] = (
                                f"{role} restart budget exhausted after exit code {exit_code}"
                            )
                            item["restart_count"] = restart_count
                self._stop_children()
                transition = "restart_budget_exhausted"
            else:
                self.state["restart_timestamps_ms"].append(now)
                self._save_state()
                self.flush_notifications()
                notifications_flushed = True
                self._stop_children()
                try:
                    self._start_role("collector")
                    self._start_role("shipper")
                except Exception:
                    self._stop_children()
                    raise
            break
        self._save_state()
        if not notifications_flushed:
            self.flush_notifications()
        return transition

    def _stop_children(self) -> None:
        for managed in list(self.processes.values()):
            if managed.process.poll() is None:
                managed.process.terminate()
        for managed in list(self.processes.values()):
            if managed.process.poll() is not None:
                continue
            try:
                managed.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                managed.process.kill()
                managed.process.wait(timeout=5)
        self.processes.clear()

    def stop(self, mark_clean: bool = True) -> None:
        session_id = self._refresh_session()
        if mark_clean and isinstance(session_id, str) and session_id:
            self._queue_terminal(
                session_id,
                "clean_shutdown",
                "watchdog received an orderly shutdown request",
            )
            self._save_state()
            self.flush_notifications()
        self._stop_children()


def _load_spec(value: dict[str, Any], role: str, base: Path) -> ProcessSpec:
    if not isinstance(value, dict):
        raise WatchdogError(f"{role} configuration must be an object")
    argv = value.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > MAX_COMMAND_ARGUMENTS
        or any(
            not isinstance(argument, str)
            or not argument
            or len(argument) > MAX_ARGUMENT_LENGTH
            for argument in argv
        )
    ):
        raise WatchdogError(f"{role}.argv is invalid")
    identity = Path(require_string(value.get("identity_path"), "identity_path"))
    if not identity.is_absolute():
        identity = (base / identity).resolve()
    require_authenticode = value.get("require_authenticode", False)
    if not isinstance(require_authenticode, bool):
        raise WatchdogError(f"{role}.require_authenticode must be boolean")
    return ProcessSpec(
        role,
        tuple(argv),
        identity,
        require_sha256(value.get("expected_sha256"), "expected_sha256"),
        require_authenticode,
    )


def _attested_arguments(
    role: str,
    argv: tuple[str, ...],
    challenge_provider: Callable[[], dict[str, Any]],
) -> tuple[str, ...]:
    present = [placeholder for placeholder in ATTESTATION_PLACEHOLDERS if placeholder in argv]
    if not present:
        return argv
    if role != "collector" or set(present) != set(ATTESTATION_PLACEHOLDERS):
        raise WatchdogError(
            "collector argv must contain all three attestation placeholders"
        )
    if any(argv.count(placeholder) != 1 for placeholder in ATTESTATION_PLACEHOLDERS):
        raise WatchdogError("each attestation placeholder must occur exactly once")
    challenge = challenge_provider()
    replacements: dict[str, str] = {}
    expected_lengths = {"challenge_id": 32, "nonce": 64, "session_id": 32}
    for placeholder, field in ATTESTATION_PLACEHOLDERS.items():
        value = require_string(challenge.get(field), field, expected_lengths[field])
        if len(value) != expected_lengths[field] or re.fullmatch(r"[0-9a-f]+", value) is None:
            raise WatchdogError(f"receiver returned an invalid {field}")
        replacements[placeholder] = value
    return tuple(replacements.get(argument, argument) for argument in argv)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--terminal-only",
        choices=("clean_shutdown",),
        help="report an orderly terminal transition without starting children",
    )
    arguments = parser.parse_args()
    config_path = Path(arguments.config).resolve()
    supervisor: WatchdogSupervisor | None = None
    supervisor_started = False
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise WatchdogError("configuration must be an object")
        collector = _load_spec(config.get("collector"), "collector", config_path.parent)
        shipper = _load_spec(config.get("shipper"), "shipper", config_path.parent)
        state_path = Path(require_string(config.get("state_path"), "state_path"))
        source_log = Path(require_string(config.get("source_log"), "source_log"))
        spool = Path(require_string(config.get("spool"), "spool"))
        endpoint = require_string(config.get("endpoint"), "endpoint")
        token_env = require_string(config.get("token_env", "AC_RECEIVER_TOKEN"), "token_env")
        token = os.environ.get(token_env, "")
        if len(token) < 32:
            raise WatchdogError(f"{token_env} must contain at least 32 characters")
        receiver = ReceiverClient(
            endpoint,
            token,
            ca_file=config.get("ca_file"),
            client_cert=config.get("client_cert"),
            client_key=config.get("client_key"),
            allow_insecure_http=bool(config.get("allow_insecure_http", False)),
        )
        collector_id = require_string(config.get("collector_id"), "collector_id", 255)
        if arguments.terminal_only is not None:
            session_id = _spool_server_session(spool)
            if session_id is None:
                raise WatchdogError("the shipper spool has no registered session")
            receiver.request(
                f"/v1/sessions/{session_id}/terminal",
                {
                    "state": arguments.terminal_only,
                    "reason": "operator requested an orderly service shutdown",
                    "restart_count": 0,
                },
            )
            return 0
        supervisor = WatchdogSupervisor(
            (collector, shipper),
            state_path,
            source_log,
            lambda: _spool_server_session(spool),
            lambda session_id, request: receiver.request(
                f"/v1/sessions/{session_id}/terminal", request
            ),
            require_integer(config.get("restart_limit", 3), "restart_limit", 0, 1000),
            require_integer(
                config.get("restart_window_ms", 60_000),
                "restart_window_ms",
                1000,
                86_400_000,
            ),
            argument_resolver=lambda role, argv: _attested_arguments(
                role,
                argv,
                lambda: receiver.request(
                    "/v1/attestations/challenges",
                    {"collector_id": collector_id},
                ),
            ),
        )
        supervisor.start()
        supervisor_started = True
        if arguments.once:
            supervisor.poll_once()
            supervisor.stop()
            return 0
        while True:
            if supervisor.poll_once() == "target_exit":
                return 0
            time.sleep(0.5)
    except KeyboardInterrupt:
        return 0
    except (OSError, json.JSONDecodeError, ProtocolError, WatchdogError) as error:
        print(f"watchdog: {error}", file=sys.stderr)
        return 2
    finally:
        if supervisor is not None:
            supervisor.stop(mark_clean=supervisor_started)


if __name__ == "__main__":
    raise SystemExit(main())
