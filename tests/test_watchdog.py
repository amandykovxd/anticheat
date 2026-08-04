#!/usr/bin/env python3
"""Integration-level state-machine tests for the privileged watchdog sidecar."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from session_watchdog import (  # noqa: E402
    ProcessSpec,
    WatchdogError,
    WatchdogSupervisor,
    _attested_arguments,
)


class FakeProcess:
    next_pid = 4000

    def __init__(self) -> None:
        self.pid = FakeProcess.next_pid
        FakeProcess.next_pid += 1
        self.exit_code: int | None = None

    def poll(self) -> int | None:
        return self.exit_code

    def terminate(self) -> None:
        self.exit_code = 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.exit_code is None:
            self.exit_code = 0
        return self.exit_code

    def kill(self) -> None:
        self.exit_code = -9


class FakeFactory:
    def __init__(self) -> None:
        self.started: list[tuple[tuple[str, ...], FakeProcess]] = []

    def __call__(self, argv: tuple[str, ...]) -> FakeProcess:
        process = FakeProcess()
        self.started.append((argv, process))
        return process


class WatchdogSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.collector = self.directory / "collector.exe"
        self.shipper = self.directory / "shipper.py"
        self.collector.write_bytes(b"collector-build")
        self.shipper.write_bytes(b"shipper-build")
        self.log = self.directory / "events.jsonl"
        self.log.write_text("active\n", encoding="utf-8")
        self.state = self.directory / "watchdog-state.json"
        self.session_id = "a" * 32
        self.factory = FakeFactory()
        self.notifications: list[tuple[str, dict[str, Any]]] = []
        self.clock_value = 1_000_000

    @staticmethod
    def _digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _supervisor(
        self,
        notifier: Any | None = None,
        restart_limit: int = 3,
    ) -> WatchdogSupervisor:
        specs = (
            ProcessSpec(
                "collector",
                ("collector", "--run"),
                self.collector,
                self._digest(self.collector),
            ),
            ProcessSpec(
                "shipper",
                ("shipper", "--run"),
                self.shipper,
                self._digest(self.shipper),
            ),
        )
        return WatchdogSupervisor(
            specs,
            self.state,
            self.log,
            lambda: self.session_id,
            notifier
            or (lambda session_id, request: self.notifications.append(
                (session_id, request)
            )),
            restart_limit=restart_limit,
            process_factory=self.factory,
            clock=lambda: self.clock_value,
        )

    def test_collector_crash_is_terminal_and_restarted_with_identity(self) -> None:
        supervisor = self._supervisor()
        supervisor.start()
        original = supervisor.processes["collector"]
        self.assertEqual(original.observed_sha256, self._digest(self.collector))
        self.assertEqual(original.creation_time_ms, self.clock_value)
        assert isinstance(original.process, FakeProcess)
        original.process.exit_code = 17
        self.clock_value += 1000
        self.assertEqual(supervisor.poll_once(), "collector_exit")
        self.assertNotEqual(
            supervisor.processes["collector"].process.pid,
            original.process.pid,
        )
        self.assertEqual(len(self.factory.started), 4)
        self.assertEqual(self.notifications[0][1]["state"], "collector_loss")
        self.assertIn("code 17", self.notifications[0][1]["reason"])

    def test_shipper_crash_is_terminal_and_restarted(self) -> None:
        supervisor = self._supervisor()
        supervisor.start()
        collector = supervisor.processes["collector"].process
        process = supervisor.processes["shipper"].process
        assert isinstance(collector, FakeProcess)
        assert isinstance(process, FakeProcess)
        process.exit_code = 23
        self.assertEqual(supervisor.poll_once(), "shipper_exit")
        self.assertEqual(self.notifications[0][1]["state"], "shipper_loss")
        self.assertNotEqual(
            supervisor.processes["collector"].process.pid,
            collector.pid,
        )
        self.assertEqual(len(self.factory.started), 4)

    def test_clean_collector_exit_reports_target_exit_without_restart(self) -> None:
        supervisor = self._supervisor()
        supervisor.start()
        process = supervisor.processes["collector"].process
        assert isinstance(process, FakeProcess)
        process.exit_code = 0
        self.assertEqual(supervisor.poll_once(), "target_exit")
        self.assertEqual(self.notifications[0][1]["state"], "target_exit")
        self.assertEqual(supervisor.processes, {})
        self.assertEqual(len(self.factory.started), 2)

    def test_orderly_stop_reports_clean_shutdown(self) -> None:
        supervisor = self._supervisor()
        supervisor.start()
        supervisor.stop()
        self.assertEqual(self.notifications[0][1]["state"], "clean_shutdown")

    def test_service_restart_invalidates_previous_active_session(self) -> None:
        self.state.write_text(
            json.dumps(
                {
                    "restart_timestamps_ms": [],
                    "pending_terminal": [],
                    "terminal_sessions": [],
                    "active_session_id": self.session_id,
                    "generation": 4,
                }
            ),
            encoding="utf-8",
        )
        supervisor = self._supervisor()
        supervisor.start()
        self.assertEqual(self.notifications[0][1]["state"], "collector_loss")
        self.assertIn("service restarted", self.notifications[0][1]["reason"])
        persisted = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(persisted["generation"], 5)
        self.assertEqual(
            persisted["processes"]["collector"]["observed_sha256"],
            self._digest(self.collector),
        )

    def test_network_outage_retains_terminal_notification(self) -> None:
        attempts = 0

        def flaky(session_id: str, request: dict[str, Any]) -> None:
            nonlocal attempts
            del session_id
            attempts += 1
            if attempts == 1:
                raise OSError("network unavailable")
            self.notifications.append((self.session_id, request))

        supervisor = self._supervisor(flaky)
        supervisor.start()
        process = supervisor.processes["collector"].process
        assert isinstance(process, FakeProcess)
        process.exit_code = 1
        supervisor.poll_once()
        persisted = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(len(persisted["pending_terminal"]), 1)
        supervisor.flush_notifications()
        self.assertEqual(len(self.notifications), 1)
        persisted = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(persisted["pending_terminal"], [])

    def test_local_log_deletion_is_reported_as_shipper_loss(self) -> None:
        supervisor = self._supervisor()
        supervisor.start()
        self.log.unlink()
        supervisor.poll_once()
        self.assertEqual(self.notifications[0][1]["state"], "shipper_loss")
        self.assertIn("log disappeared", self.notifications[0][1]["reason"])

    def test_restart_budget_exhaustion_is_terminal(self) -> None:
        supervisor = self._supervisor(restart_limit=0)
        supervisor.start()
        process = supervisor.processes["collector"].process
        assert isinstance(process, FakeProcess)
        process.exit_code = 9
        self.assertEqual(supervisor.poll_once(), "restart_budget_exhausted")
        self.assertEqual(
            self.notifications[0][1]["state"], "restart_budget_exhausted"
        )

    def test_modified_binary_is_rejected_before_launch(self) -> None:
        supervisor = self._supervisor()
        self.collector.write_bytes(b"modified")
        with self.assertRaisesRegex(Exception, "identity does not match"):
            supervisor.start()
        self.assertEqual(self.factory.started, [])

    def test_attestation_placeholders_are_refreshed_atomically(self) -> None:
        argv = (
            "collector",
            "--attestation-challenge",
            "{challenge_id}",
            "--attestation-nonce",
            "{nonce}",
            "--attestation-session",
            "{session_id}",
        )
        resolved = _attested_arguments(
            "collector",
            argv,
            lambda: {
                "challenge_id": "1" * 32,
                "nonce": "2" * 64,
                "session_id": "3" * 32,
            },
        )
        self.assertEqual(resolved[2], "1" * 32)
        self.assertEqual(resolved[4], "2" * 64)
        self.assertEqual(resolved[6], "3" * 32)

    def test_partial_attestation_placeholders_are_rejected(self) -> None:
        with self.assertRaisesRegex(WatchdogError, "all three"):
            _attested_arguments(
                "collector",
                ("collector", "{nonce}"),
                lambda: {},
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
