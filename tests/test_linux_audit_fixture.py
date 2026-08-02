#!/usr/bin/env python3
"""Exercise auditd process_vm access ingestion and fail-closed startup."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector", type=Path, required=True)
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="anticheat-linux-audit-") as directory:
        root = Path(directory)
        audit_log = root / "audit.log"
        event_log = root / "events.jsonl"
        target_pid = os.getpid()
        audit_log.write_text(
            "type=SYSCALL msg=audit(1785686400.001:42): "
            "arch=c000003e syscall=311 success=yes exit=8 "
            f"a0={target_pid:x} a1=0 a2=0 a3=0 items=0 ppid=1 pid=4242 "
            'comm="fixture" exe="/tmp/fixture" key="anticheat_process_vm"\n',
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                str(arguments.collector),
                "--pid",
                str(target_pid),
                "--audit-log",
                str(audit_log),
                "--require-kernel-audit",
                "--once",
                "--quiet",
                "--log",
                str(event_log),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"collector exited with {result.returncode}: {result.stderr}"
            )
        events = [
            json.loads(line)
            for line in event_log.read_text(encoding="utf-8").splitlines()
            if line
        ]
        signals = [
            event
            for event in events
            if event.get("event") == "linux_process_vm_access_observed"
        ]
        if len(signals) != 1:
            raise RuntimeError("collector did not retain the synthetic audit signal")
        details = signals[0].get("details", {})
        if (
            signals[0].get("severity") != "high"
            or details.get("actor_pid") != 4242
            or details.get("operation") != "process_vm_writev"
            or details.get("success") is not True
        ):
            raise RuntimeError("audit signal fields were not classified correctly")

        missing_result = subprocess.run(
            [
                str(arguments.collector),
                "--pid",
                str(target_pid),
                "--audit-log",
                str(root / "missing-audit.log"),
                "--require-kernel-audit",
                "--once",
                "--quiet",
                "--log",
                str(root / "missing-events.jsonl"),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if missing_result.returncode != 6:
            raise RuntimeError("required missing audit source did not fail closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
