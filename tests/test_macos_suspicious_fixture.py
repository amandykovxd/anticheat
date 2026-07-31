#!/usr/bin/env python3
"""Exercise macOS anonymous executable-region detection end to end."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    fixture = subprocess.Popen(
        [
            sys.executable,
            str(arguments.fixture),
            "--mode",
            "rx",
            "--duration",
            "30",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        assert fixture.stdout is not None
        identity_line = fixture.stdout.readline()
        if not identity_line:
            assert fixture.stderr is not None
            raise RuntimeError(f"fixture failed to start: {fixture.stderr.read()}")
        identity = json.loads(identity_line)

        with tempfile.TemporaryDirectory(prefix="anticheat-macos-fixture-") as directory:
            log_path = Path(directory) / "events.jsonl"
            result = subprocess.run(
                [
                    str(arguments.collector),
                    "--pid",
                    str(identity["pid"]),
                    "--once",
                    "--quiet",
                    "--log",
                    str(log_path),
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
                for line in log_path.read_text(encoding="utf-8").splitlines()
                if line
            ]

        anomalies = [
            event
            for event in events
            if event.get("event") == "executable_region_anomaly"
            and event.get("details", {}).get("anonymous") is True
        ]
        if not anomalies:
            raise RuntimeError("collector did not report the anonymous RX mapping")

        summaries = [
            event for event in events if event.get("event") == "scan_completed"
        ]
        if len(summaries) != 1:
            raise RuntimeError("collector did not emit exactly one scan summary")
        details = summaries[0]["details"]
        if details.get("anonymous_executable", 0) < 1 or not details.get("complete"):
            raise RuntimeError("scan summary does not account for the fixture mapping")
    finally:
        fixture.terminate()
        try:
            fixture.wait(timeout=5)
        except subprocess.TimeoutExpired:
            fixture.kill()
            fixture.wait(timeout=5)
        if fixture.stdout is not None:
            fixture.stdout.close()
        if fixture.stderr is not None:
            fixture.stderr.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
