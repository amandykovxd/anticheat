#!/usr/bin/env python3
"""Exercise Linux anonymous executable-mapping detection end to end."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    arguments = parser.parse_args()

    fixture = subprocess.Popen(
        [sys.executable, str(arguments.fixture)],
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

        with tempfile.TemporaryDirectory(prefix="anticheat-linux-fixture-") as directory:
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

        findings = [
            event
            for event in events
            if event.get("event") == "linux_suspicious_executable_mapping"
            and event.get("details", {}).get("anonymous") is True
        ]
        if not findings:
            raise RuntimeError("collector did not report the anonymous RX mapping")
        summaries = [event for event in events if event.get("event") == "scan_completed"]
        if len(summaries) != 1 or summaries[0]["details"].get(
            "suspicious_mappings", 0
        ) < 1:
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
