---
layout: default
title: Watchdog Service Integration
---

# Watchdog service integration

## Purpose and boundary

`anticheat_watchdog_service.exe` is a Windows SCM host for
`tools/session_watchdog.py`. The service supervises exactly one collector and
one telemetry shipper, verifies their configured SHA-256 identities before
every launch, applies a bounded restart policy, and reports terminal session
state to the remote receiver. It does not open, suspend, terminate, or modify
the protected target.

The native host runs as `LocalSystem`, removes nonessential token privileges
from the child token,
starts the Python supervisor in a kill-on-close job object, and reports service
failures through the Windows event log. Production policy should set
`require_authenticode` for the collector and shipper identity files and must
protect the installation, configuration, state, spool, and log paths with ACLs.

This service increases the cost of a user-mode collector kill. It is not an
independent trust boundary against an administrator or a hostile kernel driver.
Remote heartbeat expiry remains authoritative when the local host cannot send a
terminal transition.

## Configuration

Use an absolute path for runtime state. Relative `identity_path` values resolve
against the configuration file directory. Each command is an argument array;
no command shell is used.

```json
{
  "collector_id": "launcher-node-017",
  "collector": {
    "argv": [
      "C:\\Program Files\\Anticheat\\bin\\anticheat.exe",
      "--pid", "1234",
      "--kernel", "--require-kernel", "--require-attestation",
      "--attestation-challenge", "{challenge_id}",
      "--attestation-nonce", "{nonce}",
      "--attestation-session", "{session_id}",
      "--log", "C:\\ProgramData\\Anticheat\\events.jsonl"
    ],
    "identity_path": "C:\\Program Files\\Anticheat\\bin\\anticheat.exe",
    "expected_sha256": "<64-lowercase-hex-release-digest>",
    "require_authenticode": true
  },
  "shipper": {
    "argv": [
      "C:\\Program Files\\Python311\\python.exe",
      "C:\\Program Files\\Anticheat\\tools\\telemetry_shipper.py",
      "--log", "C:\\ProgramData\\Anticheat\\events.jsonl",
      "--spool", "C:\\ProgramData\\Anticheat\\transport.sqlite3",
      "--endpoint", "https://telemetry.example.internal:8443",
      "--collector-id", "launcher-node-017",
      "--ca-file", "C:\\ProgramData\\Anticheat\\receiver-ca.pem"
    ],
    "identity_path": "C:\\Program Files\\Anticheat\\tools\\telemetry_shipper.py",
    "expected_sha256": "<64-lowercase-hex-release-digest>",
    "require_authenticode": false
  },
  "state_path": "C:\\ProgramData\\Anticheat\\watchdog\\state.json",
  "source_log": "C:\\ProgramData\\Anticheat\\events.jsonl",
  "spool": "C:\\ProgramData\\Anticheat\\transport.sqlite3",
  "endpoint": "https://telemetry.example.internal:8443",
  "token_env": "AC_RECEIVER_TOKEN",
  "ca_file": "C:\\ProgramData\\Anticheat\\receiver-ca.pem",
  "restart_limit": 3,
  "restart_window_ms": 60000
}
```

The three attestation placeholders are mandatory as a set. The supervisor
requests a new receiver challenge immediately before each collector launch and
replaces each placeholder exactly once. A stale nonce is therefore not reused
after a crash or service restart.

`identity_path` identifies the executable content being authorized. For a
Python shipper it should identify the shipped script, while the Python runtime
and imported tools must also be pinned and ACL-protected by the deployment
package. A production signed manifest should replace standalone configured
hashes when issue #12 is complete.

## Installation

Install Python and the release package under administrator-controlled paths.
Provision `AC_RECEIVER_TOKEN` for the service through the deployment secret
manager; do not store it in the JSON file or command line. Grant `SYSTEM` read
access to binaries and configuration and modify access only to the state,
spool, and log directories.

From elevated PowerShell:

```powershell
tools\windows\Install-WatchdogService.ps1 `
  -ServiceBinary 'C:\Program Files\Anticheat\bin\anticheat_watchdog_service.exe' `
  -PythonExecutable 'C:\Program Files\Python311\python.exe' `
  -WatchdogScript 'C:\Program Files\Anticheat\tools\session_watchdog.py' `
  -Config 'C:\ProgramData\Anticheat\watchdog.json' `
  -WorkingDirectory 'C:\Program Files\Anticheat' `
  -StateDirectory 'C:\ProgramData\Anticheat\watchdog'
```

The installer rejects binaries or configuration writable by `Everyone`,
`Authenticated Users`, or the built-in `Users` group. It creates a restricted
state directory, installs a delayed automatic service, enables a restricted
service SID, and configures two bounded SCM restarts.

## Update and removal

Use `Update-WatchdogService.ps1` with the same path arguments after staging and
verifying a complete release. The script first reports `clean_shutdown`, stops
the old service, updates the SCM image path, and starts the new service. A
failed terminal notification aborts the update unless the operator explicitly
uses `-SkipTerminalNotification`; that exception must be recorded as an
incident because the receiver will classify the old session by heartbeat
timeout.

Use `Uninstall-WatchdogService.ps1` to report the terminal transition and
remove the service registration. Removal intentionally preserves telemetry,
the SQLite spool, receiver anchors, watchdog state, and Windows event logs.

## Server state model

The receiver exposes the current state through `GET /v1/sessions/{id}` and
retains every transition in `session_transitions`.

| State | Source | Meaning |
| --- | --- | --- |
| `clean_shutdown` | operator/watchdog | Planned service stop was remotely acknowledged. |
| `target_exit` | watchdog | Collector exited successfully because its target ended. |
| `collector_loss` | watchdog | Collector failed or the watchdog restarted with an active session. |
| `shipper_loss` | watchdog | Shipper failed or the active local event log disappeared. |
| `heartbeat_timeout` | receiver | The authoritative heartbeat deadline expired. |
| `restart_budget_exhausted` | watchdog | Local restart limit was reached. |

Terminal transitions are idempotent only when state and reason match. Once a
session is terminal, the receiver rejects new batches and heartbeats. Network
failures leave the notification in a mode-0600 durable queue for retry.

## Verification

Run the state-machine suite directly:

```text
python -m unittest -v tests/test_watchdog.py
```

The tests cover process identity, collector and shipper failure, successful
target exit, orderly shutdown, service restart, receiver outage recovery, log
deletion, restart exhaustion, and fresh attestation argument replacement.
