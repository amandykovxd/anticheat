# Security Operations

## Deployment controls

- Run the kernel-enabled collector as `SYSTEM` or local Administrator.
- Restrict log directories to the collector and forwarding service.
- Sign driver packages outside source control and general CI workers.
- Retain release hashes, symbols, INF, catalog, and signing evidence.
- Test upgrades, rollback, unload, and reboot-required states.
- Treat local administrator compromise as compromise of both components.

## Required monitoring

Alert on:

- `kernel_event_queue_overflow`;
- `kernel_event_sequence_gap`;
- `kernel_callback_health_degraded`;
- `kernel_correlation_coverage_gap`;
- repeated `kernel_event_read_failed`;
- `kernel_user_module_mismatch` correlated with target lifetime;
- `scan_completed` with `complete:false`;
- missing `scan_completed` cadence;
- process identity mismatch;
- collector sequence reset during an active session;
- driver protocol mismatch;
- complete log-segment deletion or unexpected rotation;
- collector or driver binary identity changes.

Reject kernel evidence for sessions whose final
`kernel_telemetry_complete` value is `false`. Do not downgrade queue loss to a
normal operational warning.

## Evidence limitations

The local hash chain detects record modification, insertion, deletion, and
reordering inside retained segments. It cannot prevent deletion of all logs,
collector replacement, or generation of a new internally consistent log by a
local administrator.

Anchor chain heads and sequence numbers remotely during the session when the
events are used as security evidence.

## Vulnerability reporting

Use a
[private security advisory](https://github.com/amandykovxd/anticheat/security/advisories/new)
for memory corruption, invalid IRQL, unload races, IOCTL validation bypass,
unauthorized device access, or signing-material exposure.

Do not attach kernel dumps, private paths, credentials, or user data to public
issues or discussions.
