# Event Pipeline

## Sources

Kernel-originated records:

- target registration changes;
- target and direct-child process lifecycle;
- image loads for the active target;
- target thread lifecycle and start-address correlation;
- foreign process-handle requests containing dangerous access;
- queue drop and callback health counters.

User-mode records:

- process identity;
- module inventory;
- executable regions outside loader-visible module ranges;
- module path and hash classification;
- pinned module and driver manifest violations;
- configured function-pointer, VMT, and target-WndProc validation;
- scan budgets and completion cadence;
- driver connection and protocol failures.

## Serialization

The collector writes UTF-8 JSON Lines. Every record contains a collector
sequence, UTC timestamp, severity, stable event identifier, target PID,
event-specific details, and a SHA-256 chain value.

```text
chain[i] = SHA256(chain[i-1] || exact_record_body[i])
```

Forward complete lines without parsing and regenerating the JSON. Verify
segments from oldest to newest:

```powershell
python tools\verify_log.py `
  anticheat-events.jsonl.2 `
  anticheat-events.jsonl.1 `
  anticheat-events.jsonl
```

## Server processing

The receiver should:

- assign a server-side session identifier;
- reject incompatible schema versions;
- index by session and collector sequence;
- retain kernel sequence independently;
- detect missing or reordered records;
- invalidate kernel evidence on queue drops, sequence gaps, or callback-health
  degradation;
- correlate kernel image bases with user-mode module snapshots while retaining
  the documented unload-race caveat;
- anchor chain heads in append-only remote storage;
- alert on queue drops, incomplete scans, and missing scan cadence;
- keep client signals separate from enforcement decisions.

See the canonical
[event schema](https://github.com/amandykovxd/anticheat/blob/main/docs/event-schema.md).
