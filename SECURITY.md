# Security Model

## Scope

This repository contains:

- an optional Windows kernel telemetry driver;
- a user-mode process scanner and event collector;
- a local tamper-evident JSONL logger;
- an asynchronous authenticated transport sidecar;
- a reference remote anchor receiver;
- a log-chain verification utility.

The system produces telemetry for an explicitly registered target process.
Enforcement, account actions, production identity provisioning, and
server-side correlation are outside the repository.

## Trust boundaries

```text
Kernel boundary
  AcTelemetry.sys
  process/image/thread/handle callbacks
  bounded event queue
  SYSTEM-only device ACL
           |
           | versioned METHOD_BUFFERED IOCTL
           v
User boundary
  anticheat.exe
  target process read handle
  local JSONL output
           |
           v
Integrator boundary
  file ownership
  telemetry_shipper.py
  authenticated TLS transport
  reference_receiver.py anchors
  correlation and policy
```

The kernel driver is trusted to report callback data and queue-health
counters. The collector is trusted to validate the driver protocol, classify
user-space memory, and serialize events. A local administrator can replace,
stop, or alter both components and must be included in the deployment threat
model.

## Kernel driver security properties

The current driver:

- registers `PsSetCreateProcessNotifyRoutineEx`;
- registers `PsSetLoadImageNotifyRoutine`;
- registers `PsSetCreateThreadNotifyRoutine`;
- registers `ObRegisterCallbacks` for telemetry-only process-handle access;
- unregisters all callbacks before unload;
- records image events only for one registered PID and process creation for
  that PID's direct children;
- uses a fixed-capacity nonpaged queue;
- exposes only fixed-size, versioned structures;
- uses `METHOD_BUFFERED` for all IOCTLs;
- validates input size, protocol version, reserved fields, session ID, and
  target PID;
- uses `IoCreateDeviceSecure` with
  `D:P(A;;GA;;;SY)`;
- creates an exclusive device handle;
- reports queue overwrites through `events_dropped`;
- does not return kernel pointers;
- records requested process access but does not modify `DesiredAccess`;

The driver does not:

- hook SSDT entries, interrupt tables, or kernel code;
- patch kernel or user memory;
- read arbitrary kernel or process memory;
- create remote threads;
- hide processes, drivers, handles, files, or registry entries;
- block process creation or image loading;
- block, remove, or downgrade process handles;
- modify `PS_CREATE_NOTIFY_INFO.CreationStatus`;
- terminate or suspend processes;
- implement an IOCTL for arbitrary address access;
- accept `METHOD_NEITHER` user pointers;
- open network connections.

Any change that introduces one of these behaviors requires a separate threat
model, API review, deployment policy, and test plan.

## User-mode collector security properties

The collector opens the target without:

- `PROCESS_VM_WRITE`;
- `PROCESS_VM_OPERATION`;
- `PROCESS_TERMINATE`;
- `PROCESS_CREATE_THREAD`.

It may request:

- `PROCESS_QUERY_LIMITED_INFORMATION`;
- `PROCESS_QUERY_INFORMATION`;
- `PROCESS_VM_READ`;
- `SYNCHRONIZE`.

The collector reads:

- the target image path and process creation time;
- loader-visible module metadata;
- virtual-memory region metadata;
- up to 4 KiB from classified executable regions, subject to a scan budget;
- module files outside configured roots when hashing is enabled;
- kernel event batches from `\\.\AcTelemetry` when enabled.

The collector does not include network transport. Integrators control the log
path, ACL, retention, and forwarding implementation.

The command-line invoker is a trusted configuration authority for the log
path. The collector does not elevate its token and does not expose an IPC
operation that accepts a log path. A launcher or service wrapper running the
collector with elevated privileges must use a fixed deployment-owned log
location and must not forward an untrusted user's path into `--log`.

## Device access

`AcTelemetry.sys` applies this SDDL to the device object:

```text
D:P(A;;GA;;;SY)
```

The descriptor grants full access only to Local System (`SY`).

No access is granted to standard users. The user-mode collector must run under
Local System when `--kernel` or `--require-kernel` is used.

The IOCTL access bits additionally require:

- read access for version, event, and statistics requests;
- write access for target registration.

The client opens the device with `GENERIC_READ | GENERIC_WRITE`.

## Protocol validation

The shared ABI is defined in `include/ac_driver_protocol.h`.

Required client checks:

1. `AcDriverVersion.size == sizeof(AcDriverVersion)`.
2. `protocol_version == AC_DRIVER_PROTOCOL_VERSION`.
3. `event_size == sizeof(AcDriverEvent)`.
4. returned byte counts are exact multiples of `event_size`.
5. every event contains the expected `size` and `protocol_version`.
6. unknown event types are retained as informational telemetry.

Required driver checks:

1. IOCTL input and output buffer lengths meet the structure contract.
2. target requests contain the current protocol version.
3. reserved fields are zero.
4. nonzero target PIDs resolve to a live process at registration time.
5. session IDs are nonzero and cannot replace another active session.
6. event reads are limited to `AC_DRIVER_MAX_BATCH_EVENTS`.

Protocol changes that alter structure size or semantics require a protocol
version increment.

## Queue and denial-of-service behavior

The kernel queue has a fixed capacity of 512 events. When full, the driver
overwrites the oldest event and increments `events_dropped`. It does not
allocate memory in process or image callbacks.

The collector:

- reads no more than 32 events per IOCTL;
- drains no more than eight batches every 250 milliseconds between scans;
- emits `kernel_event_queue_overflow` when the dropped-event counter increases;
- stops kernel collection on malformed protocol data;
- exits when `--require-kernel` is active and required driver reads fail.

Integrators must alert on:

- any increase in `events_dropped`;
- repeated `kernel_event_read_failed`;
- missing `scan_completed` events;
- a collector restart or sequence reset during an active session.

## Log integrity

Every JSONL record includes a SHA-256 chain value:

```text
chain[i] = SHA256(chain[i-1] || exact_record_body[i])
```

The chain detects local record modification, insertion, deletion, and
reordering within retained segments. It does not prevent:

- deletion of the entire log;
- replacement of the collector;
- generation of a new internally consistent log by a local administrator;
- rollback to an earlier complete segment set.

`tools/telemetry_shipper.py` forwards exact record bytes through authenticated
TLS batches. `tools/reference_receiver.py` independently verifies each chain
transition and persists the accepted chain head under a server-issued session
identifier. Production deployments must protect receiver storage against
operator rollback and monitor missing heartbeat intervals.

For registered release identities, the receiver also issues a short-lived
nonce and validates `collector_attestation_observed` before accepting
heartbeat. This detects stale responses, a collector binary different from the
configured release, and mapped executable-section modification at the time of
measurement. It is not hardware attestation: hostile kernel code can falsify
the process view or execute the measurement in a clean surrogate process.

## Driver signing and deployment

Development builds must be test-signed and loaded only on isolated test
systems. Production distribution requires:

- matching Windows SDK and WDK versions;
- a signed `.sys` file and signed package catalog;
- INF validation;
- Driver Verifier testing;
- supported Windows-version matrix;
- clean install, upgrade, rollback, and uninstall tests;
- crash-dump collection and symbol retention;
- applicable Microsoft driver signing or certification.

The `driver-submission` workflow builds an Inf2Cat package and EV-signs a
Partner Center submission CAB on a protected self-hosted runner. Private keys
remain in the runner certificate store. A submission CAB is not production
deployable; only the Microsoft-returned package that passes
`Test-MicrosoftSignedDriver.ps1` is eligible for release. Driver Verifier and
HLK workflows require dedicated self-hosted lab environments and retain result
evidence as CI artifacts.

## Data inventory

Potentially sensitive fields include:

- executable and module paths;
- process identifiers;
- process creation time;
- image base addresses and sizes;
- file and memory-content hashes;
- Windows error messages.

Integrators must define:

- storage location and ACL;
- transport encryption;
- retention duration;
- tenant/session identifiers;
- path minimization or hashing policy;
- access logging;
- deletion procedure.

Do not collect command lines, user input, file contents unrelated to module
hashing, or memory from processes other than the registered target.

## Vulnerability reporting

Report security issues through
[GitHub private vulnerability reporting](https://github.com/amandykovxd/anticheat/security/advisories/new).
Do not create a public issue or discussion before remediation is available.
Include:

- collector version;
- driver protocol version;
- Windows build and architecture;
- driver signing mode;
- relevant `agent_started`, `kernel_driver_connected`, and failure events;
- minimal reproduction steps;
- crash dump and matching symbols for kernel failures.

Relevant issue classes include:

- kernel memory corruption;
- invalid IRQL usage;
- callback unload races;
- IOCTL validation bypass;
- unauthorized device access;
- queue corruption or counter overflow;
- collector memory corruption;
- privilege expansion;
- integrity-chain verification bypass;
- unbounded CPU, memory, or nonpaged-pool consumption.
