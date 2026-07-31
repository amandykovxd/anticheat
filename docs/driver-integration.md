# Kernel Driver Integration

## Purpose

`AcTelemetry.sys` provides kernel-originated process, image-load, thread
lifecycle, and foreign process-handle telemetry for one target PID. It exports
a versioned IOCTL interface to one privileged user-mode collector.

Protocol version 4 makes queue counters and event sequences session-scoped and
adds telemetry-only process-handle and thread lifecycle events. Collectors
must reject older drivers for this contract.

The driver does not perform process-memory scanning or enforcement. The
user-mode collector remains responsible for module inventory, virtual-memory
classification, JSON serialization, and remote integration.

User-mode scan results are explicitly non-authoritative. The collector
correlates documented kernel image-load callbacks with user-mode module
snapshots, but this does not defend against a malicious ring-0 component that
can falsify both sources. Production deployment must combine the sensor with
Secure Boot/HVCI posture, driver allowlisting, and remote liveness policy.

## Components

| File | Purpose |
| --- | --- |
| `include/ac_driver_protocol.h` | Shared ABI, IOCTL values, structures, constants. |
| `driver/src/driver.c` | WDM driver implementation. |
| `driver/AcTelemetry.vcxproj` | x64 WDK build project. |
| `driver/AcTelemetry.inf` | Driver package metadata. |
| `src/kernel_client.c` | Reference user-mode protocol client. |

## Device contract

| Property | Value |
| --- | --- |
| NT device name | `\Device\AcTelemetry` |
| DOS symbolic link | `\DosDevices\AcTelemetry` |
| Win32 path | `\\.\AcTelemetry` |
| Device type | `0x8337` |
| Transfer method | `METHOD_BUFFERED` |
| Handle mode | Exclusive |
| Device characteristic | `FILE_DEVICE_SECURE_OPEN` |
| Device ACL | `SYSTEM`: full access |

Security descriptor:

```text
D:P(A;;GA;;;SY)
```

The device is created through `IoCreateDeviceSecure` with a project-specific
class GUID.

## Protocol compatibility

Current protocol:

```c
#define AC_DRIVER_PROTOCOL_VERSION 4u
```

The following structure sizes are part of the ABI:

| Structure | Size |
| --- | --- |
| `AcDriverVersion` | 16 bytes |
| `AcDriverTargetRequest` | 24 bytes |
| `AcDriverStats` | 56 bytes |
| `AcDriverEvent` | 584 bytes |

The shared header contains compile-time size assertions. All structures use
fixed-width integer fields and 8-byte packing.

A client must call `IOCTL_AC_GET_VERSION` before any other request and reject
the device when:

- `protocol_version` differs;
- `event_size` differs;
- the returned structure size differs;
- the returned byte count is invalid.

## IOCTL reference

### `IOCTL_AC_GET_VERSION`

Access: `FILE_READ_DATA`.

Input: none.

Output:

```c
typedef struct AcDriverVersion {
    uint32_t size;
    uint32_t protocol_version;
    uint32_t event_size;
    uint32_t queue_capacity;
} AcDriverVersion;
```

Returns:

- protocol version;
- event record size;
- configured queue capacity.

### `IOCTL_AC_SET_TARGET`

Access: `FILE_WRITE_DATA`.

Input:

```c
typedef struct AcDriverTargetRequest {
    uint32_t size;
    uint32_t protocol_version;
    uint32_t target_pid;
    uint32_t reserved;
    uint64_t session_id;
} AcDriverTargetRequest;
```

Rules:

- `size` must match the current structure size;
- `protocol_version` must match;
- `reserved` must be zero;
- `session_id` must be a nonzero cryptographically random value;
- nonzero `target_pid` must resolve to a live process;
- `target_pid == 0` clears the active target only for the registered session;
- a different session cannot replace or clear the active registration;
- a target process-exit callback clears the active PID after queuing the exit
  event;
- target changes preserve queued events;
- a `TARGET_CHANGED` event is inserted after the update.

Only one target is active at a time.

### `IOCTL_AC_READ_EVENTS`

Access: `FILE_READ_DATA`.

Input: none.

Output: contiguous array of `AcDriverEvent`.

Rules:

- output capacity must hold at least one event;
- one request returns at most `AC_DRIVER_MAX_BATCH_EVENTS` (`32`) records;
- a request is nonblocking;
- zero returned bytes means the queue is empty;
- returned byte count must be an exact multiple of `sizeof(AcDriverEvent)`.

### `IOCTL_AC_GET_STATS`

Access: `FILE_READ_DATA`.

Input: none.

Output:

```c
typedef struct AcDriverStats {
    uint32_t size;
    uint32_t protocol_version;
    uint64_t events_generated;
    uint64_t events_dropped;
    uint64_t next_sequence;
    uint32_t target_pid;
    uint32_t queue_depth;
    uint32_t queue_capacity;
    uint32_t callbacks_active;
    uint64_t session_id;
} AcDriverStats;
```

`callbacks_active` bit assignments:

| Bit | Meaning |
| --- | --- |
| `0x1` | Process callback registered. |
| `0x2` | Image-load callback registered. |
| `0x4` | Thread callback registered. |
| `0x8` | Process-handle callback registered. |

The client must verify `session_id`, monitor `events_dropped`, and independently
validate event sequence continuity. Any drop-counter increase or sequence gap
invalidates completeness of the session's kernel evidence.

## Event structure

```c
typedef struct AcDriverEvent {
    uint32_t size;
    uint32_t protocol_version;
    uint64_t sequence;
    uint64_t timestamp_100ns;
    uint32_t type;
    uint32_t flags;
    uint32_t process_id;
    uint32_t parent_process_id;
    int32_t status;
    uint32_t reserved;
    uint64_t image_base;
    uint64_t image_size;
    uint16_t image_path[260];
} AcDriverEvent;
```

Field contract:

| Field | Contract |
| --- | --- |
| `size` | `sizeof(AcDriverEvent)`. |
| `protocol_version` | Current driver protocol. |
| `sequence` | Monotonic driver-local sequence. |
| `timestamp_100ns` | Kernel system time in 100-nanosecond intervals. |
| `type` | `AcDriverEventType`. |
| `flags` | Path and image classification flags. |
| `process_id` | Event-specific process or requestor PID. |
| `parent_process_id` | Parent, target, or thread ID according to event type. |
| `status` | NTSTATUS or operation code where applicable. |
| `reserved` | Creator PID for thread events; otherwise zero. |
| `image_base` | Image base, thread start address, or original requested access. |
| `image_size` | Mapped image size or observed requested access. |
| `image_path` | Null-terminated UTF-16 path, bounded to 259 characters. |

Event types:

| Value | Name | Source |
| --- | --- | --- |
| `1` | `TARGET_CHANGED` | Successful target update. |
| `2` | `PROCESS_CREATED` | Process callback. |
| `3` | `PROCESS_EXITED` | Process callback. |
| `4` | `IMAGE_LOADED` | Image-load callback. |
| `5` | `PROCESS_HANDLE` | Object Manager process-handle callback. |
| `6` | `THREAD_CREATED` | Thread callback. |
| `7` | `THREAD_EXITED` | Thread callback. |

Flags:

| Value | Name |
| --- | --- |
| `0x00000001` | `PATH_TRUNCATED` |
| `0x00000002` | `SYSTEM_IMAGE` |
| `0x00000004` | `PATH_UNAVAILABLE` |
| `0x00000008` | `HANDLE_DUPLICATE` |
| `0x00000010` | `KERNEL_HANDLE` |

## Queue behavior

The device extension contains a fixed ring of 512 events in nonpaged memory.
Callbacks do not allocate memory.

When the queue is full:

1. the oldest event is removed;
2. `events_dropped` is incremented;
3. the new event is inserted.

Queue operations and target changes use a spin lock. Callback code copies only
bounded metadata and does not inspect target address space.

Registering the first target of a new session atomically clears stale queue
entries and resets the session sequence and counters. Changing the target with
the same session ID preserves queued evidence and counter continuity.

## Callback behavior

### Process callback

Registered with:

```c
PsSetCreateProcessNotifyRoutineEx(AcProcessNotify, FALSE);
```

The callback emits:

- the registered target's exit event;
- process-creation events where the new process is the target or its direct
  parent PID is the registered target.

It does not modify `CreationStatus`.

### Image callback

Registered with:

```c
PsSetLoadImageNotifyRoutine(AcImageNotify);
```

The callback records:

- target PID;
- image base;
- image size;
- system-image flag;
- bounded image path when supplied by the operating system.

The callback does not map, read, or modify user memory.

### Thread callback

Registered with `PsSetCreateThreadNotifyRoutine`. It emits target thread IDs
and the callback-context PID. The kernel callback does not query user memory.
The collector resolves `ThreadQuerySetWin32StartAddress` and correlates the
result with its next module range snapshot. A short-lived thread can exit
before that query; this is reported as unavailable coverage.

### Process-handle callback

Registered with `ObRegisterCallbacks` for process handle creation and
duplication. It records foreign requests containing termination, remote-thread,
VM read/write/operation, duplicate-handle, or suspend/resume rights. The
callback returns `OB_PREOP_SUCCESS` without changing `DesiredAccess`.

### Unload

Unload order:

1. unregister the Object Manager callback;
2. remove the thread callback;
3. remove the image-load callback;
4. remove the process callback;
5. delete symbolic link;
6. delete device object.

The driver must not be unloaded while an integration continues to require
kernel telemetry.

## Reference client sequence

```c
HANDLE device = CreateFileW(
    L"\\\\.\\AcTelemetry",
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL);

DeviceIoControl(device, IOCTL_AC_GET_VERSION, ...);
DeviceIoControl(device, IOCTL_AC_SET_TARGET, ...);

for (;;) {
    DeviceIoControl(device, IOCTL_AC_READ_EVENTS, ...);
    DeviceIoControl(device, IOCTL_AC_GET_STATS, ...);
}

DeviceIoControl(device, IOCTL_AC_SET_TARGET, target_pid_zero, ...);
CloseHandle(device);
```

Use `src/kernel_client.c` as the canonical implementation. It:

- validates all version and size fields;
- generates a nonzero session ID with the Windows system RNG;
- verifies that driver statistics remain bound to that session;
- checks callback health and queue statistics before and after each drain;
- drains up to 32 bounded batches per pass;
- rejects duplicate or decreasing driver sequences and reports gaps;
- correlates kernel image-load bases with the next user-mode module snapshot;
- resolves and correlates target thread start addresses;
- resolves requestor process paths for dangerous handle requests;
- converts UTF-16 paths to UTF-8;
- emits JSONL records;
- reports queue saturation and treats queue overflows as high-severity evidence
  loss;
- closes the device on malformed protocol data.

## Launcher integration

Recommended launch sequence:

1. verify the installed driver and collector version matrix;
2. start the driver service;
3. create the protected process suspended;
4. obtain its PID and process creation time;
5. start the collector with `--pid <pid> --require-kernel`;
6. wait for `kernel_driver_connected`;
7. resume the protected process;
8. forward JSONL records to the remote collector;
9. on process exit, wait for `agent_stopped`;
10. stop or retain the driver according to the product lifecycle.

Target registration occurs after process creation. Therefore the driver cannot
emit the original process-creation callback for that PID in this sequence.
Creating the process suspended minimizes missed post-creation image loads.
The user-mode scanner inventories the current modules on its first scan.

## Error handling

Client policy:

| Condition | `--kernel` | `--require-kernel` |
| --- | --- | --- |
| Device not found | Continue user-mode only. | Exit nonzero. |
| Access denied | Continue user-mode only. | Exit nonzero. |
| Protocol mismatch | Continue user-mode only. | Exit nonzero. |
| Target rejected | Continue user-mode only. | Exit nonzero. |
| Read failure | Close driver, continue. | Close driver, exit nonzero. |
| Queue overflow | Emit high-severity evidence-loss event; continue. | Emit high-severity evidence-loss event; deployment must reject session evidence. |

An integrator may apply a stricter policy outside the collector.

## Build, signing, and packaging

Build:

```powershell
nuget restore driver\packages.config -PackagesDirectory driver\packages
msbuild driver\AcTelemetry.vcxproj `
  /p:Configuration=Release `
  /p:Platform=x64
```

Package contents:

- `AcTelemetry.sys`;
- `AcTelemetry.inf`;
- generated and signed `AcTelemetry.cat`;
- release notes containing collector/protocol compatibility;
- public symbols or retained private symbols.

Production requirements:

- the pinned WDK NuGet package and its matching SDK dependency;
- release driver signature;
- catalog signature;
- INF validation;
- Driver Verifier;
- target Windows compatibility tests;
- install, upgrade, rollback, and uninstall tests.

## Driver API exclusions

The protocol intentionally has no operation for:

- arbitrary process-memory reads;
- arbitrary kernel-memory reads or writes;
- process termination or suspension;
- handle removal;
- object hiding;
- code patching;
- driver or process enumeration outside the registered target;
- command execution.

These operations are not required for the telemetry integration described by
this document.
