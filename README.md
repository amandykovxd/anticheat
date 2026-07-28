# Anticheat Telemetry

[![build-and-test](https://github.com/amandykovxd/anticheat/actions/workflows/windows-build.yml/badge.svg)](https://github.com/amandykovxd/anticheat/actions/workflows/windows-build.yml)
[![CodeQL](https://github.com/amandykovxd/anticheat/actions/workflows/codeql.yml/badge.svg)](https://github.com/amandykovxd/anticheat/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D4.svg)](#supported-configurations)
[![Language: C11](https://img.shields.io/badge/language-C11-555555.svg)](CMakeLists.txt)

Anticheat Telemetry is a Windows process-integrity sensor composed of:

- `AcTelemetry.sys`: optional x64 kernel telemetry driver;
- `anticheat.exe`: user-mode collector and process-memory scanner;
- `tools/verify_log.py`: JSONL integrity-chain verifier;
- a versioned IOCTL protocol in `include/ac_driver_protocol.h`.

The kernel driver records process lifecycle and image-load notifications for
one registered process ID. The user-mode collector inventories modules, maps
executable memory, classifies regions not backed by loader-visible modules,
applies event de-duplication, and writes a tamper-evident JSONL stream.

The components produce telemetry only. They do not terminate processes,
modify target memory, block image loads, or issue enforcement decisions.

## System architecture

```text
Windows kernel
  PsSetCreateProcessNotifyRoutineEx
  PsSetLoadImageNotifyRoutine
               |
               v
  AcTelemetry.sys bounded event queue
               |
       versioned buffered IOCTL
               |
               v
anticheat.exe
  kernel event collector
  module inventory
  executable-memory classification
  de-duplication and resource budgets
               |
               v
tamper-evident JSONL
               |
               v
integrator-owned storage, transport, correlation, and policy
```

The driver and collector use the shared ABI defined in
[`include/ac_driver_protocol.h`](include/ac_driver_protocol.h). The driver
device is exclusive and accessible only to `SYSTEM` and local
`Administrators`.

## Supported configurations

| Component | Architecture | Build requirement |
| --- | --- | --- |
| Kernel driver | x64 | Visual Studio, matching Windows SDK and WDK |
| User-mode collector | x64, Win32 | Visual Studio 2022 and CMake 3.24+ |
| Portable core tests | Linux, macOS, Windows | C11 compiler and CMake |
| Log verifier | Platform-independent | Python 3 |

Use the x64 collector for x64 targets. A Win32 collector cannot enumerate all
modules of an x64 process.

## Build the user-mode collector

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The executable is generated at:

```text
build\Release\anticheat.exe
```

The normal CI matrix builds and tests x64 and Win32 collectors. The portable
core is additionally tested with AddressSanitizer and UndefinedBehaviorSanitizer.

## Build the kernel driver

Install Visual Studio with Desktop C++ support and a matching Windows SDK/WDK
pair. Microsoft requires matching SDK and WDK build numbers.

From a Developer Command Prompt:

```powershell
msbuild driver\AcTelemetry.vcxproj `
  /p:Configuration=Release `
  /p:Platform=x64
```

Expected output:

```text
driver\x64\Release\AcTelemetry.sys
```

The project does not enable production signing. Development systems must use a
test-signed package and an isolated test configuration. Production deployment
requires a signed catalog and a driver package accepted by the applicable
Microsoft signing process.

Microsoft references:

- [Download and install the WDK](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk)
- [Build a driver with MSBuild](https://learn.microsoft.com/windows-hardware/drivers/develop/building-a-driver)
- [Driver package components](https://learn.microsoft.com/windows-hardware/drivers/install/components-of-a-driver-package)
- [Test-signing driver packages](https://learn.microsoft.com/windows-hardware/drivers/install/test-signing-driver-packages)

## Development installation

The repository includes `driver/AcTelemetry.inf` for package preparation.
During local driver development, an elevated terminal can register a
test-signed binary directly:

```powershell
sc.exe create AcTelemetry `
  type= kernel `
  start= demand `
  binPath= "C:\absolute\path\AcTelemetry.sys"

sc.exe start AcTelemetry
```

Remove the development service:

```powershell
sc.exe stop AcTelemetry
sc.exe delete AcTelemetry
```

Do not load unsigned or test-signed kernel code on production endpoints.
Validate the driver with Driver Verifier and WinDbg on a disposable test
system before deployment.

## Collector operation

User-mode telemetry only:

```powershell
.\build\Release\anticheat.exe `
  --process game.exe `
  --interval-ms 5000 `
  --log anticheat-events.jsonl
```

User-mode telemetry plus optional kernel events:

```powershell
.\build\Release\anticheat.exe `
  --pid 1234 `
  --kernel `
  --interval-ms 5000 `
  --log anticheat-events.jsonl
```

Require an operational kernel driver:

```powershell
.\build\Release\anticheat.exe `
  --pid 1234 `
  --require-kernel `
  --log anticheat-events.jsonl
```

`--kernel` continues with user-mode collection when the driver is unavailable.
`--require-kernel` exits with a nonzero status if the device cannot be opened,
the protocol version is incompatible, target registration fails, or event
reads fail.

The driver device ACL requires the collector to run as `SYSTEM` or as an
administrator when kernel telemetry is enabled. User-mode-only collection does
not require administrative privileges when the target process ACL permits
read access.

## Integration sequence

1. Build and sign `AcTelemetry.sys` for the target Windows release.
2. Install and start the `AcTelemetry` driver service during product setup.
3. Start the protected application and retain its PID and process handle.
4. Start `anticheat.exe --pid <pid> --require-kernel`.
5. Read the JSONL file or forward complete lines to the integrator's collector.
6. Validate each log segment with `tools/verify_log.py`.
7. Enforce schema compatibility using `details.schema` from
   `log_segment_opened` and `agent_started`.
8. Correlate signals on the server. Do not treat a single client event as an
   enforcement decision.
9. Monitor expected `scan_completed` cadence and kernel queue-overflow events.
10. Stop the collector before unloading or upgrading the driver.

For launchers that must capture the earliest possible post-launch image loads,
create the application suspended, obtain its PID, start the collector with
`--require-kernel`, wait for `kernel_driver_connected`, then resume the
application. Image mappings performed before target registration are not
replayed by the driver; the user-mode module inventory covers the current
state at the next scan.

## CLI contract

| Option | Description |
| --- | --- |
| `--process <name>` | Resolve a target by executable name. |
| `--pid <id>` | Select an explicit target PID. Preferred for integration. |
| `--wait-timeout-ms <n>` | Stop waiting for a named process after `n` milliseconds. |
| `--interval-ms <n>` | User-mode scan interval, `1000..3600000`. |
| `--once` | Run one user-mode scan and exit. |
| `--allow-root <dir>` | Add an expected module root. Repeatable. |
| `--kernel` | Consume driver events when the driver is available. |
| `--require-kernel` | Require driver connectivity and protocol compatibility. |
| `--scan-budget-ms <n>` | Emit an event when a scan exceeds the configured duration. |
| `--repeat-interval-ms <n>` | Re-emit a de-duplicated finding after `n` milliseconds. |
| `--no-module-hashes` | Disable SHA-256 calculation for modules outside allowed roots. |
| `--no-region-probe` | Disable content probing of suspicious executable regions. |
| `--log <path>` | Set the JSONL output path. |
| `--max-log-bytes <n>` | Rotate the active log after `n` bytes. `0` disables rotation. |
| `--log-generations <n>` | Set the number of retained rotated segments. |
| `--quiet` | Disable JSONL mirroring to standard output. |
| `--version` | Print collector, event-schema, and driver-protocol versions, then exit. |
| `--help` | Print the command-line contract, then exit. |

`--version` is a standalone metadata command. It does not select a target,
open the driver device, or create a log. Operational options cannot be combined
with it; a conflicting invocation exits with code `2`.

The output is a stable, line-oriented contract:

```text
collector_version=0.3.0
event_schema_version=3
driver_protocol_version=1
```

Integrators must parse the keys rather than depend on a fixed numeric value.
The collector version follows the project release, while schema and protocol
versions change only with their corresponding compatibility contracts.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Completed successfully. |
| `2` | Invalid command-line arguments. |
| `3` | Log initialization failed. |
| `4` | Target process was not found or identity validation failed. |
| `5` | Required process or driver access was denied. |
| `6` | Internal or required-kernel runtime failure. |

## Kernel protocol

The driver exposes `\\.\AcTelemetry` and supports:

| IOCTL | Direction | Purpose |
| --- | --- | --- |
| `IOCTL_AC_GET_VERSION` | Driver to client | Return protocol and structure versions. |
| `IOCTL_AC_SET_TARGET` | Client to driver | Register or clear one target PID. |
| `IOCTL_AC_READ_EVENTS` | Driver to client | Return up to 32 queued fixed-size events. |
| `IOCTL_AC_GET_STATS` | Driver to client | Return queue depth, dropped-event count, and callback state. |

All IOCTLs use `METHOD_BUFFERED`. Structures use fixed-width fields and an
explicit 8-byte packing contract. The user-mode client validates protocol
version, structure size, and returned byte count before consuming data.

See [docs/driver-integration.md](docs/driver-integration.md) for the complete
ABI and lifecycle contract.

## Event output

The collector writes UTF-8 JSON Lines. Each line contains:

- monotonically increasing collector sequence number;
- UTC timestamp;
- severity and stable event identifier;
- target PID;
- event-specific `details`;
- SHA-256 integrity-chain value.

Kernel-originated records contain the driver's independent sequence number and
100-nanosecond system timestamp. Relevant event identifiers are:

- `kernel_driver_connected`;
- `kernel_target_changed`;
- `kernel_process_created`;
- `kernel_process_exited`;
- `kernel_image_loaded`;
- `kernel_event_queue_overflow`;
- `kernel_event_read_failed`.

The complete schema is defined in
[docs/event-schema.md](docs/event-schema.md).

Verify log segments from oldest to newest:

```powershell
python tools\verify_log.py `
  anticheat-events.jsonl.2 `
  anticheat-events.jsonl.1 `
  anticheat-events.jsonl
```

## Operational constraints

- The driver queue contains 512 events and overwrites the oldest event when
  full. Every overwrite increments `events_dropped`.
- A read returns at most 32 events. The collector drains at most eight batches
  per scan iteration to bound CPU usage.
- Only one device handle is allowed at a time.
- Target registration is PID-based. The collector separately validates target
  image path and process creation time.
- The driver reports image loads for the active PID, direct child-process
  creation, and target exit. It clears the active PID after recording exit.
- Kernel callbacks report image mappings; they do not inspect or modify image
  contents.
- The driver does not enumerate image mappings that occurred before target
  registration.
- The user-mode scanner still provides the current module and executable-memory
  view.
- Driver unload unregisters callbacks before deleting the device object.
- The current driver is a development WDM implementation. Production release
  requires Driver Verifier, HLK/signing validation, upgrade testing, crash-dump
  analysis, and explicit OS-version support policy.

## Repository structure

```text
include/
  ac_driver_protocol.h    shared kernel/user ABI
driver/
  AcTelemetry.vcxproj     WDK x64 driver project
  AcTelemetry.inf         driver package metadata
  src/driver.c            callbacks, device, IOCTLs, bounded queue
src/
  kernel_client.c         user-mode driver client
  process.c               target discovery and identity validation
  scanner.c               module and memory telemetry
  log.c                   JSONL output, rotation, integrity chain
  dedup.c                 bounded finding de-duplication
  ranges.c                executable range index
  sha256.c                SHA-256 implementation
  text.c                  JSON escaping and fingerprints
tests/
  test_core.c             Windows integration and ABI tests
  test_portable.c         portable unit tests
tools/
  verify_log.py           log-chain verifier
```

## Additional documentation

- [Driver integration](docs/driver-integration.md)
- [Event schema](docs/event-schema.md)
- [Security model](SECURITY.md)
- [Technical roadmap](ROADMAP.md)
- [Engineering project contract](docs/project-board.md)
- [Technical support](SUPPORT.md)
- [Wiki source](docs/wiki/Home.md)

Project coordination:

- [Engineering project](https://github.com/users/amandykovxd/projects/1)
- [Issues](https://github.com/amandykovxd/anticheat/issues)
- [Discussions](https://github.com/amandykovxd/anticheat/discussions)
- [Security](https://github.com/amandykovxd/anticheat/security)

## Contributing

External contributors can fork the repository, push a focused feature branch,
and open a pull request. Repository collaborators can push feature branches
directly to this repository. All changes enter `main` through owner-reviewed
pull requests with required x64, Win32, and sanitizer checks.

Start with:

- [Contribution requirements](CONTRIBUTING.md)
- [`good first issue` tasks](https://github.com/amandykovxd/anticheat/labels/good%20first%20issue)
- [`help wanted` tasks](https://github.com/amandykovxd/anticheat/labels/help%20wanted)
- [Integration and design discussions](https://github.com/amandykovxd/anticheat/discussions)

## License

MIT. See [LICENSE](LICENSE).
