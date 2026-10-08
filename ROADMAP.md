# Technical Roadmap

This roadmap defines engineering work required to move the current telemetry
implementation from development status to a deployable Windows component.

## Current baseline

Implemented:

- x64 WDM telemetry driver source;
- restricted, exclusive device object;
- process, image-load, thread, and process-handle callbacks;
- one-PID target filter;
- bounded kernel event queue with dropped-event accounting;
- versioned fixed-size IOCTL protocol;
- user-mode kernel-event client;
- x64 and Win32 user-mode process scanner;
- loader/module and executable-memory correlation;
- content and file hashing under explicit budgets;
- event de-duplication;
- JSONL rotation and SHA-256 integrity chain;
- portable unit tests and Windows integration tests;
- Release macOS and Linux user-mode collectors;
- WDK NuGet restore and x64 driver CI artifact;
- authenticated transport, bounded spool, heartbeat, and remote chain anchors;
- control-plane-pinned module and driver manifest enforcement;
- Ed25519-signed `ac-manifest-v2` with build ID, validity window, key
  rotation, and a control-plane rollback floor;
- PE section, IAT, EAT, configured function-pointer, and VMT validation.

Not yet completed:

- production driver package signing;
- Driver Verifier and HLK validation;
- KMDF migration evaluation;
- server-side manifest sequence ledger and manifest identity in attestation;
- measured compatibility and false-positive datasets.

## Milestone 1: kernel build and verification pipeline — partial

Deliverables:

- WDK NuGet restore with a pinned SDK/WDK dependency set — implemented;
- `msbuild` of `driver/AcTelemetry.vcxproj` — implemented;
- `InfVerif /w /v` validation of `driver/AcTelemetry.inf` — implemented;
- test catalog generation;
- static driver analysis;
- CodeQL or equivalent analysis for user-mode code;
- published unsigned development artifacts with SHA-256 checksums — implemented;
- symbol artifact retention — implemented.

Acceptance criteria:

- Release x64 driver builds without warnings;
- shared ABI compile-time assertions pass in driver and collector builds;
- INF validation passes;
- user-mode x64 and Win32 matrices remain green;
- protocol compatibility test covers version, structure size, and malformed
  requests.

## Milestone 2: kernel reliability validation

Deliverables:

- Driver Verifier configuration for Special Pool, Force IRQL Checking, I/O
  Verification, Deadlock Detection, Security Checks, and DDI compliance;
- concurrent open, target-change, read, process-exit, and unload tests;
- queue saturation and wraparound tests;
- repeated load/unload test;
- crash-dump triage procedure;
- kernel code coverage for dispatch and callback paths;
- ETW or WPP diagnostics that do not expose target memory.

Acceptance criteria:

- 24-hour stress test completes without bugcheck or verifier finding;
- queue counters remain internally consistent under concurrent callbacks;
- callback removal completes before device deletion;
- malformed IOCTL corpus produces only documented NTSTATUS responses;
- nonpaged allocation remains fixed after driver initialization.

## Milestone 3: package, signing, and lifecycle

Deliverables:

- production INF and catalog generation;
- release-signing pipeline using an external protected signing service;
- installer integration;
- service start, stop, upgrade, rollback, and uninstall operations;
- version compatibility matrix between driver and collector;
- safe behavior when a newer or older peer is installed;
- reboot-required state reporting.

Acceptance criteria:

- clean installation and uninstall pass on every supported Windows release;
- an in-use driver upgrade follows a documented restart or reboot path;
- collector refuses incompatible protocol versions;
- signing keys are never present in source control or CI job files;
- package hashes and symbols are retained for each release.

## Milestone 4: target-session registration

The current protocol registers a PID after the process exists. Image mappings
that occur before registration are not replayed.

Deliverables:

- launcher integration API;
- create-suspended launch sequence;
- server-issued session identifier;
- target PID plus process creation-time identity;
- explicit target-clear operation during teardown;
- optional process-start policy based on a signed expected image identity;
- no system-wide event export.

Acceptance criteria:

- launcher registers the target before resuming its initial thread;
- PID reuse cannot associate events with an earlier session;
- target exit closes the active session deterministically;
- a second client cannot replace the active target;
- all target transitions are represented in the event stream.

## Milestone 5: signed application manifest — partial

The collector verifies either a control-plane-supplied SHA-256 pin
(`ac-manifest-v1`) or an offline Ed25519 signature (`ac-manifest-v2`) and
applies the manifest to every loader-visible module baseline and the startup
kernel driver snapshot. The signed format carries the application name, build
ID, monotonic sequence, and validity window; the collector accepts up to eight
rotation keys and rejects sequences below the control-plane floor. Remaining:
a receiver-side sequence ledger, manifest identity inside the attestation
response, per-file size and path constraints, and Authenticode publisher
constraints.

Deliverables:

- signed manifest containing expected executable and module identities;
- application build ID;
- expected path, file size, and SHA-256 per file;
- optional Authenticode publisher constraints;
- manifest key rotation;
- offline signature verification;
- explicit manifest version in every session.

Acceptance criteria:

- collector rejects a manifest with an invalid signature;
- expected modules are classified by cryptographic identity rather than
  directory alone;
- manifest updates do not require collector or driver recompilation;
- rollback to an expired manifest is detected.

## Milestone 6: PE-aware integrity — implemented baseline

Deliverables:

- PE parser with strict bounds validation;
- executable-section block hashes;
- relocation, import, delay-load, and supported hotpatch normalization;
- IAT and EAT target validation;
- exact RVA and expected/observed hash in integrity events;
- CPU and I/O budgets per scan.

Acceptance criteria:

- a one-instruction `.text` modification produces an event with the exact
  affected RVA;
- supported relocations and import resolution do not generate findings;
- malformed PE inputs do not crash or exceed configured resource limits;
- integrity scanning remains outside kernel callbacks.

## Milestone 7: event transport and remote verification — implemented baseline

Deliverables:

- authenticated TLS transport;
- server-issued session ID;
- idempotent batch protocol keyed by session and sequence;
- offline spool with size and age limits;
- remote chain-head anchoring;
- reference receiver;
- schema compatibility policy;
- backpressure and retry policy.

Acceptance criteria:

- duplicate batches are accepted idempotently;
- missing or reordered sequences are detected;
- local record modification is detected after remote anchoring;
- collector remains within spool limits while offline;
- transport failure does not block kernel callbacks or the target process.

## Milestone 8: rule and correlation service

Deliverables:

- versioned server-side rules;
- audit-only rollout mode;
- correlation across kernel events, user-mode scans, application identity, and
  session state;
- per-rule false-positive metrics;
- rule rollback;
- decision audit record.

Acceptance criteria:

- client binaries contain no account-enforcement policy;
- every decision references input event IDs and rule version;
- new rules remain non-enforcing until configured acceptance thresholds are
  met;
- unknown client events are retained without breaking ingestion.

## Milestone 9: compatibility and performance qualification

Test matrix:

- supported Windows client builds;
- supported CPU architectures;
- Hyper-V and VBS/HVCI configurations;
- common GPU, overlay, accessibility, and endpoint-security software;
- high-module-count and high-image-load workloads;
- application startup, update, and shutdown paths.

Required metrics:

- kernel callback duration distribution;
- queue depth and dropped-event rate;
- collector CPU p50/p95/p99;
- user-mode scan duration p50/p95/p99;
- bytes read from target memory;
- log throughput and rotation rate;
- crash-free session rate;
- finding rate by rule and application build.

Acceptance criteria must be defined per supported application and hardware
class before production rollout.

## Explicit exclusions

The planned kernel component will not include:

- SSDT or kernel inline hooks;
- DKOM or object hiding;
- arbitrary process or kernel memory IOCTLs;
- direct client enforcement from callbacks;
- process termination;
- unsigned production loading;
- undocumented kernel structure traversal as a required signal;
- network operations in kernel mode.

Any proposal to add an excluded capability requires a separate design and
security review.

## Versioning policy

Three versions are independent:

- collector version: `AC_AGENT_VERSION`;
- JSON event schema: `AC_SCHEMA_VERSION`;
- kernel IOCTL ABI: `AC_DRIVER_PROTOCOL_VERSION`.

Rules:

- additive event types may remain within one JSON schema version;
- changes to existing field meaning require a schema increment;
- any IOCTL structure layout or semantic change requires a protocol increment;
- incompatible driver and collector versions must fail closed when
  `--require-kernel` is active;
- release packages must publish the supported version matrix.
