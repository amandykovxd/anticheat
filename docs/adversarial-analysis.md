# Adversarial Analysis

This document describes how an attacker defeats the current system, ordered by
cost to the attacker. It is written from the attacker's side on purpose: a
control that is not stated as evadable will be trusted as if it were not.

Assumed attacker: a local user running arbitrary code at the same integrity
level as the game, able to elevate to Administrator when the deployment allows
it. This is the normal condition on a consumer machine.

Status legend: **open** — no control exists; **partial** — detectable but
evadable; **closed** — the documented attack no longer works.

---

## A. Attacks on the collector process

### A1. Terminate or suspend the collector — *partial*

The collector is a separate user-mode process with a fixed image name. A
process at the same integrity level may call `TerminateProcess`, suspend every
thread with `NtSuspendProcess`, or close its log handle.

Cost: minutes. Detection is remote rather than local: the transport sidecar
registers a heartbeat interval and the reference receiver retains the last
accepted chain head. Two missed heartbeat intervals are a session-integrity
failure for the deployment.

Remaining gap: terminating both collector and sidecar still leaves only the
server timeout as evidence. A watchdog service in a different session raises
cost further but does not close the class while attacker and watchdog share a
privilege level.

### A2. Patch the collector's own code — *open*

The collector emits its executable SHA-256 as
`collector_identity_observed`, allowing deployment to reject an unexpected
binary. Nothing continuously verifies the collector's mapped image. Patching
`ac_report_region` or `ac_verify_module_integrity` to return immediately still
produces a process that emits a well-formed, correctly chained, blind event
stream.

Cost: hours, once. Detection: none.

Countermeasure: self-integrity using the same machinery this repository now
applies to the target — validate the collector's own executable sections
against its file on disk, and include the result in a periodic record. This
raises the bar to "patch the check and the reporting path", but a local
attacker with equal privilege can always win the final round. The durable
control is remote: a server-issued nonce that the collector must answer with a
hash over its own mapped code. Precompute is prevented by the nonce; the
attacker must keep a pristine copy of the code and emulate the response, which
is real work rather than a one-byte patch.

### A3. Race the driver device — *partial*

`AcTelemetry.sys` creates its device with `IoCreateDeviceSecure(..., TRUE, ...)`
— exclusive. The first opener wins. An attacker who opens `\\.\AcTelemetry`
before the collector denies it kernel telemetry entirely. Without
`--require-kernel` the collector degrades to user-mode-only and logs
`kernel_driver_open_failed` at severity `medium`.

The device ACL is now `D:P(A;;GA;;;SY)`, so a normal Administrator token cannot
open it directly. An attacker able to execute as `SYSTEM` can still win the
exclusive-open race.

Countermeasure: treat `kernel_driver_open_failed` as a session-integrity event
rather than an operational warning, make `--require-kernel` the deployment
default, and have the driver record the identity of the process that holds the
device so a losing collector can report who won.

### A4. Blind the driver through the IOCTL interface — *partial*

Protocol v4 requires a nonzero random session ID. A different session cannot
replace or clear an active registration, and target changes no longer clear the
queue. Compromise of the collector process still exposes the active session ID
and device handle, so this does not defend against an equal-privilege attacker
inside the collector.

Cost: minutes with Administrator. Detection: a `kernel_target_changed` record
appears, but nothing marks it as unexpected.

Countermeasure: issue #11. Bind registration to a launcher-created session with
a server-issued identifier, reject a target change that does not present the
current session token, and never silently drop queued events on
re-registration.

---

## B. Attacks on evidence

### B1. Delete the log — *partial*

The chain detects modification of retained records. It does not survive
deletion of the whole file, and the seed is generated locally, so an attacker
can produce a fresh, internally consistent, fully verifiable log of a clean
session.

Countermeasure: issue #14. Forward the sequence number and chain head to
append-only remote storage during the session. The value of the chain is that
it makes the *server's* copy authoritative — locally it proves nothing.

### B2. Flood the kernel queue — *partial*

The driver queue holds 512 events and overwrites the oldest on overflow. An
attacker who loads and unloads modules in a loop pushes the record of their own
injection out of the queue before the collector drains it. `events_dropped`
increases, which is reported as `kernel_event_queue_overflow` at severity
`high`. The collector also validates the independent driver sequence and marks
the session's kernel telemetry incomplete.

Countermeasure: an overflow during a session is evidence destruction, not an
operational nuisance. The collector reads statistics outside the ring before
and after a drain, drains up to 1,024 events per pass before and after every
scan and every 250 milliseconds while waiting, and exposes cumulative loss in
`agent_stopped`. A remote policy must reject a session whose
`kernel_telemetry_complete` is false; no finite local queue closes flooding.

### B3. Flood user-mode findings — *mitigated with explicit residual risk*

`ac_scan_memory_regions` reports at most `AC_MAX_REGION_EVENTS_PER_SCAN` (64)
regions. A CSPRNG-selected address-space epoch cursor continues across bounded
scans, while a persistent cyclic finding window advances by the event capacity.
Stable low-address decoys therefore cannot permanently exclude a stable
high-address payload. Epoch age, visits, deferrals, and omitted findings are
emitted as coverage metrics. Rapidly created and removed regions can still fall
between observations. The same temporal limitation applies to probe and
integrity budgets.

Countermeasure: the caps are necessary, but hitting them must be reported as a
finding rather than applied silently. A server should invalidate sessions with
sustained deferrals, omitted findings, or random-source failure.

### B4. Saturate the de-duplication table — *partial*

The table holds 4096 fingerprints and fails open when saturated, which is the
right default. An attacker who forces saturation converts a quiet log into a
noisy one and buries a real finding in volume.

Countermeasure: `dedup_saturated_events` is already reported; it needs a
server-side rule, not more code.

---

## C. Attacks on detection logic

### C1. Drop the payload into an allowed root — *partial*

`module_outside_allowed_roots` still classifies by directory, but directory
membership is no longer the authorization boundary when a pinned manifest is
configured. The collector hashes loader-visible modules inside allowed roots
and emits `module_manifest_violation` when a basename is absent or its SHA-256
does not match. The same policy applies to the startup driver snapshot.

This is the cheapest bypass in the system: copy the payload into the game
folder and load it normally.

Remaining gap: the expected manifest hash must arrive through the authenticated
launcher/control-plane channel. A pin stored beside the manifest is not a
trust anchor, and a compromised collector can skip the check.

### C2. Erase the PE header of a manual-mapped image — *partial*

The bounded probe raises severity to `high` on a valid `MZ`/`PE` header in
unbacked memory. Zeroing the first page after mapping removes that signal; the
region is then fingerprinted by reason, protection, and size bucket, which
collapses it into the same bucket as ordinary JIT output.

Countermeasure: header erasure is itself anomalous. A private executable region
whose first page is entirely zero, or whose entropy profile does not match
compiled code, is a stronger signal than the absence of a header. Section-shape
heuristics belong here.

### C3. Time the scan window — *partial*

The collector randomises each wait by plus or minus 20 percent around
`--interval-ms`, so the next scan cannot be predicted from the configured base
interval. A payload that maps, executes, and unmaps entirely between two scans
can still remain unobserved. The default base interval is five seconds.

Countermeasure: randomised intervals so the window is not predictable, and
event-driven collection — the kernel image-load callback already provides one —
rather than polling alone. Polling can only ever find what is still resident.

### C4. Restore before the scan — *partial for inline hooks*

Against the region scanner, a cheat can restore original page protections
before each poll. Against the integrity check added for issue #13 this is
harder: restoring means writing the original bytes back, which removes the hook
for the duration. That is the intended effect — the control does not stop the
hook, it makes the hook expensive to keep resident.

Remaining gap: the check runs on a round-robin cursor with a byte budget, so a
given module is validated every N scans, not every scan. A cheat that hooks,
acts, and unhooks within that window survives.

Countermeasure: prioritise the cursor by module risk — the main executable and
the modules a cheat must hook to be useful — instead of round-robin over all
modules equally.

### C5. Hook without modifying section bytes — *partial*

The integrity check compares section content and validates IAT and EAT targets.
Integrators can additionally configure exact function-pointer slots and object
VMT locations with `--watch-pointer` and `--watch-vtable`; the target WndProc
is also checked against loader-visible module ranges. These checks cover known
game-build dispatch points, not arbitrary writable dispatch metadata. Remaining
gaps include:

- unconfigured function pointers, vtables, and callback registrations;
- return-oriented payloads that execute only existing bytes;
- the Control Flow Guard dispatch table;
- exception-handler tables and TLS callbacks;
- `KUSER_SHARED_DATA` and PEB-derived dispatch.

Countermeasure: generate watch specifications from a signed per-build game
manifest and reject missing or unreadable required watches. Broad scanning of
all writable data is too noisy to be an authorization control.

### C6. Modify the file on disk after load — *partial*

`ac_hash_file` still hashes a path rather than the mapped section object.
Integrity baselines now retain volume serial, file index, size, and write time;
a change emits `module_file_identity_changed`, invalidates the cache, and
rebuilds the baseline. A replacement completed before the first baseline is
still indistinguishable without the signed manifest.

Countermeasure: derive identity from the mapped section rather than the path —
open the file by its file ID, or read the image from memory and compare against
a manifest entry rather than against the current file on disk.

### C7. Load before the collector attaches — *open*

The user-mode scan sees a snapshot. Anything injected before the collector
starts is indistinguishable from a legitimately loaded module unless it fails
another check.

Countermeasure: issue #11's create-suspended launcher sequence. Registration
must complete before the initial thread resumes.

### C8. Intercept user-mode scan APIs — *partial*

An equal-privilege injector can hook `CreateToolhelp32Snapshot`,
`VirtualQueryEx`, or `ReadProcessMemory`. A malicious kernel driver can hide or
forge both user-mode and kernel observations. Moving the same polling loop into
the driver would add crash and compatibility risk without creating an
independent trust anchor.

The collector now labels every Windows scan as `source_trust:"untrusted"`,
sets `complete:false` on structural query, read, module, or integrity gaps, and
correlates driver image-load bases with the next Toolhelp snapshot. A missing
base emits `kernel_user_module_mismatch`; this detects some user-mode hiding but
also occurs for legitimate transient unloads.

Remaining gap: manual-mapped private memory does not trigger the documented
image-load callback, and a hostile ring-0 component can tamper with both
sources. Production enforcement therefore requires a signed-driver policy,
Secure Boot/HVCI posture, remote heartbeat and cross-session correlation. The
local collector cannot prove its own correctness against a stronger kernel
attacker.

---

## D. What issue #13 changes

Before: a cheat that loads a normal DLL and installs inline hooks in
`game.exe`'s `.text` produced no finding at all. The module list was intact,
the memory was image-backed, and no rule looked at content.

After: the modified block is reported at `high` with the exact RVA, the
expected and observed digests, and the differing bytes.

The attacker's cheapest responses, in order:

1. Move the hook to an unconfigured data pointer (C5) — partially covered.
2. Hook only inside the interval where the module is not being validated
   (C4) — partially covered.
3. Drop the payload into an allowed root and hook from there — the hook is
   still detected; only the module classification is defeated (C1).
4. Patch the collector instead of the game (A2) — not covered.

Item 4 remains the dominant strategy, which is why collector self-integrity and
remote attestation rank above further detection work in the roadmap.

---

## E. Priority

Ranked by attacker cost imposed per unit of engineering effort:

| Rank | Work | Closes | Issue |
| --- | --- | --- | --- |
| 1 | Remote chain anchoring and heartbeat | B1, A1 | implemented |
| 2 | Session-bound target registration | A4, C7 | partial; #11 remains |
| 3 | Control-plane-pinned identity manifest | C1, C6 | implemented locally; launcher integration required |
| 4 | Collector self-integrity with server nonce | A2 | — |
| 5 | Randomised scan order and interval | B3, C3 | interval and reservoir sampling implemented |
| 6 | Risk-ordered integrity cursor | C4 | — |
| 7 | Dispatch-metadata validation | C5 | configured pointer/VMT watches implemented |

Collector nonce attestation is implemented as a server-issued, short-lived
challenge bound to the signed release file digest and normalized mapped-image
digest. It raises the cost of patching the active collector and prevents
cross-session challenge replay. It does not establish a hardware root of trust:
a hostile kernel can redirect reads, hide executable mappings, or run the
measurement in a clean surrogate. Risk-ordered integrity scheduling remains a
separate control.

No item in this table makes user-mode detection unevadable. They raise the cost
from "one afternoon" to "sustained engineering", which is the only honest goal
for a Ring 3 sensor.
