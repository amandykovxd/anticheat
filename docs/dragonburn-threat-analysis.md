---
layout: default
title: DragonBurn Defensive Analysis
---

# DragonBurn Defensive Analysis

## Scope

This analysis covers the public `stable` branch at revision
[`6c71899873af06de105289521ef844c31551e801`](https://github.com/ByteCorum/DragonBurn/tree/6c71899873af06de105289521ef844c31551e801).
It is based on static source inspection only. The software and its embedded
payloads were not built or executed.

The public repository does not contain the deployed kernel payload source.
The user-mode client and mapper expose enough interfaces and behavior to define
defensive signals, but they do not support a complete audit of the kernel
component.

## Observed attack chain

| Stage | Observable behavior | Collector control |
| --- | --- | --- |
| Security reduction | Attempts to disable vulnerable-driver blocking and virtualization-backed protections | `kernel_attack_surface_posture` reports explicit registry configuration with user-mode trust labeling |
| Driver bootstrap | Uses a signed vulnerable Intel driver as a kernel read/write primitive and manually maps a second driver | `kernel_system_image_loaded` records loader-mediated driver images after session registration; the `Nal` device link is a medium IOC |
| Trace removal | Removes entries from driver-load tracking structures after mapping | No authoritative local control; require remote anchoring and treat missing kernel coverage as an invalid session |
| Kernel memory service | Exposes a custom DOS device used by the external client to obtain target data without a game process handle | `DragonBurn-kmd` is a high-confidence versioned IOC; it is inventoried with `QueryDosDeviceW` on every scan |
| External client | Polls game state through the custom driver rather than modifying game memory | Exact public build names are versioned IOCs; rename resistance comes from overlay and posture correlation |
| Overlay | Creates a transparent topmost window aligned to the game, obtains UIAccess, and can exclude the window from capture | `external_overlay_candidate` requires high target overlap plus UIAccess or capture exclusion |
| Input automation | Emits synthetic mouse movement and button input | Not attributed locally in this revision; input provenance requires a separate trusted input sensor and server-side gameplay correlation |

## Detection policy

The new events are telemetry, not enforcement decisions.

- Treat `known_threat_indicator_observed` for the custom kernel device as a
  strong endpoint signal, but retain the versioned indicator set in the event.
- Correlate an external overlay candidate with disabled kernel protections,
  driver-load telemetry, and remote session continuity.
- Do not sanction on UIAccess, window style, capture exclusion, a process name,
  or the Intel device link alone. Each can occur in legitimate software or can
  be renamed.
- Require `--require-kernel` for production sessions. User-mode inventories are
  explicitly marked untrusted and can be falsified after kernel compromise.

## Residual gaps

- A driver manually mapped before `AcTelemetry` target registration is not
  replayed by `PsSetLoadImageNotifyRoutine`.
- Manual mapping can bypass the normal image-load callback entirely.
- A hostile kernel driver can hide DOS devices, processes, windows, registry
  values, and target memory from the user-mode collector.
- Renaming removes exact process and device indicators unless the deployment
  supplies an updated signed indicator or manifest set.
- Kernel reads performed by an unrelated driver are not observable through
  documented process-handle callbacks. Preventing this class requires platform
  code-integrity policy, vulnerable-driver blocking, and an independently
  trusted server decision.
- UIAccess and capture exclusion are shared with legitimate accessibility and
  privacy software; the overlay classifier intentionally remains medium
  severity.

## Integration requirements

1. Launch the collector with the target PID and `--require-kernel` before the
   target is resumed.
2. Forward all JSONL records through the authenticated transport and monitor
   heartbeat and chain-head continuity.
3. Store the versioned indicator set centrally and correlate it with system
   posture and kernel coverage.
4. Reject evidence as incomplete when the driver is unavailable, callbacks are
   unhealthy, an event sequence is missing, or the kernel queue reports drops.
5. Keep endpoint findings separate from account enforcement and require
   corroborating server-side evidence.
