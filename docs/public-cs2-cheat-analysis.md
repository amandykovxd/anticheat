# Public CS2 Cheat Defensive Analysis

## Scope

This document records static defensive analysis of public source revisions. No
binary was built or executed. Repository names and file names are versioned
indicators only; behavioral controls must remain effective after renaming.

| Project | Revision | Access model | Rendering and input |
| --- | --- | --- | --- |
| [Osiris](https://github.com/danielkrupinski/Osiris) | `f314a97592a8176912a9dd9741846b97601a0622` | In-process DLL; loader or manual map | Panorama, SDL callback replacement, copied VMT |
| [Valthrun CS2](https://github.com/Valthrun/valthrun-cs2) | `ac08b2d70659f36699b157e100efa4cef365ac52` | External client backed by a kernel interface | Capture-excluded external overlay; kernel input |
| [CS2_External](https://github.com/TKazer/CS2_External) | `b7e3b41687ce6ba798975741d9a9755249d1b65c` | `OpenProcess`, RPM, and WPM | D3D11 overlay and synthetic mouse input |
| [deadlocked](https://github.com/avitran0/deadlocked) | `1c5bbb22698f8ff80e71c44b76ea92058fb989b9` | Linux `process_vm_readv/writev` and procfs | X11 overlay and `/dev/uinput` |
| [WilonityLoader](https://github.com/WilonityDev/WilonityLoader) | `746ed119aa5af48ef371e220e178f3ee539cd764` | Not established from repository contents | Generic runtime DLLs only |
| [cs2-sdk](https://github.com/bruhmoment21/cs2-sdk) | `a19f4a5cce937539c865e59596e5471e38568ed7` | In-process DLL | Funchook trampolines, DX11/Vulkan, SDL, WndProc |

## Defensive mapping

### Internal mapped components

Osiris initializes from `DllMain`, replaces an SDL function pointer, and
redirects a view-render object to a copied VMT. The copied VMT changes writable
dispatch data rather than the original executable section. A manual-mapped
payload is covered by private/unlinked executable-region classification; a
loader-visible payload requires manifest authorization. Game integrations must
configure `--watch-pointer` for critical callback slots and `--watch-vtable`
for global object-pointer slots.

The cs2-sdk revision creates an initialization thread and installs trampoline
hooks through funchook. Executable-section comparison and private executable
region classification cover persistent trampolines. Kernel thread telemetry
provides a separate start-address correlation signal. WndProc replacement is
covered by target-window dispatch validation.

### External user-mode access

CS2_External requests broad target process rights and uses RPM/WPM. The kernel
Object Manager callback records dangerous handle creation and duplication,
including the requestor PID, access mask, and process path. Its topmost,
transparent, capture-excluded overlay is covered by behavioral overlay
classification. Data-only writes are not equivalent to executable-section
modification and require game/server state validation.

### External kernel-backed access

Valthrun uses a native Object Manager device rather than requiring a DOS
symbolic link. The collector therefore inventories both `QueryDosDeviceW`
names and the native `\Device` directory. A startup PSAPI snapshot records
drivers loaded before target registration; image callbacks record subsequent
loader-mediated driver loads. A pinned driver manifest supplies local
authorization input. Manual kernel mapping and malicious ring-0 falsification
remain outside authoritative local detection.

The overlay is independently classifiable by topmost, transparent,
capture-excluded, and target-overlap properties. Direct attribution of packets
in the Windows input class stack is not available through a documented passive
API; driver identity, overlay behavior, target state, and server-side input
statistics must be correlated.

### Linux external access

deadlocked reads through `process_vm_readv`, optionally writes through
`process_vm_writev`, opens procfs memory, creates a uinput device, and uses an
always-on-top X11 overlay. The Linux collector covers target tracing,
`/proc/<pid>/mem` file descriptors, `/dev/uinput` ownership, and suspicious
executable mappings. Observation of process-vm system calls requires an
integrator-owned eBPF LSM or audit rule and is explicitly reported as a
coverage gap when absent.

### Unverifiable package

The WilonityLoader revision contains no loader executable, driver, installer,
or implementation source. The committed FFmpeg, EGL/GLES, ICU, and shader
compiler files are common runtime components and are not suitable standalone
indicators. Analysis requires the distributed installer or executable,
Authenticode metadata, embedded payload inventory, service/device creation,
and protocol behavior. Blocking the generic DLL names would create excessive
false positives.

## Correlation policy

High-confidence correlation should combine independent sources:

1. a foreign process requests dangerous target access;
2. an external overlay strongly overlaps the target and excludes capture;
3. an unknown driver or native device is present;
4. a thread start, function pointer, VMT entry, or WndProc resolves outside
   authorized loader-visible modules;
5. the module or driver identity violates the pinned manifest;
6. server-side state or input behavior is inconsistent with the game rules.

A single public name, file path, window title, device name, or hash must not be
used as an account-level enforcement decision.
