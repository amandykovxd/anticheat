# Architecture

## Component model

```text
Protected application
        |
        | PID and process identity
        v
anticheat.exe
  user-mode module inventory
  executable-memory classification
  bounded hashing and probing
        |
        | versioned METHOD_BUFFERED IOCTL
        v
AcTelemetry.sys
  process callbacks
  image-load callbacks
  bounded nonpaged event queue
        |
        v
tamper-evident JSONL
        |
        v
integrator transport, storage, correlation, and policy
```

## Kernel boundary

The driver registers documented process and image-load callbacks for one
active target PID. It stores fixed-size records in a preallocated queue and
does not perform target-memory scanning in callback context.

The device is exclusive and restricted to `SYSTEM`. Target registration is
bound to a random protocol session ID. All requests use fixed-size structures
and `METHOD_BUFFERED`.

## User boundary

The collector validates process identity, opens the target with read-only
process rights, inventories loader-visible modules, maps executable virtual
memory, and emits classified findings.

The Win32 module, virtual-memory, and read APIs are not a trusted security
boundary. Scan records identify this source as untrusted. Kernel image-load
bases are correlated with the next module snapshot so cross-source omissions
remain visible, subject to legitimate unload races.

The collector does not request process write, operation, terminate, or
remote-thread rights.

## Integrator boundary

Integrators own:

- launcher sequencing and target PID selection;
- driver installation and signing;
- collector service identity and ACLs;
- JSONL forwarding and retention;
- server-issued session identity;
- signal correlation and enforcement policy;
- compatibility and false-positive qualification.

A hostile kernel driver can manipulate both callback and user-mode views. The
architecture raises attacker cost but does not claim local authority against a
same-ring adversary.

See the repository
[security model](https://github.com/amandykovxd/anticheat/blob/main/SECURITY.md)
for the complete trust boundary.
