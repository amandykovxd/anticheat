# Anticheat Telemetry Engineering Wiki

Anticheat Telemetry is a Windows Ring 0/3 process-integrity telemetry system.
It combines an optional WDM driver, a user-mode memory and module collector, a
versioned IOCTL ABI, and tamper-evident JSONL output.

The implementation produces telemetry only. Enforcement, account actions,
production transport credentials, and game-specific policy remain
integrator-owned.

## Entry points

- [Architecture](Architecture)
- [Integration](Integration)
- [Kernel driver development](Kernel-Driver-Development)
- [Event pipeline](Event-Pipeline)
- [Security operations](Security-Operations)
- [Contribution workflow](Contribution-Workflow)
- [Engineering project](https://github.com/users/amandykovxd/projects/1)
- [Source repository](https://github.com/amandykovxd/anticheat)

## Current implementation

Implemented components:

- x64 `AcTelemetry.sys` WDM telemetry driver;
- x64 and Win32 `anticheat.exe` collector;
- reduced-scope macOS and Linux collectors;
- fixed-size versioned buffered IOCTL protocol;
- process, image-load, thread, and process-handle callback telemetry;
- module and executable-memory classification;
- pinned module/driver manifest and configured dispatch validation;
- event de-duplication and bounded scan budgets;
- JSONL rotation and SHA-256 integrity chain;
- authenticated transport sidecar and reference receiver;
- WDK x64, collector, sanitizer, and CodeQL validation workflows.

Production deployment still requires Driver Verifier, HLK validation, package
signing, installer lifecycle tests, and an integrator-owned correlation
service.
