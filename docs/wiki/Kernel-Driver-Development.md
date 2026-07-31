# Kernel Driver Development

## Toolchain

Use Visual Studio 2022 with Desktop C++ support. `driver\packages.config` pins
the x64 WDK and SDK packages so CI and local builds restore the same dependency
set; `driver\Directory.Build.props` imports them into the project.

```powershell
nuget restore driver\packages.config -PackagesDirectory driver\packages
msbuild driver\AcTelemetry.vcxproj `
  /p:Configuration=Release `
  /p:Platform=x64
```

Validate the INF and package before deployment:

```powershell
InfVerif.exe /w driver\AcTelemetry.inf
```

Development packages must be test-signed and loaded only on isolated test
systems. Production packages require an applicable Microsoft signing path.

## Required review areas

Every driver change must review:

- callback registration and unload ordering;
- IRQL and pageable-code constraints;
- nonpaged allocation lifetime;
- queue synchronization and overflow behavior;
- integer conversion and structure layout;
- IOCTL input, output, and returned-byte validation;
- device ACL and handle exclusivity;
- target PID lifecycle and PID reuse;
- failure cleanup after partial initialization.

## Prohibited implementation classes

The project does not accept:

- arbitrary kernel or process-memory read/write IOCTLs;
- SSDT, IDT, dispatch-table, or executable-code hooks;
- kernel or user code patching;
- process, module, driver, handle, file, or registry hiding;
- remote-thread creation;
- callback-based blocking or termination;
- `METHOD_NEITHER` user pointers;
- embedded production signing material.

## Reliability qualification

Production readiness requires static driver analysis, Driver Verifier,
concurrent I/O tests, queue saturation, repeated load/unload, crash-dump
triage, HLK validation, and an explicit Windows support matrix.
