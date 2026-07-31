---
layout: default
title: Anticheat Telemetry
---

# Anticheat Telemetry

Anticheat Telemetry is a Windows Ring 0/3 process-integrity sensor consisting
of an optional x64 WDM telemetry driver, an x64/Win32 user-mode collector, a
versioned buffered IOCTL ABI, and tamper-evident JSONL output.

The implementation records telemetry only. It does not patch memory, hide
objects, block image loads, terminate processes, or implement account
enforcement.

## Technical documentation

- [System architecture](wiki/Architecture.html)
- [Integrator sequence](wiki/Integration.html)
- [Kernel driver development](wiki/Kernel-Driver-Development.html)
- [Event pipeline](wiki/Event-Pipeline.html)
- [Security operations](wiki/Security-Operations.html)
- [Contribution workflow](wiki/Contribution-Workflow.html)
- [Driver ABI and lifecycle](driver-integration.html)
- [Authenticated transport and remote anchoring](transport-integration.html)
- [Event schema](event-schema.html)
- [Adversarial analysis](adversarial-analysis.html)
- [Engineering project contract](project-board.html)

## Engineering coordination

- [GitHub repository](https://github.com/amandykovxd/anticheat)
- [Engineering project](https://github.com/users/amandykovxd/projects/1)
- [Roadmap](https://github.com/amandykovxd/anticheat/blob/main/ROADMAP.md)
- [Open issues](https://github.com/amandykovxd/anticheat/issues)
- [Technical discussions](https://github.com/amandykovxd/anticheat/discussions)
- [Private vulnerability reporting](https://github.com/amandykovxd/anticheat/security/advisories/new)

## Build status

[Windows x64, Win32, and sanitizer CI](https://github.com/amandykovxd/anticheat/actions/workflows/windows-build.yml)
and
[CodeQL C/C++ analysis](https://github.com/amandykovxd/anticheat/actions/workflows/codeql.yml)
run on changes to the protected `main` branch and on pull requests.
