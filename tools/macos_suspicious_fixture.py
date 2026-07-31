#!/usr/bin/env python3
"""Create a harmless anonymous executable mapping for collector validation.

The mapping contains diagnostic bytes and is never called. This fixture exists
only to exercise macOS executable-region telemetry in a controlled process.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import mmap
import os
import signal
import sys
import time
from dataclasses import dataclass


PROT_READ = mmap.PROT_READ
PROT_WRITE = mmap.PROT_WRITE
PROT_EXEC = mmap.PROT_EXEC


@dataclass
class FixtureMapping:
    mapping: mmap.mmap
    address: int
    size: int
    mode: str


def _address_of(mapping: mmap.mmap) -> int:
    view = ctypes.c_char.from_buffer(mapping)
    address = ctypes.addressof(view)
    del view
    return address


def _mprotect(address: int, size: int, protection: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.mprotect
    function.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    function.restype = ctypes.c_int
    if function(address, size, protection) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _allocate(mode: str) -> FixtureMapping:
    size = mmap.PAGESIZE
    flags = mmap.MAP_PRIVATE | mmap.MAP_ANON

    if mode == "rwx":
        mapping = mmap.mmap(
            -1,
            size,
            flags=flags,
            prot=PROT_READ | PROT_WRITE | PROT_EXEC,
        )
        mapping[:24] = b"ANTICHEAT_TEST_FIXTURE\0\0"
        return FixtureMapping(mapping, _address_of(mapping), size, mode)

    mapping = mmap.mmap(
        -1,
        size,
        flags=flags,
        prot=PROT_READ | PROT_WRITE,
    )
    mapping[:24] = b"ANTICHEAT_TEST_FIXTURE\0\0"
    address = _address_of(mapping)
    _mprotect(address, size, PROT_READ | PROT_EXEC)
    return FixtureMapping(mapping, address, size, mode)


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a non-executed anonymous executable mapping on macOS."
    )
    parser.add_argument(
        "--mode",
        choices=("rwx", "rx"),
        default="rx",
        help="mapping permissions (default: rx)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=300.0,
        help="seconds to retain the mapping; 0 waits until interrupted",
    )
    arguments = parser.parse_args()
    if arguments.duration < 0:
        parser.error("--duration must be non-negative")
    return arguments


def main() -> int:
    if sys.platform != "darwin":
        print("macos_suspicious_fixture.py requires macOS", file=sys.stderr)
        return 2

    arguments = _parse_arguments()
    try:
        fixture = _allocate(arguments.mode)
    except OSError as error:
        print(f"unable to create {arguments.mode} fixture mapping: {error}", file=sys.stderr)
        return 1
    stop_requested = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    print(
        json.dumps(
            {
                "fixture": "anonymous_executable_region",
                "pid": os.getpid(),
                "address": f"0x{fixture.address:x}",
                "size": fixture.size,
                "mode": fixture.mode,
                "payload_executed": False,
            },
            separators=(",", ":"),
        ),
        flush=True,
    )

    deadline = (
        time.monotonic() + arguments.duration if arguments.duration > 0 else None
    )
    try:
        while not stop_requested and (
            deadline is None or time.monotonic() < deadline
        ):
            time.sleep(0.1)
    finally:
        if fixture.mode == "rx":
            _mprotect(fixture.address, fixture.size, PROT_READ | PROT_WRITE)
        fixture.mapping.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
