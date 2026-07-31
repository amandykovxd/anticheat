#!/usr/bin/env python3
"""Create a harmless anonymous executable mapping for Linux sensor tests."""

from __future__ import annotations

import ctypes
import json
import mmap
import os
import signal
import sys
import time


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("linux_suspicious_fixture.py requires Linux", file=sys.stderr)
        return 2

    mapping = mmap.mmap(
        -1,
        mmap.PAGESIZE,
        flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
        prot=mmap.PROT_READ | mmap.PROT_WRITE,
    )
    mapping[:24] = b"ANTICHEAT_TEST_FIXTURE\0\0"
    view = ctypes.c_char.from_buffer(mapping)
    address = ctypes.addressof(view)
    del view
    libc = ctypes.CDLL(None, use_errno=True)
    mprotect = libc.mprotect
    mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    mprotect.restype = ctypes.c_int
    if mprotect(
        address,
        mmap.PAGESIZE,
        mmap.PROT_READ | mmap.PROT_EXEC,
    ) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))

    stopped = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(
        json.dumps(
            {
                "fixture": "anonymous_executable_region",
                "pid": os.getpid(),
                "address": f"0x{address:x}",
                "size": mmap.PAGESIZE,
                "payload_executed": False,
            },
            separators=(",", ":"),
        ),
        flush=True,
    )

    try:
        deadline = time.monotonic() + 30.0
        while not stopped and time.monotonic() < deadline:
            time.sleep(0.1)
    finally:
        if mprotect(
            address,
            mmap.PAGESIZE,
            mmap.PROT_READ | mmap.PROT_WRITE,
        ) != 0:
            return 1
        mapping.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
