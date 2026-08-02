#!/bin/sh
set -eu

key=anticheat_process_vm

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditctl is required" >&2
    exit 1
fi

auditctl -a always,exit -F arch=b64 \
    -S process_vm_readv -S process_vm_writev -k "$key"

if [ "$(uname -m)" = "x86_64" ]; then
    auditctl -a always,exit -F arch=b32 \
        -S process_vm_readv -S process_vm_writev -k "$key"
fi

auditctl -l | grep "$key"
