#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

if [ -z "${AXIOM_BPF_TRUSTED_KEY_PATH:-}" ] || [ ! -f "$AXIOM_BPF_TRUSTED_KEY_PATH" ]; then
    echo "Error: AXIOM_BPF_TRUSTED_KEY_PATH must name a 32-byte Ed25519 public key."
    echo "The key is compiled into the kernel; this script will not generate a substitute."
    exit 1
fi
if [ "$(wc -c < "$AXIOM_BPF_TRUSTED_KEY_PATH")" -ne 32 ]; then
    echo "Error: AXIOM_BPF_TRUSTED_KEY_PATH must contain exactly 32 bytes."
    exit 1
fi
AXIOM_BPF_TRUSTED_KEY_PATH=$(realpath "$AXIOM_BPF_TRUSTED_KEY_PATH")
export AXIOM_BPF_TRUSTED_KEY_PATH

ARTIFACT_PATHS=$(mktemp "$PROJECT_DIR/target/virt-artifacts.XXXXXX")
trap 'rm -f "$ARTIFACT_PATHS"' EXIT
export AXIOM_ARTIFACT_PATHS="$ARTIFACT_PATHS"

# Generate disk.img by building the root package for aarch64
echo "Building root package for aarch64 to generate disk.img..."
cargo build -p axiomos --target aarch64-unknown-none --no-default-features --features aarch64_deps

# Consume the output path from this exact build invocation. Selecting the
# newest target-directory file would make stale artifacts part of the boot.
DISK_PATH=$(sed -n 's/^DISK_IMAGE=//p' "$ARTIFACT_PATHS")
if [ -z "$DISK_PATH" ] || [ ! -f "$DISK_PATH" ]; then
    echo "Error: build did not report a valid DISK_IMAGE in $ARTIFACT_PATHS"
    exit 1
fi
echo "Using disk image: $DISK_PATH"
echo "Disk image SHA-256: $(sha256sum "$DISK_PATH" | awk '{print $1}')"
echo "Trusted key SHA-256: $(sha256sum "$AXIOM_BPF_TRUSTED_KEY_PATH" | awk '{print $1}')"

# Build the kernel for QEMU virt
cargo build --target aarch64-unknown-none --features virt,cloud-profile -p kernel

# Run in QEMU
# Use the exact image reported above; no root-level copy or timestamp search.
timeout 600s qemu-system-aarch64 \
    -machine virt \
    -m 1G \
    -cpu cortex-a57 \
    -nographic \
    -kernel target/aarch64-unknown-none/debug/kernel \
    -drive if=none,file="$DISK_PATH",format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -d guest_errors,unimp \
    -semihosting
