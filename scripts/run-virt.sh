#!/bin/bash
set -e

# Generate disk.img by building the root package for aarch64
echo "Building root package for aarch64 to generate disk.img..."
cargo build -p axiomos --target aarch64-unknown-none --no-default-features --features aarch64_deps

# The build.rs generates the image in the target directory.
# We find it and copy it to the root.
# Pick the most recently modified disk.img to avoid stale build artifacts
DISK_PATH=$(find target/aarch64-unknown-none -name disk.img -printf "%T@ %p\n" | sort -n | tail -n 1 | awk '{print $2}')
if [ -n "$DISK_PATH" ]; then
    echo "Using disk image: $DISK_PATH"
    cp "$DISK_PATH" disk.img
else
    echo "Error: disk.img not found in target/aarch64-unknown-none"
    exit 1
fi

# Build the kernel for QEMU virt
cargo build --target aarch64-unknown-none --features virt,cloud-profile -p kernel

# Run in QEMU
# Added virtio-blk-device for disk.img
timeout 600s qemu-system-aarch64 \
    -machine virt \
    -m 1G \
    -cpu cortex-a57 \
    -nographic \
    -kernel target/aarch64-unknown-none/debug/kernel \
    -drive if=none,file=disk.img,format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -d guest_errors,unimp \
    -semihosting
