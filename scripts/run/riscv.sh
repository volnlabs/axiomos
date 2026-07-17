#!/bin/bash
set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Running axiomos RISC-V demo kernel in QEMU..."
echo "================================================"
echo ""

KERNEL_PATH="$SCRIPT_DIR/../../kernel/demos/riscv/target/riscv64gc-unknown-none-elf/debug/riscv-kernel-demo"

# Check if kernel exists
if [ ! -f "$KERNEL_PATH" ]; then
    echo "Error: Kernel not found at $KERNEL_PATH"
    echo "Please run ./scripts/build-riscv.sh first"
    exit 1
fi

echo "Kernel: $KERNEL_PATH"
echo ""
echo "Press Ctrl+A then X to exit QEMU"
echo "================================================"
echo ""

qemu-system-riscv64 \
    -machine virt \
    -bios default \
    -kernel "$KERNEL_PATH" \
    -nographic \
    -serial mon:stdio
