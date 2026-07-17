#!/bin/bash
set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building axiomos RISC-V demo kernel..."
echo "=========================================="
echo ""
echo "Note: This builds the demo kernel (kernel/demos/riscv/)"
echo "The full kernel port is still in progress."
echo ""

# Add RISC-V target if not already installed
rustup target add riscv64gc-unknown-none-elf

# Build the RISC-V demo kernel
cd "$SCRIPT_DIR/../../kernel/demos/riscv"
cargo build

echo ""
echo "✅ Build complete!"
echo ""
echo "Kernel binary: kernel/demos/riscv/target/riscv64gc-unknown-none-elf/debug/riscv-kernel-demo"
echo ""
echo "To run in QEMU:"
echo "  cargo xtask run riscv"
echo ""
echo "Or manually:"
echo "  qemu-system-riscv64 \\"
echo "    -machine virt \\"
echo "    -bios default \\"
echo "    -kernel kernel/demos/riscv/target/riscv64gc-unknown-none-elf/debug/riscv-kernel-demo \\"
echo "    -nographic"
echo ""
