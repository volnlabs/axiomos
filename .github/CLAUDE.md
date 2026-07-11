# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

axiom-ebpf is a hobby x86-64 operating system kernel written in Rust. It boots via the Limine bootloader and runs on QEMU. The project aims for POSIX.1-2024 compliance.

**Primary Target:** x86_64-unknown-none (bare-metal)
**Toolchain:** Rust Nightly (configured in rust-toolchain.toml)
**Bootloader:** Limine v9.x

## Build Commands

```bash
# Build workspace libraries (recommended for validation)
cargo build --workspace --lib

# Full release build (creates axiomos.iso)
cargo build --release

# Format check
cargo fmt -- --check

# Lint (workspace libraries only to avoid bare-metal linker issues)
cargo clippy --workspace --lib -- -D clippy::all

# Test individual kernel crates
cargo test -p kernel_abi
cargo test -p kernel_vfs
cargo test -p kernel_physical_memory

# Test kernel_bpf (requires profile feature)
cargo test -p kernel_bpf                                              # uses default (embedded-profile)
cargo test -p kernel_bpf --no-default-features --features cloud-profile
cargo test -p kernel_bpf --no-default-features --features embedded-profile

# Miri tests for undefined behavior detection
cargo miri setup
cargo miri test -p kernel_abi
cargo miri test -p kernel_bpf --no-default-features --features cloud-profile

# Run in QEMU
cargo run                      # Default
cargo run -- --headless       # No GUI
cargo run -- --debug          # GDB on localhost:1234
cargo run -- --smp 4 --mem 512M
```

**System dependencies:** `sudo apt install -y xorriso e2fsprogs qemu-system`

## Critical Build Notes

- **Do NOT** run `cargo test` or `cargo clippy` without `--workspace --lib` - bare-metal targets will fail with linker errors
- The kernel crate cannot run standard unit tests due to its custom linker script
- Test kernel functionality through the separate kernel crates in `kernel/crates/`
- Full builds may have SSL errors downloading OVMF; use `--workspace --lib` for validation

## Architecture

```
kernel/                          # Main bare-metal kernel
├── src/
│   ├── arch/                   # Architecture abstraction (x86_64, riscv64, aarch64)
│   ├── driver/                 # Device drivers (VirtIO, PCI)
│   ├── file/                   # VFS and filesystem
│   ├── mcore/                  # Core kernel (multithreading, processes)
│   ├── mem/                    # Memory management
│   └── syscall/                # System call interface
├── crates/                     # Testable kernel subsystems (run tests here)
│   ├── kernel_abi/
│   ├── kernel_bpf/            # eBPF subsystem (requires profile feature)
│   ├── kernel_vfs/
│   ├── kernel_physical_memory/
│   ├── kernel_virtual_memory/
│   ├── kernel_elfloader/
│   ├── kernel_pci/
│   ├── kernel_syscall/
│   ├── kernel_device/
│   ├── kernel_devfs/
│   └── kernel_memapi/
└── linker-x86_64.ld           # Custom linker script

userspace/                      # Userspace components
├── init/                      # Init process
├── minilib/                   # Minimal C library
└── file_structure/            # Filesystem builder

src/main.rs                    # QEMU runner (builds kernel, launches emulation)
build.rs                       # Clones Limine, downloads OVMF, creates ISO
```

## Testability Philosophy

The kernel binary cannot have standard unit tests. Testable functionality is extracted into separate crates (`kernel_vfs`, `kernel_physical_memory`, etc.) that can be unit tested on the host system. When adding new kernel functionality, consider implementing it in a separate crate.

## Multi-Architecture Support

The project supports multiple architectures:
- **x86-64**: Fully supported (primary target)
- **RISC-V 64-bit**: Partial (demo kernel in `kernel/demos/riscv/`)
- **ARM 64-bit / Raspberry Pi 5**: Implemented with RP1 peripheral drivers

Architecture-specific code uses conditional compilation (`#[cfg(target_arch = "...")]`). The `kernel/src/arch/` module provides architecture abstraction with traits defined in `arch/traits.rs`.

### Raspberry Pi 5 Port

Build and deploy for Pi 5:
```bash
# Build kernel
./scripts/build-rpi5.sh

# Deploy to SD card
./scripts/deploy-rpi5.sh /path/to/sdcard/boot
```

Key files:
- `kernel/src/arch/aarch64/platform/rpi5/` - RP1 drivers (UART, GPIO)
- `kernel/src/arch/aarch64/boot.S` - ARM64 boot assembly
- `kernel/linker-aarch64.ld` - Linker script (loads at 0x80000)
- `kernel/platform/rpi5/config/config.txt` - Pi 5 boot configuration

Requires firmware shortcuts in config.txt:
- `pciex4_reset=0` - Keeps RP1 in firmware-initialized state
- `enable_rp1_uart=1` - Pre-configures UART at 115200 baud

RP1 peripheral addresses: UART at `0x1F00_0030_0000`, GPIO at `0x1F00_00D0_0000`

## Code Style

- All clippy warnings treated as errors (`-D clippy::all`)
- Rustfmt config: `imports_granularity = "Module"`, `group_imports = "StdExternalCrate"`
- Prefer safe Rust; all `unsafe` blocks must have safety comments
- Known intentional warnings: unused fields in memory region structs

## CI Pipeline

GitHub Actions runs: format check, clippy, tests (debug/release), Miri per-crate, and full build. Validate locally with:

```bash
cargo fmt -- --check
cargo clippy --workspace --lib -- -D clippy::all
cargo build --workspace --lib
cargo test -p <crate_name>
```
