# RISC-V Kernel Demo with OpenSBI Integration

This is a minimal demonstration kernel showing OpenSBI bootloader integration for RISC-V.

## Features

- ✅ Boot assembly entry point (`boot.S`)
- ✅ OpenSBI SBI calls for console output
- ✅ Device tree blob (DTB) address capture
- ✅ Proper linker script for physical address loading
- ✅ Hart ID handling (multi-core aware)
- ✅ BSS section clearing

## Building

```bash
cd kernel/riscv-demo
cargo build
```

## Running with QEMU

```bash
qemu-system-riscv64 \
  -machine virt \
  -bios default \
  -kernel target/riscv64gc-unknown-none-elf/debug/riscv-kernel-demo \
  -nographic
```

## Expected Output

```
OpenSBI v0.9
...
axiom-ebpf RISC-V Kernel
=======================
Hart ID: 0
DTB Address: 0x87000000

OpenSBI integration successful!
Kernel booted via OpenSBI firmware

This is a minimal demonstration kernel showing:
  - Boot assembly entry point
  - OpenSBI SBI calls (console output)
  - Device tree blob address capture
  - Proper linker script usage

Halting...
```

## Boot Process

1. **OpenSBI Firmware** (M-mode)
   - Initializes platform
   - Loads kernel at `0x80200000`
   - Passes hart_id in `a0`, DTB address in `a1`
   - Jumps to kernel `_start`

2. **Boot Assembly** (`boot.S`)
   - Saves boot arguments
   - Filters secondary harts (only hart 0 continues)
   - Clears BSS section
   - Sets up stack
   - Calls Rust entry point `_start_rust`

3. **Rust Kernel** (`main.rs`)
   - Receives boot info
   - Makes SBI calls for console I/O
   - Prints boot information
   - Halts in WFI loop

## Files

- `src/main.rs` - Rust kernel code with SBI console
- `src/boot.S` - Assembly entry point
- `linker.ld` - Linker script for physical address `0x80200000`
- `build.rs` - Build script to compile assembly
- `.cargo/config.toml` - Cargo configuration for RISC-V target

## Integration with Main Kernel

This demo shows the working OpenSBI integration. To integrate into the main axiomos kernel:

1. Add boot assembly compilation to main kernel build
2. Implement device tree parsing
3. Set up page tables for higher-half kernel
4. Initialize physical memory allocator from DTB
5. Port remaining architecture-specific modules

## References

- [RISC-V SBI Specification](https://github.com/riscv-non-isa/riscv-sbi-doc)
- [OpenSBI Documentation](https://github.com/riscv-software-src/opensbi)
- [RISC-V Privileged Specification](https://riscv.org/technical/specifications/)
