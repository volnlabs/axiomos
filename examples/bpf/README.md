# BPF Examples for axiomos

This directory contains example BPF programs for the axiomos kernel.

## Quick Start

### Raw Bytecode (Current Approach)

axiomos currently loads BPF programs as raw bytecode via the `sys_bpf` syscall:

```rust
// Example: Simple program that returns 42
let insns = [
    BpfInsn { code: 0xb7, dst_src: 0x00, off: 0, imm: 42 }, // r0 = 42
    BpfInsn { code: 0x95, dst_src: 0x00, off: 0, imm: 0 },  // exit
];

// Load via sys_bpf(BPF_PROG_LOAD, attr, size)
let prog_id = bpf(5, attr_ptr, size);

// Attach to timer (type=1) or syscall (type=2)
let res = bpf(8, attach_attr_ptr, size);
```

### C BPF Programs (Reference)

The `hello.bpf.c` file shows the standard C structure for BPF programs.

To compile (requires clang with BPF target):
```bash
clang -target bpf -O2 -c hello.bpf.c -o hello.bpf.o
```

## Attach Points

| Type | Event | Description |
|------|-------|-------------|
| 1 | Timer | Executes on every timer interrupt |
| 2 | Syscall | Executes at syscall entry |

## Helper Functions

| ID | Name | Description |
|----|------|-------------|
| 1 | `bpf_ktime_get_ns` | Get current kernel time in nanoseconds |
| 2 | `bpf_trace_printk` | Print debug message to kernel log |

## BpfAttr Structure

```rust
#[repr(C)]
pub struct BpfAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,        // ptr to instructions
    pub license: u64,      // ptr to license string
    // ... (for attach)
    pub attach_btf_id: u32,   // attach type
    pub attach_prog_fd: u32,  // program id
}
```

## Example: Timer Hook

See `userspace/core/init/src/main.rs` for a complete working example that:
1. Loads a BPF program
2. Attaches it to the timer interrupt
3. Observes execution via kernel logs
