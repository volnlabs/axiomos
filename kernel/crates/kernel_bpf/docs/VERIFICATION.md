# BPF Verifier Guide

This document explains how the BPF verifier ensures program safety.

## Overview

The verifier performs static analysis on BPF programs before execution to guarantee:
- No out-of-bounds memory access
- No use of uninitialized data
- No infinite loops (bounded iteration)
- No division by zero
- No stack overflow
- Profile-specific constraints are met, including a static WCET (worst-case
  execution time) bound per program on the embedded profile

The verifier is load-bearing: `sys_bpf` calls it on every program load (#48) —
a program that fails verification does not load.

## Verification Pipeline

```
┌────────────┐    ┌─────────────┐    ┌──────────────┐    ┌────────────┐
│   Parse    │───▶│  Build CFG  │───▶│   Analyze    │───▶│  Verified  │
│  Program   │    │             │    │   States     │    │  Program   │
└────────────┘    └─────────────┘    └──────────────┘    └────────────┘
      │                  │                  │
      ▼                  ▼                  ▼
   Invalid           Unreachable        Safety
   Opcodes           Code Found         Violations
```

## Using the Verifier

The entry points are associated functions on `Verifier<P>` taking raw
instructions; on success they return the constructed `BpfProgram<P>`.

### Basic Usage

```rust
use kernel_bpf::verifier::Verifier;
use kernel_bpf::profile::ActiveProfile;
use kernel_bpf::bytecode::program::BpfProgType;

// Zero-config: ctx / map-value accesses are rejected because no region
// sizes are known.
let program = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns)?;
```

### With Region Sizes (`VerifyConfig`)

This is what the `sys_bpf` load path does: it supplies the context size and
per-map value sizes so `PtrToCtx` / `PtrToMapValue` accesses can be
bounds-checked precisely.

```rust
use kernel_bpf::verifier::{Verifier, VerifyConfig};

let config = VerifyConfig {
    ctx_size: core::mem::size_of::<BpfContext>() as u32,
    map_value_size: 64,        // fallback (e.g. ringbuf_reserve returns)
    map_value_sizes: &[8, 64], // exact accessible bytes, indexed by map id
};

let program = Verifier::<ActiveProfile>::verify_with_config(
    BpfProgType::SocketFilter, &insns, config)?;
```

A `bpf_map_lookup_elem` whose map-id register holds a known constant `id`
yields exactly `map_value_sizes[id]` accessible bytes; a known id outside the
table is rejected; a dynamic id is bounded to the smallest entry (sound —
never over-permits any reachable map).

### With Cost Stats

```rust
let (program, stats) = Verifier::<ActiveProfile>::verify_with_stats(
    BpfProgType::SocketFilter, &insns, config)?;

stats.states_explored; // verification cost (distinct states)
stats.wcet_cycles;     // static worst-case execution bound, cycle units
```

Verification runs in phases: basic checks → CFG construction → profile
structural constraints (loop-freedom, helper allow-list, WCET budget — checked
*before* path-sensitive exploration, so an over-budget program is refused
without paying exploration cost) → path-sensitive safety exploration.

## Verification Checks

### 1. Opcode Validation

Every instruction must have a valid opcode:

```rust
// Valid
BpfInsn::mov64_imm(0, 42)  // 0xb7 - known opcode

// Invalid - will fail verification
BpfInsn::new(0xFF, 0, 0, 0, 0)  // 0xFF - invalid opcode
```

**Error:** `VerifyError::InvalidOpcode { insn_idx: usize, opcode: u8 }`

### 2. Register Initialization

Registers must be initialized before use:

```rust
// BAD: R1 is used but never initialized
let bad_program = ProgramBuilder::new(BpfProgType::SocketFilter)
    .insn(BpfInsn::mov64_reg(0, 1))  // R0 = R1, but R1 is undefined!
    .insn(BpfInsn::exit())
    .build()?;

// GOOD: R1 is initialized first
let good_program = ProgramBuilder::new(BpfProgType::SocketFilter)
    .insn(BpfInsn::mov64_imm(1, 42)) // R1 = 42
    .insn(BpfInsn::mov64_reg(0, 1))  // R0 = R1
    .insn(BpfInsn::exit())
    .build()?;
```

**Error:** `VerifyError::UninitializedRegister { insn_idx: usize, reg: u8 }`

### 3. Frame Pointer Protection

R10 (frame pointer) is read-only:

```rust
// BAD: Writing to R10
let bad = ProgramBuilder::new(BpfProgType::SocketFilter)
    .insn(BpfInsn::mov64_imm(10, 0))  // R10 = 0, FORBIDDEN!
    .insn(BpfInsn::exit())
    .build()?;
```

**Error:** `VerifyError::WriteToReadOnly { insn_idx: usize, reg: u8 }`

### 4. Division by Zero

Division/modulo by zero is detected:

```rust
// BAD: Division by zero
let bad = ProgramBuilder::new(BpfProgType::SocketFilter)
    .insn(BpfInsn::mov64_imm(0, 100))
    .insn(BpfInsn::div64_imm(0, 0))  // R0 /= 0, FORBIDDEN!
    .insn(BpfInsn::exit())
    .build()?;
```

**Error:** `VerifyError::DivisionByZero { insn_idx: usize }`

### 5. Exit Requirement

Every program must have at least one reachable exit:

```rust
// BAD: No exit instruction
let bad = ProgramBuilder::new(BpfProgType::SocketFilter)
    .insn(BpfInsn::mov64_imm(0, 42))
    // Missing exit!
    .build()?;

// BAD: Infinite loop, no reachable exit
let bad = ProgramBuilder::new(BpfProgType::SocketFilter)
    .insn(BpfInsn::ja(0))  // Jump to self forever
    .insn(BpfInsn::exit()) // Never reached
    .build()?;
```

**Error:** `VerifyError::InfiniteLoop { insn_idx }` (jump-to-self) or `VerifyError::UnreachableInstruction { insn_idx }`

### 6. Bounded Iteration

Loops must be provably bounded:

```rust
// GOOD: Loop with clear termination
let good = ProgramBuilder::new(BpfProgType::SocketFilter)
    .insn(BpfInsn::mov64_imm(0, 0))      // counter = 0
    .insn(BpfInsn::mov64_imm(1, 10))     // limit = 10
    .insn(BpfInsn::jeq_reg(0, 1, 2))     // if counter == limit, exit
    .insn(BpfInsn::add64_imm(0, 1))      // counter++
    .insn(BpfInsn::ja(-3))               // goto loop
    .insn(BpfInsn::exit())
    .build()?;
```

The verifier tracks loop iterations and fails if the bound cannot be determined.

**Error:** `VerifyError::UnboundedLoop { insn_idx: usize }`

### 7. Stack Bounds

Stack access must be within bounds:

```rust
// Stack grows downward from R10
// Valid range: [R10 - MAX_STACK_SIZE, R10)

// GOOD: Valid stack access
let offset = -8;  // 8 bytes below frame pointer
// store to stack: *(R10 + offset) = value

// BAD: Stack overflow
let offset = -600_000;  // Way below stack limit
// Error: StackOutOfBounds
```

**Error:** `VerifyError::OutOfBoundsAccess { insn_idx, .. }` (bad offset) or `VerifyError::StackExceeded { needed, limit }` (depth over profile limit)

### 8. Memory Access

Pointer arithmetic and memory access are validated:

```rust
// Pointer must be valid before dereference
// Offset must be within object bounds
// Access size must match instruction

// BAD: Null pointer dereference
// BAD: Out-of-bounds access
// BAD: Misaligned access (if strict_alignment enabled)
```

**Error:** `VerifyError::InvalidMemoryAccess { insn_idx, .. }` or `VerifyError::OutOfBoundsAccess { insn_idx, .. }`

## Control Flow Graph

The verifier builds a CFG to analyze all possible execution paths:

```rust
use kernel_bpf::verifier::cfg::ControlFlowGraph;

let cfg = ControlFlowGraph::build(&insns);

// Analyze basic blocks
for block in cfg.blocks() {
    println!("Block {}: instructions {}-{}",
        block.id, block.start, block.end);
    println!("  Successors: {:?}", block.successors);
    println!("  Predecessors: {:?}", block.predecessors);
}

// Check reachability
for unreachable in cfg.unreachable_blocks() {
    println!("Warning: unreachable code at {}", unreachable);
}
```

### CFG Example

```
Program:
  0: mov64 r0, 0
  1: jeq r1, 0, +2
  2: mov64 r0, 1
  3: ja +1
  4: mov64 r0, 2
  5: exit

CFG:
  Block 0 (insn 0-1): successors=[1, 2]
  Block 1 (insn 2-3): predecessors=[0], successors=[3]
  Block 2 (insn 4):   predecessors=[0], successors=[3]
  Block 3 (insn 5):   predecessors=[1, 2]
```

## State Tracking

The verifier tracks an abstract state per register and stack slot
(`verifier/state.rs`). Each register's abstraction is a **tnum**
(known-bits tracking) × **unsigned interval**, plus a register-type lattice
(scalar, stack pointer, ctx pointer, map-value pointer — pointers from map
lookups are *maybe-null* until a null check clears the flag). Stack state is
sparse (#118): only touched slots cost memory.

Supporting analyses, each its own module, are wired into the core paths:

| Module | Wired into | Role |
|---|---|---|
| `state.rs` (tnum) | `verify_alu` (#102) | known-bits through ALU ops, width-correct 32-bit semantics (#114) |
| `refine.rs` | `verify_jump` (#105) | branch-condition range refinement on both arms |
| `pruner.rs` | `verify_safety` (#103) | state subsumption; recorded-state budget caps exploration (#116) |
| `liveness.rs` | pruner subsumption (#104) | dead registers don't block pruning |

### Value Tracking Example

```
// Initial: R0 known to be 10
R0: tnum=0b1010 exact, range [10, 10]

// After: add64 r0, r1  (R1 in [0, 100])
R0: range [10, 110]

// After: if r0 < 50 goto ...
// True branch:  R0 range [10, 49]
// False branch: R0 range [50, 110]
```

## WCET Cost Model & Admission

Beyond safety, the verifier bounds *execution* cost (Track C, #43).
`verifier/cost.rs` assigns each instruction a static cycle cost (per-helper
costs included, calibrated on Pi 5 Cortex-A76 — `CYCLE_UNIT_NS = 6` ns/unit)
and computes the program's WCET as the longest path through its loop-free CFG.
The result lands in `VerifyStats::wcet_cycles`.

Two enforcement points consume it on the embedded profile:

- **Per-program budget (verifier):** WCET over `WCET_CYCLE_BUDGET`
  (`RT_PERIOD_NS / CYCLE_UNIT_NS` = 1,000,000 / 6 ≈ 166,666 units — one 1 kHz
  control-loop period) rejects with `WcetExceeded` before exploration.
- **Utilization admission (kernel):** each attach commits
  `wcet × CYCLE_UNIT_NS × freq` ns/s to an `AdmissionLedger`
  (`verifier/admission.rs`); the sum across all attached programs is capped at
  `UTILIZATION_BUDGET_NS_PER_S` = 5×10⁸ (U = 0.5, half a core). Over-budget
  attaches are refused; detach returns the budget. This is the EDF utilization
  test, validated on Pi 5 hardware (`docs/performance/current-results.md` §12).

`trace_printk` is banned on RT-fragment programs
(`HelperForbiddenOnRtFragment`). See `docs/security/verifier-assurance.md` at the repo
root for the bounded-fragment definition and cost bounds.

## Profile-Specific Verification

### Cloud Profile

Standard verification with relaxed limits:

```rust
// Cloud allows more instructions
const MAX_INSN: usize = 1_000_000;

// Cloud allows more stack
const MAX_STACK: usize = 512 * 1024;
```

### Embedded Profile

Additional checks for real-time safety:

```rust
// Embedded has stricter limits
const MAX_STACK_SIZE: usize = 8 * 1024;
const MAX_INSN_COUNT: usize = 100_000;

// Additional structural checks (run before path exploration):
// - Loop-free CFG: any back edge rejects with UnboundedLoop
// - Helper allow-list; trace_printk banned on the RT fragment
// - WCET budget: longest CFG path must fit one control-loop period
```

**Embedded-only errors:**
- `VerifyError::WcetExceeded { wcet_cycles, budget_cycles }`
- `VerifyError::UnboundedLoop { insn_idx }`
- `VerifyError::HelperForbiddenOnRtFragment { insn_idx, helper_id }`
- `VerifyError::DynamicAllocationAttempted { insn_idx }`
- `VerifyError::InterruptUnsafe { insn_idx }`

## Error Reference

The full enum lives in `verifier/error.rs`. Common variants:

| Error | Description | Fix |
|-------|-------------|-----|
| `InvalidOpcode` | Unknown instruction opcode | Use valid BPF opcodes |
| `InvalidRegister` | Register number out of range | Use R0–R10 |
| `UninitializedRegister` | Reading uninitialized register | Initialize before use |
| `WriteToReadOnly` | Writing R10 or a read-only region | Don't write to R10 / ctx |
| `DivisionByZero` | Division/modulo by provably-zero divisor | Check divisor first |
| `InfiniteLoop` | Jump-to-self, no reachable exit | Add exit instruction |
| `UnboundedLoop` | Back edge on embedded profile | Unroll; loops are outside the fragment |
| `OutOfBoundsAccess` | Access outside stack/ctx/map-value bounds | Check pointer offset |
| `InvalidMemoryAccess` | Dereference of non-pointer / maybe-null pointer | Null-check map lookups first |
| `MisalignedAccess` | Unaligned load/store | Align accesses to size |
| `StackExceeded` | Stack depth over profile limit | Reduce stack usage |
| `InsnCountExceeded` | Program over `MAX_INSN_COUNT` | Reduce program size |
| `InvalidJump` | Jump target outside program | Fix jump offset |
| `UnreachableInstruction` | Dead code detected | Remove or fix branches |
| `InvalidHelper` / `HelperNotAvailable` | Unknown helper / not in profile allow-list | Use allowed helpers |
| `HelperArgCount` / `HelperArgType` | Helper signature mismatch | Match `get_helper_signature` |
| `InvalidMapId` | Constant map id with no entry in `map_value_sizes` | Reference an existing map |
| `StateLimitExceeded` | Exploration over the recorded-state budget | Simplify control flow |
| `WcetExceeded` | Static WCET over per-program budget | Shorten the worst path |

## Best Practices

1. **Initialize all registers** before use
2. **Check pointers** before dereferencing
3. **Bound all loops** with explicit counters
4. **Avoid R10 modification** - it's read-only
5. **Check divisors** before division
6. **Keep programs small** - stay under limits
7. **Use structured control flow** - avoid complex jumps
8. **Test edge cases** - empty input, max values

## Debugging Verification Failures

Every `VerifyError` variant carries the failing `insn_idx` and implements
`Display`:

```rust
match Verifier::<ActiveProfile>::verify_with_stats(prog_type, &insns, config) {
    Ok((prog, stats)) => {
        // stats.states_explored / stats.wcet_cycles for cost questions
    }
    Err(e) => println!("verification failed: {e}"),
}
```

To measure verification cost on device, build the kernel with the
`verifier-cost` feature: every BPF load then emits
`AXIOM VERIFIER COST prog_id=… insns=… states=… cycles=… wcet=…` on the UART.
The fuzz harness (`kernel_bpf/fuzz`) exercises the verifier on every PR and
nightly.
