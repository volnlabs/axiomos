# Architecture Overview

This document describes the architecture of the kernel_bpf crate and how its components interact.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Space                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ BPF Loader  │  │ Map Access  │  │ Program Management      │  │
│  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘  │
└─────────┼────────────────┼──────────────────────┼───────────────┘
          │                │                      │
          ▼                ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                       kernel_bpf                                 │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Profile Layer                          │   │
│  │  ┌─────────────────┐        ┌─────────────────────────┐  │   │
│  │  │  CloudProfile   │   OR   │   EmbeddedProfile       │  │   │
│  │  │  (build-time)   │        │   (build-time)          │  │   │
│  │  └─────────────────┘        └─────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌───────────────────────────┼───────────────────────────────┐  │
│  │                           ▼                               │  │
│  │  ┌─────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐  │  │
│  │  │Bytecode │  │ Verifier │  │ Execution │  │   Maps   │  │  │
│  │  │ Parser  │─▶│          │─▶│  Engine   │◀▶│          │  │  │
│  │  └─────────┘  └──────────┘  └─────┬─────┘  └──────────┘  │  │
│  │                                   │                       │  │
│  │  ┌────────────────────────────────▼─────────────────────┐│  │
│  │  │                    Scheduler                         ││  │
│  │  │  ┌────────────────┐      ┌─────────────────────────┐││  │
│  │  │  │ThroughputPolicy│  OR  │    DeadlinePolicy       │││  │
│  │  │  │  (cloud)       │      │    (embedded)           │││  │
│  │  │  └────────────────┘      └─────────────────────────┘││  │
│  │  └──────────────────────────────────────────────────────┘│  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### Profile Layer

The profile layer provides compile-time configuration for the entire subsystem.

```
profile/
├── mod.rs          # PhysicalProfile sealed trait, ActiveProfile alias
├── memory.rs       # MemoryStrategy trait (Elastic vs Static)
├── scheduler.rs    # SchedulerPolicy trait (Throughput vs Deadline)
└── failure.rs      # FailureSemantic trait (Restart vs Recovery)
```

**Key Types:**

```rust
pub trait PhysicalProfile: sealed::Sealed + 'static {
    type MemoryStrategy: MemoryStrategy;
    type SchedulerPolicy: SchedulerPolicy;
    type FailureSemantic: FailureSemantic;

    const MAX_STACK_SIZE: usize;
    const MAX_INSN_COUNT: usize;
    const JIT_ALLOWED: bool;
    const RESTART_ACCEPTABLE: bool;
}
```

### Bytecode Module

Handles BPF instruction encoding and program representation.

```
bytecode/
├── mod.rs          # Module root, re-exports
├── registers.rs    # BpfReg enum (R0-R10)
├── opcode.rs       # OpcodeClass, AluOp, JmpOp, MemSize, MemMode
├── insn.rs         # BpfInsn struct, instruction builders
└── program.rs      # BpfProgram<P>, ProgramBuilder<P>
```

**Instruction Format (8 bytes):**

```
┌────────┬────────┬────────┬────────┬────────────────────────────┐
│ opcode │dst:src │ offset │ offset │           imm              │
│ 8 bits │ 4:4    │ lo 8   │ hi 8   │          32 bits           │
└────────┴────────┴────────┴────────┴────────────────────────────┘
```

### Verifier Module

Ensures program safety before execution, and bounds both verification cost
and program execution cost (WCET). Wired into the `sys_bpf` load path (#48).

```
verifier/
├── mod.rs          # Verifier<P> public API
├── core.rs         # Phased verification: basic → CFG → profile → exploration
├── state.rs        # Register/stack abstract state: tnum × interval × type
├── cfg.rs          # ControlFlowGraph, BasicBlock (CSR successor table, O(n+E))
├── alu.rs          # Width-correct ALU transfer functions (#114)
├── refine.rs       # Branch-condition range refinement (#105)
├── pruner.rs       # State subsumption + recorded-state budget (#103, #116)
├── liveness.rs     # Per-instruction liveness for pruning (#104)
├── helpers.rs      # HelperId (runtime ABI numbering), signatures, allow-lists
├── cost.rs         # Static WCET cycle model, Pi5-calibrated (Track C)
├── admission.rs    # AdmissionLedger: Σ wcet·freq utilization admission
└── error.rs        # VerifyError enum
```

**Verification Pipeline:**

```
Parse → Build CFG → Profile constraints → Path-sensitive exploration → OK
            │       (loop-freedom,            │
            ▼        helper allow-list,       ▼
       Detect loops, WCET budget —      Register types, tnum/range
       dead code     pre-exploration)   tracking, memory + stack bounds,
                                        state pruning w/ liveness
```

See `VERIFICATION.md` for the full guide and `docs/verifier-fragment.md` at
the repo root for the bounded-cost fragment.

### Loader Module

Parses BPF ELF objects and relocates helper calls and map references.

```
loader/
├── mod.rs          # Load entry points
├── elf.rs          # ELF parsing
├── object.rs       # Program/map object model
├── reloc.rs        # Relocation incl. helper-name → HelperId (runtime ABI)
└── error.rs        # LoadError
```

### Signing Module

Ed25519 program provenance, enforced on the load path (#20): a `SignedProgram`
container is verified against the kernel-held trust store and fails closed on
any bad signature; unsigned loads pass only while `allow_unsigned = true`
(default until a userspace signer ships).

```
signing/
├── mod.rs          # Module root
├── verifier.rs     # SignatureVerifier::authenticate gate
├── signature.rs    # SignedProgram container
├── hash.rs         # Program hashing
└── error.rs        # SigningError
```

### Attach Module

Hook-type-specific attach points.

```
attach/
├── mod.rs          # Attach registry
├── gpio.rs         # GPIO line interrupts
├── pwm.rs          # PWM cycle hooks
├── iio.rs          # Sensor-sample hooks
├── kprobe.rs       # Kernel probe hooks
└── tracepoint.rs   # Tracepoint hooks
```

### Execution Module

Provides execution engines for BPF programs.

```
execution/
├── mod.rs          # BpfExecutor trait, BpfContext, default_executor()
├── interpreter.rs  # Interpreter<P> - bytecode interpreter
├── jit/            # JIT compiler (x86_64)
└── jit_aarch64.rs  # AArch64 JIT (native codegen on Pi 5)
```

**Execution Flow:**

```
                    ┌─────────────────┐
                    │ BpfExecRequest  │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   Scheduler     │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
       ┌────────────┐ ┌────────────┐ ┌────────────┐
       │    JIT     │ │Interpreter │ │    AOT     │
       │  (cloud)   │ │   (both)   │ │ (embedded) │
       └──────┬─────┘ └──────┬─────┘ └──────┬─────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │     Result      │
                    └─────────────────┘
```

### Maps Module

Provides shared data storage between BPF programs and userspace.

```
maps/
├── mod.rs          # BpfMap trait, MapDef, MapError
├── array.rs        # ArrayMap<P> - O(1) lookup by index
├── hash.rs         # HashMap<P> - arbitrary keys
├── ringbuf.rs      # RingBufMap<P> - kernel→userspace event stream
├── timeseries.rs   # TimeSeriesMap<P> - timestamped samples
└── static_pool.rs  # StaticPool (embedded-only)
```

**Map Operations:**

```rust
pub trait BpfMap<P: PhysicalProfile> {
    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> MapResult<()>;
    fn delete(&self, key: &[u8]) -> MapResult<()>;
    fn def(&self) -> &MapDef;

    #[cfg(feature = "cloud-profile")]
    fn resize(&mut self, new_max_entries: u32) -> MapResult<()>;
}
```

### Scheduler Module

Manages BPF program execution scheduling.

```
scheduler/
├── mod.rs          # BpfScheduler, BpfExecRequest, ProgId
├── policy.rs       # BpfPolicy trait, ExecPriority
├── queue.rs        # BpfQueue<P>, QueuedProgram<P>
├── throughput.rs   # ThroughputPolicy (cloud-only)
└── deadline.rs     # DeadlinePolicy, Deadline (embedded-only)
```

**Scheduling Policies:**

| Policy | Profile | Algorithm | Use Case |
|--------|---------|-----------|----------|
| ThroughputPolicy | Cloud | Priority + FIFO | Maximize throughput |
| DeadlinePolicy | Embedded | EDF | Meet real-time deadlines |

## Data Flow

### Program Loading

```
1. User provides bytecode (raw insns or BPF ELF) via sys_bpf
2. Signing gate authenticates provenance (signed container verified
   against kernel trust store; fail-closed on bad signature)
3. Loader parses ELF, relocates helper calls / map references
4. Verifier checks safety + computes static WCET; over-budget rejects
5. Program stored in BpfProgram<P>
6. Attach passes the admission ledger (Σ wcet·freq ≤ utilization budget)
   before the hook fires it
```

### Program Execution

```
1. Execution request submitted to scheduler
2. Scheduler selects program based on policy
3. Executor runs program with context
4. Program accesses maps as needed
5. Result returned to caller
```

### Map Operations

```
1. Map created with MapDef
2. Programs reference map by ID
3. Lookup/update/delete through BpfMap trait
4. Changes visible to all referencing programs
```

## Memory Layout

### Cloud Profile

```
┌─────────────────────────────────────┐
│           Heap Memory               │
│  ┌─────────────────────────────┐   │
│  │    Program Storage          │   │  Dynamic allocation
│  ├─────────────────────────────┤   │
│  │    Map Storage              │   │  Can resize
│  ├─────────────────────────────┤   │
│  │    Stack (512KB max)        │   │  Per-program
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

### Embedded Profile

```
┌─────────────────────────────────────┐
│         Static Pool (64KB)          │
│  ┌─────────────────────────────┐   │
│  │    Program Storage          │   │  Fixed at init
│  ├─────────────────────────────┤   │
│  │    Map Storage              │   │  Cannot resize
│  ├─────────────────────────────┤   │
│  │    Stack (8KB max)          │   │  Per-program
│  ├─────────────────────────────┤   │
│  │    Unused                   │   │  Watermark allocation
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

## Thread Safety

All public types are designed to be thread-safe:

- `BpfProgram<P>`: `Send + Sync` (immutable after creation)
- `ArrayMap<P>`: `Send + Sync` (internal RwLock)
- `BpfScheduler`: Not `Sync` (requires external synchronization)
- `Interpreter<P>`: `Send + Sync` (stateless)

## Error Handling

Errors are categorized by module:

| Module | Error Type | Example Errors |
|--------|------------|----------------|
| Bytecode | `ProgramError` | TooManyInstructions, InvalidOpcode |
| Verifier | `VerifyError` | UninitializedRegister, OutOfBounds |
| Execution | `BpfError` | DivisionByZero, InvalidMemoryAccess |
| Maps | `MapError` | KeyNotFound, OutOfMemory |
| Scheduler | `SchedError` | QueueFull, DeadlineMiss |

## Extension Points

The architecture supports future extensions:

1. **New Map Types**: Implement `BpfMap<P>` trait
2. **New Execution Engines**: Implement `BpfExecutor<P>` trait
3. **New Scheduling Policies**: Implement `BpfPolicy<P>` trait
4. **New Profiles**: (Not recommended - use existing profiles)
