# Quick Reference

A quick reference for kernel_bpf types, functions, and patterns.

## Building

```bash
# Cloud profile
cargo build --features cloud-profile
cargo test --features cloud-profile

# Embedded profile
cargo build --features embedded-profile
cargo test --features embedded-profile
```

## Imports

```rust
// Core types
use kernel_bpf::profile::{ActiveProfile, PhysicalProfile};
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::{BpfProgram, BpfProgType, ProgramBuilder};
use kernel_bpf::execution::{BpfContext, BpfExecutor, Interpreter};
use kernel_bpf::verifier::Verifier;
use kernel_bpf::maps::{ArrayMap, HashMap, RingBufMap, TimeSeriesMap, BpfMap};
use kernel_bpf::scheduler::{BpfScheduler, BpfExecRequest, ProgId, ExecPriority};

// Cloud-only
#[cfg(feature = "cloud-profile")]
use kernel_bpf::scheduler::ThroughputPolicy;

// Embedded-only
#[cfg(feature = "embedded-profile")]
use kernel_bpf::scheduler::{Deadline, DeadlinePolicy};
#[cfg(feature = "embedded-profile")]
use kernel_bpf::maps::StaticPool;
```

## Creating Programs

```rust
let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
    .insn(BpfInsn::mov64_imm(0, 42))
    .insn(BpfInsn::exit())
    .build()?;
```

## Common Instructions

```rust
// Move
BpfInsn::mov64_imm(dst, imm)     // dst = imm
BpfInsn::mov64_reg(dst, src)     // dst = src

// Arithmetic
BpfInsn::add64_imm(dst, imm)     // dst += imm
BpfInsn::sub64_imm(dst, imm)     // dst -= imm
BpfInsn::mul64_imm(dst, imm)     // dst *= imm
BpfInsn::div64_imm(dst, imm)     // dst /= imm
BpfInsn::mod64_imm(dst, imm)     // dst %= imm
BpfInsn::neg64(dst)              // dst = -dst

// Bitwise
BpfInsn::and64_imm(dst, imm)     // dst &= imm
BpfInsn::or64_imm(dst, imm)      // dst |= imm
BpfInsn::xor64_imm(dst, imm)     // dst ^= imm
BpfInsn::lsh64_imm(dst, imm)     // dst <<= imm
BpfInsn::rsh64_imm(dst, imm)     // dst >>= imm

// Jumps
BpfInsn::ja(offset)              // goto PC + offset
BpfInsn::jeq_imm(dst, imm, off)  // if dst == imm goto PC + off
BpfInsn::jeq_reg(dst, src, off)  // if dst == src goto PC + off
BpfInsn::jne_imm(dst, imm, off)  // if dst != imm goto PC + off

// Control
BpfInsn::exit()                  // return R0
BpfInsn::call(helper_id)         // call helper function
BpfInsn::nop()                   // no operation
```

## Verification

```rust
// From raw instructions (associated fn; returns the program on success)
let program = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns)?;

// With region sizes (what the sys_bpf load path uses)
let config = VerifyConfig { ctx_size, map_value_size, map_value_sizes: &sizes };
let program = Verifier::<ActiveProfile>::verify_with_config(prog_type, &insns, config)?;

// With cost stats (states_explored, wcet_cycles)
let (program, stats) = Verifier::<ActiveProfile>::verify_with_stats(prog_type, &insns, config)?;
```

## Execution

```rust
let interpreter = Interpreter::<ActiveProfile>::new();
let result = interpreter.execute(&program, &BpfContext::empty())?;
```

## Maps

```rust
// Create
let map = ArrayMap::<ActiveProfile>::with_entries(value_size, max_entries)?;

// Operations
map.lookup(&key) -> Option<Vec<u8>>
map.update(&key, &value, flags) -> MapResult<()>
map.delete(&key) -> MapResult<()>

// Flags
const BPF_ANY: u64 = 0;      // Create or update
const BPF_NOEXIST: u64 = 1;  // Create only
const BPF_EXIST: u64 = 2;    // Update only

// Cloud-only
#[cfg(feature = "cloud-profile")]
map.resize(new_max_entries)?;
```

## Scheduling

```rust
// Create scheduler
let mut scheduler = BpfScheduler::new();

// Submit
let request = BpfExecRequest::new(ProgId(1), Arc::new(program), ctx)
    .with_priority(ExecPriority::High);
scheduler.submit(request)?;

// Get next
if let Some(queued) = scheduler.next() {
    // Execute queued.program
}

// Cancel
scheduler.cancel(ProgId(1));

// Stats
scheduler.pending_count()
scheduler.exec_count()

// Embedded-only
#[cfg(feature = "embedded-profile")]
{
    scheduler.update_time(now_ns);
    scheduler.deadline_misses();

    let deadline = Deadline::from_now(now_ns, timeout_ns);
    request.with_deadline(deadline);
}
```

## Profile Constants

| Constant | Cloud | Embedded |
|----------|-------|----------|
| `MAX_STACK_SIZE` | 512 KB | 8 KB |
| `MAX_INSN_COUNT` | 1,000,000 | 100,000 |
| `JIT_ALLOWED` | true | false |
| `RESTART_ACCEPTABLE` | true | false |
| `WCET_CYCLE_BUDGET` | unlimited | ≈166,666 units (one 1 kHz period) |
| `CYCLE_UNIT_NS` | 1 (nominal) | 6 (Pi5 A76 calibrated) |
| `RT_PERIOD_NS` | unlimited | 1,000,000 (1 kHz) |
| `UTILIZATION_BUDGET_NS_PER_S` | unlimited | 500,000,000 (U = 0.5) |

## Error Types

```rust
// Program building
ProgramError::TooManyInstructions
ProgramError::InvalidOpcode

// Verification (all carry insn_idx)
VerifyError::UninitializedRegister { insn_idx, reg }
VerifyError::WriteToReadOnly { insn_idx, reg }
VerifyError::OutOfBoundsAccess { insn_idx, .. }
VerifyError::WcetExceeded { wcet_cycles, budget_cycles }
VerifyError::HelperForbiddenOnRtFragment { insn_idx, helper_id }

// Execution
BpfError::DivisionByZero
BpfError::InvalidMemoryAccess
BpfError::Timeout

// Maps
MapError::KeyNotFound
MapError::KeyExists
MapError::OutOfMemory

// Scheduler
SchedError::QueueFull
SchedError::NotFound
```

## Conditional Compilation

```rust
// Cloud-only code
#[cfg(feature = "cloud-profile")]
fn cloud_only() { }

// Embedded-only code
#[cfg(feature = "embedded-profile")]
fn embedded_only() { }

// Either profile (at least one required)
#[cfg(any(feature = "cloud-profile", feature = "embedded-profile"))]
fn either_profile() { }
```

## Pattern: Execute Program

```rust
fn run_bpf(bytecode: &[BpfInsn]) -> Result<u64, Box<dyn Error>> {
    // Verify (builds the program and checks safety in one step)
    let program = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, bytecode)?;

    // Execute
    let interpreter = Interpreter::new();
    let result = interpreter.execute(&program, &BpfContext::empty())?;

    Ok(result)
}
```

## Pattern: Counter Map

```rust
fn increment_counter(map: &ArrayMap, index: u32) -> MapResult<u64> {
    let key = index.to_ne_bytes();
    let old = map.lookup(&key)
        .map(|v| u64::from_ne_bytes(v.try_into().unwrap()))
        .unwrap_or(0);
    let new = (old + 1).to_ne_bytes();
    map.update(&key, &new, 0)?;
    Ok(old + 1)
}
```

## Pattern: Scheduler Loop

```rust
fn scheduler_loop(scheduler: &mut BpfScheduler) {
    let executor = Interpreter::<ActiveProfile>::new();

    while let Some(queued) = scheduler.next() {
        match executor.execute(&queued.program, &queued.context) {
            Ok(ret) => println!("Program {} returned {}", queued.id.0, ret),
            Err(e) => println!("Program {} failed: {}", queued.id.0, e),
        }
    }
}
```

## Files Reference

```
kernel/crates/kernel_bpf/
├── src/
│   ├── lib.rs              # Crate root
│   ├── profile/            # Physical profiles
│   │   ├── mod.rs          # PhysicalProfile trait
│   │   ├── memory.rs       # MemoryStrategy
│   │   ├── scheduler.rs    # SchedulerPolicy
│   │   └── failure.rs      # FailureSemantic
│   ├── bytecode/           # BPF instructions
│   │   ├── mod.rs
│   │   ├── registers.rs    # R0-R10
│   │   ├── opcode.rs       # Opcodes
│   │   ├── insn.rs         # BpfInsn
│   │   └── program.rs      # BpfProgram
│   ├── verifier/           # Safety verification + WCET + admission
│   │   ├── mod.rs
│   │   ├── core.rs         # Phased verification
│   │   ├── state.rs        # tnum × interval × type state
│   │   ├── cfg.rs          # Control flow (CSR successor table)
│   │   ├── alu.rs          # ALU transfer functions
│   │   ├── refine.rs       # Branch range refinement
│   │   ├── pruner.rs       # State pruning + budget
│   │   ├── liveness.rs     # Liveness for pruning
│   │   ├── helpers.rs      # HelperId + signatures
│   │   ├── cost.rs         # WCET cycle model (Pi5-calibrated)
│   │   ├── admission.rs    # Utilization admission ledger
│   │   └── error.rs        # Errors
│   ├── loader/             # BPF ELF loading + relocation
│   ├── signing/            # Ed25519 provenance (load-path gate)
│   ├── attach/             # gpio/pwm/iio/kprobe/tracepoint hooks
│   ├── cost_corpus.rs      # Shared shapes for cost measurement
│   ├── execution/          # Execution engines
│   │   ├── mod.rs          # BpfExecutor trait
│   │   ├── interpreter.rs  # Interpreter
│   │   ├── jit/            # JIT (x86_64)
│   │   └── jit_aarch64.rs  # AArch64 JIT
│   ├── maps/               # BPF maps
│   │   ├── mod.rs          # BpfMap trait
│   │   ├── array.rs        # ArrayMap
│   │   ├── hash.rs         # HashMap
│   │   ├── ringbuf.rs      # RingBufMap
│   │   ├── timeseries.rs   # TimeSeriesMap
│   │   └── static_pool.rs  # StaticPool (embedded)
│   └── scheduler/          # Program scheduling
│       ├── mod.rs          # BpfScheduler
│       ├── policy.rs       # BpfPolicy trait
│       ├── queue.rs        # BpfQueue
│       ├── throughput.rs   # ThroughputPolicy (cloud)
│       └── deadline.rs     # DeadlinePolicy (embedded)
├── tests/
│   ├── profile_contracts.rs
│   └── semantic_consistency.rs
└── docs/
    ├── ARCHITECTURE.md
    ├── PROFILES.md
    ├── BYTECODE.md
    ├── VERIFICATION.md
    ├── MAPS.md
    ├── SCHEDULING.md
    └── QUICKREF.md
```
