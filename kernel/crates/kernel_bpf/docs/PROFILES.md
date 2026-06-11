# Physical Profiles Guide

This document explains the physical profile system and how to choose and use profiles effectively.

## Overview

Physical profiles encode the assumptions the kernel can make about the deployment environment. These assumptions are fixed at compile time, enabling aggressive optimization and compile-time safety guarantees.

## Profile Selection

### When to Use Cloud Profile

Use `--features cloud-profile` when:

- Running on servers with abundant RAM (GBs available)
- Elastic scaling is acceptable (memory can grow/shrink)
- Latency is soft (occasional spikes acceptable)
- Service restarts are tolerable for recovery
- JIT compilation benefits outweigh startup cost
- Throughput is prioritized over predictability

**Typical deployments:**
- Cloud VMs (AWS, GCP, Azure)
- Container orchestration (Kubernetes pods)
- Microservices
- Data center servers

### When to Use Embedded Profile

Use `--features embedded-profile` when:

- Running on resource-constrained devices (MBs of RAM)
- Memory must be statically allocated
- Hard real-time deadlines must be met
- System cannot restart to recover
- Predictable execution time is mandatory
- Interpreter/AOT is preferred for determinism

**Typical deployments:**
- Raspberry Pi / ARM SBCs
- Industrial controllers
- Medical devices
- Automotive ECUs
- IoT gateways

## Profile Comparison

### Constants

| Constant | Cloud | Embedded | Rationale |
|----------|-------|----------|-----------|
| `MAX_STACK_SIZE` | 512 KB | 8 KB | Cloud has more memory |
| `MAX_INSN_COUNT` | 1,000,000 | 100,000 | Embedded needs bounded execution |
| `JIT_ALLOWED` | true | false | JIT needs memory, unpredictable timing |
| `RESTART_ACCEPTABLE` | true | false | Embedded systems must recover in-place |
| `RT_PERIOD_NS` | unlimited | 1,000,000 | Embedded assumes a 1 kHz control loop |
| `CYCLE_UNIT_NS` | 1 (nominal) | 6 | ns per WCET cycle unit, Pi5 A76 calibrated (benchmarks §12) |
| `WCET_CYCLE_BUDGET` | unlimited | ≈166,666 | one period: `RT_PERIOD_NS / CYCLE_UNIT_NS`; over-budget programs rejected at load |
| `UTILIZATION_BUDGET_NS_PER_S` | unlimited | 5×10⁸ | U = 0.5 — Σ wcet·freq across all attached programs capped at half a core |

### Associated Types

```rust
// Cloud Profile
type MemoryStrategy = ElasticMemory;    // Heap allocation, can grow
type SchedulerPolicy = ThroughputFirst; // Maximize work done
type FailureSemantic = RestartRecovery; // Restart on failure

// Embedded Profile
type MemoryStrategy = StaticMemory;     // Fixed pool, no growth
type SchedulerPolicy = DeadlineFirst;   // Meet deadlines
type FailureSemantic = GracefulRecovery;// Degrade gracefully
```

## Memory Strategy

### ElasticMemory (Cloud)

```rust
pub struct ElasticMemory;

impl MemoryStrategy for ElasticMemory {
    const IS_STATIC: bool = false;
    const CAN_GROW: bool = true;
    const MAX_ALLOCATION: usize = 16 * 1024 * 1024; // 16 MB

    fn allocate(size: usize) -> Option<NonNull<u8>> {
        // Uses heap allocation
        alloc::alloc::alloc(Layout::from_size_align(size, 8).ok()?)
    }
}
```

**Characteristics:**
- Allocations from heap
- Can request more memory as needed
- Maps can be resized
- No fragmentation concerns (allocator handles it)

### StaticMemory (Embedded)

```rust
pub struct StaticMemory;

impl MemoryStrategy for StaticMemory {
    const IS_STATIC: bool = true;
    const CAN_GROW: bool = false;
    const MAX_ALLOCATION: usize = 64 * 1024; // 64 KB total pool

    fn allocate(size: usize) -> Option<NonNull<u8>> {
        // Uses static pool with bump allocator
        StaticPool::allocate(size)
    }
}
```

**Characteristics:**
- Fixed 64KB pool at compile time
- Bump allocator (fast, no fragmentation)
- Cannot resize maps
- Must plan memory usage upfront

## Scheduler Policy

### ThroughputFirst (Cloud)

Optimizes for maximum work completed:

```
Priority Queue:
┌─────────────────────────────────────┐
│ Critical │ High │ Normal │ Low     │
│    P3    │  P2  │   P1   │   P0    │
└─────────────────────────────────────┘
        ▲
        │ Select highest priority
        │ FIFO within same priority
```

**Algorithm:**
1. Find highest priority program
2. Among same priority, use FIFO (fairness)
3. Execute until completion or yield
4. No preemption (cooperative)

### DeadlineFirst (Embedded)

Optimizes for meeting deadlines (EDF):

```
Deadline Queue:
┌─────────────────────────────────────┐
│ t=100ns │ t=500ns │ t=1ms │ t=5ms  │
│   P1    │   P3    │  P2   │  P4    │
└─────────────────────────────────────┘
     ▲
     │ Select earliest deadline
     │ Fallback to priority if no deadline
```

**Algorithm:**
1. Find program with earliest deadline
2. If no deadlines, fall back to priority
3. Track deadline misses for monitoring
4. Support preemption at safe points

## Failure Semantics

### RestartRecovery (Cloud)

```rust
pub struct RestartRecovery;

impl FailureSemantic for RestartRecovery {
    const CAN_RESTART: bool = true;
    const MAX_RETRIES: u32 = 3;

    fn on_failure(error: BpfError) -> RecoveryAction {
        match error {
            BpfError::OutOfMemory => RecoveryAction::Restart,
            BpfError::Timeout => RecoveryAction::Restart,
            BpfError::InvalidAccess => RecoveryAction::Abort,
            _ => RecoveryAction::Restart,
        }
    }
}
```

**Behavior:**
- Transient failures trigger restart
- Up to 3 retries before giving up
- Logs error and restarts cleanly
- Acceptable for stateless services

### GracefulRecovery (Embedded)

```rust
pub struct GracefulRecovery;

impl FailureSemantic for GracefulRecovery {
    const CAN_RESTART: bool = false;
    const MAX_RETRIES: u32 = 0;

    fn on_failure(error: BpfError) -> RecoveryAction {
        match error {
            BpfError::DeadlineMiss => RecoveryAction::SkipAndContinue,
            BpfError::OutOfMemory => RecoveryAction::Degrade,
            _ => RecoveryAction::SafeState,
        }
    }
}
```

**Behavior:**
- No restarts allowed
- Graceful degradation on resource exhaustion
- Enter safe state on critical errors
- Maintain system stability at all costs

## Compile-Time Erasure

### What Gets Erased

Code that is physically absent from the wrong profile:

**Cloud-only (absent from embedded):**
```rust
#[cfg(feature = "cloud-profile")]
pub mod jit;                    // JIT compiler

#[cfg(feature = "cloud-profile")]
fn resize(&mut self, ...) { }   // Map resize

#[cfg(feature = "cloud-profile")]
pub struct ThroughputPolicy;    // Throughput scheduler
```

**Embedded-only (absent from cloud):**
```rust
#[cfg(feature = "embedded-profile")]
pub struct StaticPool;          // Static allocator

#[cfg(feature = "embedded-profile")]
pub struct Deadline;            // Deadline type

#[cfg(feature = "embedded-profile")]
pub struct DeadlinePolicy;      // EDF scheduler
```

### Verifying Erasure

The build system ensures proper erasure:

```bash
# This should fail - both profiles enabled
cargo build --features cloud-profile,embedded-profile
# error: Cannot enable both cloud-profile and embedded-profile

# This should fail - no profile enabled
cargo build
# error: Must enable either cloud-profile or embedded-profile
```

## Profile-Specific Code Patterns

### Conditional Compilation

```rust
// Prefer cfg attributes for clean separation
#[cfg(feature = "cloud-profile")]
fn cloud_only_function() {
    // Only exists in cloud builds
}

#[cfg(feature = "embedded-profile")]
fn embedded_only_function() {
    // Only exists in embedded builds
}

// For small differences, use cfg in expressions
fn common_function() {
    #[cfg(feature = "cloud-profile")]
    let limit = 1_000_000;

    #[cfg(feature = "embedded-profile")]
    let limit = 100_000;

    // Use limit...
}
```

### Using ActiveProfile

```rust
use kernel_bpf::profile::ActiveProfile;

// Generic code that works with any profile
fn process_program<P: PhysicalProfile>(program: &BpfProgram<P>) {
    if program.insn_count() > P::MAX_INSN_COUNT {
        // Handle error
    }
}

// Code using the active profile
fn process_current(program: &BpfProgram<ActiveProfile>) {
    // Automatically uses correct profile constants
}
```

### Profile-Specific Imports

```rust
// Import profile-specific types conditionally
#[cfg(feature = "cloud-profile")]
use kernel_bpf::scheduler::ThroughputPolicy;

#[cfg(feature = "embedded-profile")]
use kernel_bpf::scheduler::{Deadline, DeadlinePolicy};
```

## Testing Profiles

### Profile Contract Tests

Verify profile constraints are maintained:

```rust
#[test]
#[cfg(feature = "cloud-profile")]
fn cloud_allows_jit() {
    assert!(CloudProfile::JIT_ALLOWED);
}

#[test]
#[cfg(feature = "embedded-profile")]
fn embedded_forbids_jit() {
    assert!(!EmbeddedProfile::JIT_ALLOWED);
}
```

### Semantic Consistency Tests

Verify same behavior across profiles:

```rust
#[test]
fn same_result_both_profiles() {
    // This test runs identically under both profiles
    let program = create_test_program();
    let result = execute(&program);
    assert_eq!(result, 42); // Must be same on both
}
```

## Migration Guide

### Cloud to Embedded

When migrating from cloud to embedded:

1. **Reduce instruction count**: Programs must be under 100K instructions
2. **Reduce stack usage**: Stack limit drops from 512KB to 8KB
3. **Remove resize calls**: Maps cannot be resized
4. **Add deadlines**: Consider adding deadline annotations
5. **Test bounded execution**: Verify WCET is acceptable

### Embedded to Cloud

When migrating from embedded to cloud:

1. **Remove deadline dependencies**: Deadlines are not available
2. **Remove StaticPool usage**: Use heap allocation
3. **Consider JIT**: May improve performance
4. **Relax constraints**: Can use larger programs/stacks

## Best Practices

1. **Design for embedded first**: If targeting both, design for embedded constraints
2. **Use ActiveProfile**: Prefer generic code using `ActiveProfile` type alias
3. **Test both profiles**: Run full test suite under each profile
4. **Document assumptions**: Note which profile features code depends on
5. **Avoid profile checks at runtime**: Use compile-time cfg instead
