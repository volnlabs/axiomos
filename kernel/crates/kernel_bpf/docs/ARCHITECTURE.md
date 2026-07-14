# kernel_bpf architecture

Status: normative current documentation, 2026-07-14.

## Data flow

```text
signed/raw input
  -> loader and call normalization
  -> verifier with credential-derived caller tier
  -> VerifiedProgram
  -> kernel-owned handle table and immutable attachment snapshot
  -> synchronous interpreter execution
  -> guarded map/helper/actuation operations
```

The standalone crate defines verification and execution mechanisms. The kernel
integration owns authorization, quotas, pin grants, object lifetime, attachment
publication, and per-hook runtime state.

## Execution

Hook dispatch does not enqueue work into a second BPF scheduler. It reads a
fixed-capacity immutable snapshot and executes matching programs synchronously.
The kernel publishes snapshot updates only after an epoch grace period, so the
interrupt and scheduler paths avoid manager locks, allocation, cloning, and
reference-count changes.

The interpreter accepts only `VerifiedProgram`. Its scratch stack is supplied
by the kernel runtime and cannot be shared by concurrent executions. JIT
compiler modules are retained for differential/unit testing, but
`PhysicalProfile::JIT_ALLOWED` is false for every shipped profile and the kernel
contains no RWX allocator.

## Profiles

`PhysicalProfile` contains limits that production code consumes directly. It
does not expose allocator, scheduler, or recovery marker types. The cloud and
embedded profiles differ in stack/instruction limits, map resize availability,
per-map memory budget, WCET/admission bounds, and actuation envelopes.

The embedded 64 KiB memory constant is a per-map constructor ceiling. All maps
use checked, fallible heap allocation; the kernel manager applies stricter
aggregate and per-owner quotas.

## Object lifetime

The kernel uses slot-plus-generation handles for maps and programs. Creation is
charged before publication; unload/destroy reject busy objects; owner exit
reclaims unpinned objects after hook snapshots quiesce. Pinned maps retain
bounded owner/access grants rather than becoming globally accessible.

## Safety boundaries

- Raw bytecode cannot be executed through the safe public API.
- `BpfContext<'a>` carries the lifetime of borrowed input data.
- Verifier helper descriptors and runtime helper dispatch share one ABI table.
- Map allocation sizes use checked arithmetic and fallible reservation.
- Latency-sensitive hooks reject logging helpers.
- Signed production input is verified against the immutable build-provisioned
  trusted key before loading.

## Non-goals

The crate does not currently promise an asynchronous/EDF BPF scheduler, static
map allocation, JIT execution, cross-host persistence, or recovery partitions.
Those features require separate runtime designs and acceptance gates before
they may re-enter the public contract.
