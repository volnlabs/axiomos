# Current axiomos architecture

**Status:** Normative for the supported release surface.

This document describes the architecture implemented by the current tree. The
generated manifests and ABI catalogs define the exact shipped boundary; the
accepted ADRs define policy where this overview only links the components.

## Authority order

When two documents disagree, use this order:

1. Generated authorities under [`docs/reference/generated`](../reference/generated/README.md).
2. Accepted decisions under [`docs/decisions`](../decisions/).
3. Current documents in this directory.
4. Source code and its required gate evidence.
5. Archived and legacy documents, which are historical only.

## System shape

```text
userspace tools and init
        |
        | versioned syscall/BPF ABI
        v
kernel syscall, VFS, process, VM, and scheduler owners
        |                         |
        | verified program       | event snapshots
        v                         v
kernel_bpf verifier -> immutable ProgramRuntime -> interpreter
        |                                      |
        | guarded map leases                   | monitored actuation
        v                                      v
maps / ring buffers                    platform GPIO, PWM, IIO
        |
        | Shrike-link control frames
        v
RP2040 firmware control loop
```

The root workspace and every standalone Cargo, fuzz, firmware, and Lean
component are enumerated by [`ci/components.toml`](../../ci/components.toml).
The generated [component inventory](../reference/generated/components.md) is the readable
view of that boundary.

## Supported targets

The supported target/feature combinations are defined by
[ADR-0003](../decisions/0003-supported-targets.md) and generated in the
[target matrix](../reference/generated/targets.md):

- x86_64 bare metal under the pinned QEMU/OVMF launch path is the primary
  release-gate target.
- AArch64 `virt` and Raspberry Pi 5 are supported build/platform targets; real
  Pi assurance remains dependent on physical HIL.
- RISC-V is an isolated experimental demo and is not a shipped kernel target.

Produced boot images, root filesystems, firmware, and trust roots are listed in
the [artifact provenance table](../reference/generated/artifacts.md). Build inputs such as
OVMF and Limine are listed in the [immutable input table](../reference/generated/build-inputs.md).

## Runtime ownership

- **Scheduling:** one run queue exists per CPU, enqueue uses the task's recorded
  `last_cpu`, and dequeue performs a bounded rotating steal on local miss.
  Preemption, interrupt, and lock rules are normative in
  [ADR-0001](../decisions/0001-runtime-scheduling-locking.md). A wakeup IPI remains an
  explicit implementation gap, not a current invariant.
- **Processes:** `Process` owns credentials, descriptors, memory-region
  metadata, and its address-space handle. Construction, fork, exec, lifecycle,
  and userspace-entry invariants are separated under
  `kernel/src/mcore/mtask/process/`.
- **Virtual memory:** `AddressSpace` owns the top-level page table, mapper lock,
  and resident-CPU mask. Mapping, rollback, user-copy, shootdown, and fault
  semantics are normative in [VM ownership and faults](memory.md).
- **VFS and syscalls:** ABI-visible commands are limited to the generated
  [ABI v1 catalog](../reference/generated/abi.md). Typed error policy is defined by
  [ADR-0002](../decisions/0002-kernel-error-policy.md).
- **BPF:** the kernel binary owns credentials, handles, quotas, attachment
  publication, and object reclamation. `kernel_bpf` owns parsing,
  authentication primitives, verification, maps, and interpretation. The
  complete security boundary is normative in [BPF trust and lifecycle](../security/bpf-trust.md).
- **Firmware:** `shrike_control` contains the platform-independent `no_std`
  control loop; RP2040 adapters remain in `shrike_rp2040`. Host simulation
  proves sampled-state behavior, not GPIO IRQ-edge behavior.

## Release policy

Shipped profiles use the interpreter and do not ship a JIT. The decision and
criteria for any future RW-to-RX implementation are in
[ADR-0004](../decisions/0004-bpf-jit-policy.md).

The required local evidence command is documented in the
[local audit gate](../security/local-audit-gate.md). `--quick` is an iteration
mode and is not full release evidence.

## Known assurance limits

- Hosted H-06 evidence is blocked until GitHub Actions billing/quota is
  restored.
- Physical RPi5/RP2040 HIL and GPIO IRQ stress require hardware and a retained
  UART/control-link evidence contract.
- Device completion has no production `WaitChannel` consumer; pipe and
  child-exit integration still need a host-runnable production fixture.
- The historical ring-3 fault is currently non-reproducing and has no pinned
  reproducer; it is not classified as fixed.
- The unsafe ledger, Miri, Loom, coverage, and mutation gates are not a
  substitute for an independent safety/concurrency review.
