---
title: runtime scheduling and locking
status: accepted-with-implementation-gap
source-of-truth: true
---

# ADR-0001: Runtime scheduling, preemption, interrupts, and lock ordering

- Status: Accepted with implementation gap (reschedule IPI pending)
- Date: 2026-07-14

## Context

The audit found one global runnable queue, polling lifecycle and pipe waits, raw
bring-up markers in production paths, and inconsistent interrupt/preemption
rules. The runtime now uses per-CPU queues and one generation-checked wait
protocol for timer, child-exit, and pipe events; this ADR fixes those choices as
the required design rather than incidental implementation detail.

## Decision

1. Each online CPU owns its current task and one runnable queue. New and woken
   tasks prefer their last CPU unless affinity or availability requires another.
2. **DRAFT — target, not yet implemented:** remote producers may enqueue to a
   CPU. An idle target should be notified with a reschedule IPI. No runnable
   task may be present in more than one queue.

   The notification path was not wired when this ADR was accepted. Today a
   wakeup enqueues to `last_cpu()`, and the task runs when that CPU next
   reschedules. The future ownership and ordering contract is defined below,
   but implementing it still requires an SMP regression and evidence that the
   current eventually-consistent wakeup latency is insufficient. Until those
   conditions are met, the IPI is a design target rather than an enforced
   runtime invariant.
3. Work stealing is best effort and bounded by both a victim-attempt limit and a
   maximum batch. A failed `try_steal` never spins on another CPU's queue.
4. Context-switch preparation runs with local interrupts masked and an exclusive,
   non-escaping scheduler borrow. That borrow ends before assembly transfers
   control. No blocking, allocation, filesystem operation, or unbounded retry is
   permitted in this region.
5. Interrupt handlers never sleep, allocate, acquire a blocking lock, perform
   filesystem I/O, or emit synchronous logs. They may update bounded per-CPU
   state, publish a wake event, and request rescheduling.
6. Task-context code must register a wait while holding the same condition lock
   used by the producer, transition the task to waiting, release the lock, and
   only then reschedule. Wake, cancellation, and exit are generation checked.
7. Preemption-disabled sections are CPU-local and nest through a counter. They
   do not imply interrupt masking. Interrupt masking implies preemption is
   disabled for the masked scope.
8. Locks have explicit ranks. Acquisition is strictly increasing, except for a
   documented same-rank shard rule. Release builds rely on review and tests;
   debug/test builds assert the held-rank stack.
9. Production release builds compile all `log` macros out. One-shot serial
   evidence for the local/hosted gate requires `audit-diagnostics`. Raw AArch64
   UART/register probes and forced scheduling probes require
   `bringup-diagnostics`; neither feature is part of a shipped profile.

Initial rank classes, from outermost to innermost, are:

| Rank | Class |
|---:|---|
| 10 | Process tree and global registries |
| 20 | Process lifecycle and file-descriptor tables |
| 30 | Address-space and memory-region state |
| 40 | VFS namespace and filesystem state |
| 50 | File, pipe, and device object state |
| 60 | BPF manager mutation state |
| 70 | BPF map and execution leases |
| 80 | Per-CPU scheduler/run-queue state |
| 90 | Per-CPU trace and interrupt bookkeeping |

The scheduler may consume owned handles prepared at lower ranks, but it must not
acquire a lower-ranked lock while holding scheduler state. Queue publication and
wake APIs therefore accept owned task/event values rather than callbacks into
process, VFS, VM, or BPF managers.

## Future reschedule-IPI contract (not implemented)

This section defines the target contract for decision 2. It does not describe
behavior present in the current kernel.

1. **Policy belongs to the scheduler.** The scheduler selects the destination
   CPU from affinity and availability state and decides whether a remote
   notification is needed. Queue selection, migration policy, and notification
   suppression must not be duplicated in an APIC/GIC driver.
2. **Transport belongs to the architecture interrupt layer.** The x86 APIC or
   AArch64 GIC implementation owns vector allocation, delivery, acknowledgement,
   and architecture-specific barriers. It exposes a bounded, non-blocking
   `request_reschedule(cpu)`-equivalent operation to scheduler policy; it does
   not inspect run queues or choose a destination. The IPI carries no task
   pointer or queue payload; its target CPU is the only routing information.
3. **One scheduler-owned pending bit per target coalesces notifications.** After
   release-publishing the runnable task to the selected queue, a remote producer
   sets the target CPU's pending bit. Only the transition from clear to set sends
   an IPI. Queue publication therefore happens-before notification; the IPI is
   a hint to inspect already-published work, never the publication mechanism.
4. **The handler is bounded.** The target handler acknowledges the interrupt
   and records a CPU-local reschedule request. It does not allocate, mutate or
   drain a run queue, block, acquire a subsystem lock, or emit synchronous
   logging. A context switch occurs only at the normal interrupt-return or
   scheduler boundary.
5. **Clear then recheck prevents a lost wakeup.** A target may clear its pending
   bit only while it is at a scheduler boundary and actively inspecting its
   local queue. After clearing, it performs an acquire observation and rechecks
   the queue before leaving that boundary. A producer that published before the
   clear is found by the recheck; a producer that observes the cleared bit must
   set it and notify. The pending bit is notification state, not the source of
   truth for runnable work.
6. **Masking delays delivery, not publication.** Producers may invoke the
   bounded request API from task or permitted interrupt context. A target with
   interrupts masked retains the pending request and handles it when delivery
   is enabled. Preemption-disabled code may receive an interrupt when IRQs are
   enabled, but the handler only latches the request; it must not force a
   context switch until the preemption count and interrupt-return rules permit
   one.

The IPI target may be implemented only after both of these acceptance
conditions are met:

- A required SMP-4 regression identifies its own worker tasks, confirms that
  every worker exits successfully, and observes those workers across all four
  CPUs. Exact-once queue ownership remains a model-test obligation. The planned
  `qemu-smp4-scheduler-smoke` is pending; it is not evidence until its
  implementation and gate step land and pass.
- A repeatable latency measurement shows that the implemented no-IPI behavior
  misses an accepted wakeup-latency objective. SMP distribution alone does not
  justify adding the IPI path.

## Required evidence

- Host/model tests prove no duplicate/lost tasks and no lost wakeups.
- SMP QEMU tests exercise local scheduling, remote wakeups, bounded stealing,
  affinity, cancellation, interruption, and task-exit cleanup.
- Any reschedule-IPI implementation tests publish-before-notify, coalescing,
  masked-interrupt deferral, and the clear-then-recheck lost-wakeup cases.
- Static release-gate checks reject allocation, synchronous logging, manager
  locking, and unbounded loops from scheduler and interrupt hot paths.
