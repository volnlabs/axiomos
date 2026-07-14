# ADR-0001: Runtime scheduling, preemption, interrupts, and lock ordering

- Status: Accepted
- Date: 2026-07-14

## Context

Each CPU already owns a scheduler, but runnable tasks pass through one global
queue. Timer waits use a bounded deadline queue while child exit, pipes, and I/O
do not share a lost-wake-safe blocking primitive. Interrupt masking and lock
ordering are enforced inconsistently.

## Decision

1. Each online CPU owns its current task and one runnable queue. New and woken
   tasks prefer their last CPU unless affinity or availability requires another.
2. Remote producers may enqueue to a CPU. An idle target is notified with a
   reschedule IPI. No runnable task may be present in more than one queue.
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

## Required evidence

- Host/model tests prove no duplicate/lost tasks and no lost wakeups.
- SMP QEMU tests exercise local scheduling, remote wakeups, bounded stealing,
  affinity, cancellation, interruption, and task-exit cleanup.
- Static release-gate checks reject allocation, synchronous logging, manager
  locking, and unbounded loops from scheduler and interrupt hot paths.
