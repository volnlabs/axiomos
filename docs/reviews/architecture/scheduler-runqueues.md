# Scheduler run-queues design review

**Status:** design review and target-contract update. The current kernel has no
reschedule-IPI implementation; the future ownership contract is documented
separately from implemented behavior.

**Scope:** `kernel/src/mcore/mtask/scheduler/{mod,run_queue,cleanup,sleep,switch,wait,wait_channel}.rs`,
`kernel/src/mcore/mtask/task/queue.rs`, and
`kernel/crates/kernel_run_queue/src/{queue,per_cpu,policy}.rs`.

**Out of scope:** BPF sched_switch bridge demo, BPF-related task state,
scheduler.test fixtures. BPF is observed by the scheduler but does not
own it.

---

## 1. Current ownership and topology

### 1.1 Global state

`RunQueues` is a unit struct with static methods. Its kernel integration
owns one private static in `run_queue.rs`:

```
static RUN_QUEUES: OnceCell<kernel_run_queue::RunQueueSet<Task>>
```

`RunQueueSet<Task>` owns fixed boxed slices containing one
`RunQueue<Task>` and one rotating `AtomicUsize` steal cursor per CPU.
Initialization is via `RunQueues::init()` (called from BSP bring-up) and
creates `MAX_SCHEDULER_CPUS = 64` queues. The kernel supplies the task
stubs, CPU identity, affinity, and online mask; the extracted crate owns
the queue and steal-policy algorithms used by both production and model
tests.

### 1.2 Per-CPU queue topology

`RunQueues` already provides one `RunQueue<Task>` per CPU through the
fixed storage inside `RunQueueSet`. `RunQueues::enqueue(task)` delegates
to `enqueue_on(target_cpu, task)`, where `target_cpu = task.last_cpu()`.
Dequeue delegates to `try_take_from(current_cpu, online_cpu_mask)`, which
tries the local queue before it even loads the online mask; on miss, work
stealing probes other queues.

This is the per-CPU topology prescribed by ADR-0001. The unresolved
ownership issue is not whether per-CPU queues exist; it is whether the
single-consumer premise of each MPSC queue remains valid when another
CPU attempts to steal from that queue.

### 1.3 Last-CPU sticky affinity

`enqueue` uses `task.last_cpu()` (sticky). This means a task that last
ran on CPU 3 gets re-queued to `queue(3)` even when CPU 0 is currently
idle and CPU 3 is busy. The reason given in the code is "sticky-load"
(i.e., preferring the home CPU keeps cache warm). The trade-off is that
this can produce load imbalance: a CPU that just finished a task is
likely to be put back on the runnable list and selected again, while an
idle CPU sits empty.

`last_cpu` is read by `RunQueues::enqueue` to select the target queue.
It is written by the scheduler through `set_last_cpu` during
reschedule, immediately after `dequeue` returns the next task and
before that task is marked running. It therefore records the CPU that
most recently selected the task to run, not the CPU that called
`enqueue`. There is no decay, rebalancing, or idle migration.

### 1.4 Work stealing on miss

`dequeue()` first tries the local CPU's queue. On miss it delegates to
the extracted production policy, whose effective flow is:

```
let cursor = steal_cursors[current_cpu].fetch_add(1, Ordering::Relaxed);
let online = online_mask();
let local_bit = 1u64 << current_cpu;
let victim_count = (online & !local_bit).count_ones() as usize;
for ordinal in 0..MAX_STEAL_ATTEMPTS.min(victim_count) {
    let Some(victim) = victim_at(online, current_cpu, cursor + ordinal) else { break; };
    if let Some(task) = queues[victim].try_take() { return Some(task); }
}
None
```

`MAX_STEAL_ATTEMPTS = 4` is defined in
`kernel_run_queue::policy`. The steal attempts are bounded; the next
dequeue iterates from the rotated cursor. `victim_at` wraps modulo
`victim_count` so the same victim is not probed repeatedly.

### 1.5 Why MPSC and not MPMC

`MpscQueue` (multi-producer single-consumer) is what `cordyceps`
provides and what each `RunQueue` uses. Producers may run on several
CPUs, while the home CPU is the intended consumer of its indexed queue.
The steal path may concurrently call `try_take` from one remote CPU.

The extracted crate now runs the actual Cordyceps implementation under
`cfg(loom)`. Its pairwise models cover a local consumer racing a remote
stealer (no duplicate or lost task) and publication racing a remote
steal (a miss remains retryable and the task is observed after
quiescence). This is evidence for the current pairwise use of
`try_dequeue`, not a proof of arbitrary-N liveness, hotplug behavior, or
wakeup latency. Those remain separate SMP and policy obligations.

---

## 2. Preemption boundaries

### 2.1 Where the scheduler runs

`Scheduler::reschedule` (called via `ExecutionContext::with_current_task_mut`-equivalent
sites, e.g., `kernel/src/mcore/mtask/scheduler/switch.rs:85`) is the
context-switch entry. It is invoked from:

1. **Return-to-userspace paths** — explicit `reschedule` after
   `iretq` plumbing. The current task has fully unloaded its kernel
   stack.
2. **Sleep entry** (`TaskSleep::sleep_until` etc.) — the current task
   parks itself and calls `reschedule`.
3. **Block** (`WaitChannel`, `WaitRegistration::park`) — analogous to
   sleep.
4. **Exit** (`Task::exit`) — terminal, runs cleanup, then
   `reschedule`.

`switch.rs:85` documents the rule directly: *"Disable interrupts
before you call this. This will enable interrupts again."* The
scheduler switcher itself holds interrupts disabled while it runs;
interrupts are re-enabled by `iretq` to the new task on resume.

### 2.2 What may NOT happen at CPL=0 with interrupts enabled

- `reschedule()` — must be called with interrupts disabled.
- Direct manipulation of the current task's state — the current task
  is on-CPU; only the scheduler (which owns the context switch) may
  transition it.
- Free of any wait-channel call. `block_current` is the entry point to
  sleep, and it disables interrupts around the state transition.

### 2.3 What may happen at CPL=0 with interrupts enabled (kernel preemption)

The kernel does NOT currently support preemption of arbitrary kernel
code. `Task::should_terminate()` is checked at reschedule boundaries
only. A userspace-spawned thread that calls `exit()` while another
task is running will be terminated at the next reschedule, not at the
moment of the syscall entry.

This is a deliberate design: any lock held in a kernel subsystem is
safe to acquire and release across reschedule-free kernel code, because
no reschedule happens mid-acquire. The downside is that no
"preemptible kernel" model is used; a long-running syscall blocks all
other tasks on the same CPU.

---

## 3. Interrupt-context rules

### 3.1 IRQ handlers don't enqueue directly

A hardware interrupt handler runs in IRQ context. It is forbidden from
acquiring `RunQueues`'s lock-irrelevant lock (TaskQueue uses
lock-free MPSC). It MAY call `RunQueues::enqueue` to wake a sleeping
task, **but only if it can do so at the right preemption level**:

- The bottom-half / softirq that processes the wakeup runs at a
  preemption-disabled level (effectively CLI) when calling `enqueue`,
  so the enqueue path is in the same preemption domain as the waker
  (the user-space blocked task). The task lands on its `last_cpu()`
  queue, never on the interrupting CPU's queue unless they happen to
  match.
- The interrupting CPU may not have its own scheduler running the
  woken task; the task will sit on that CPU's queue until the next
  `reschedule` on that CPU.

This is the standard "cross-CPU wakeup via run queue" pattern but with
an asymmetric honor system: the waker picks a CPU, the wakee lands
there, the wakee runs there next time the picked CPU reschedules.

### 3.2 When the wakeup latency is bounded

- The waker is at CPL=0 with interrupts enabled (post-IRQ handler
  flow). It calls `enqueue`, which doesn't take a lock (MPSC), and
  returns.
- The wakee's CPU sees the new entry next time its scheduler
  `dequeue()`s — which is "soon" if the CPU is currently idle or "at
  the next reschedule" if the CPU is busy.

There is **no scheduler wakeup IPI** in this design. Cross-CPU task
wakeup is fire-and-forget. This is distinct from the x86 TLB-shootdown
IPI described in §5.

---

## 4. Lock ordering

### 4.1 What locks exist

`RunQueues` does NOT use a single global lock. Each `TaskQueue` is
lock-free (cordyceps MPSC) and the steal-cursor is an `AtomicUsize`.
The "lock-ordering discipline" is really a memory-ordering discipline:

- `enqueue` ends with a release-store equivalent (cordyceps publish).
- `dequeue` begins with an acquire-load (Cordyceps consume).
- `try_take` returns `Option<Pin<Box<Task>>>` so a successful steal
  hands ownership atomically.

### 4.2 What locks do OTHER subsystems hold across scheduler calls

The audit branch has documented a small number of locks:

- `Task::kstack` is an owned optional stack allocation. `Task::ustack`,
  `Task::tls`, and `Task::fx_area` are per-task `RwLock<Option<T>>`
  fields. `Task::exit` releases the latter three through normal
  `write().take()` guards (`task/mod.rs:188-198`). No
  `force_write_unlock` call remains in the current kernel source; the
  audit row `Additional High: force unlock` is closed.
- `process_tree()` is a `RwLock<...>` covering the parent/child
  relations; `Task::mark_exited` acquires write.
- `WaitChannel::waiters` (per channel) is `TaskQueue::new()` under
  MPSC; no explicit lock.
- `interruptible_sleep_state` on `Process` is `AtomicU64` with
  generation-count semantics; no lock.

The lock-ordering rule is therefore:

1. **Acquire scheduler-relevant state first** (e.g., `process_tree`
   write before `mark_exited`'s queue side-effect).
2. **`enqueue`/`dequeue` are last** — they are lock-free; ordering is
   about memory visibility (release/acquire), not a deadlock surface.
3. **Avoid holding any lock across `reschedule()`** — `Task::exit`
   releases all locks before calling `reschedule`.

---

## 5. Cross-CPU wakeup / IPI ownership

### 5.1 Current implemented behavior

There is **no inter-processor interrupt (IPI) path** in this kernel
for wakeup. The `RunQueues::enqueue(task)` call always targets
`task.last_cpu()`, and the wakee sits on that CPU's queue until the
next reschedule.

This has consequences:

- **No preemption of a busy CPU**. If the wakee's CPU is currently
  busy running another task, the wakee waits for the next reschedule.
  There is no "fast wakeup IPI" to interrupt the running task.
- **No scheduler IPI for SMP load balancing**. A task stuck on a hot
  CPU remains there unless the hot CPU voluntarily reschedules.
- **TLB shootdown is a separate, implemented IPI path.** On x86,
  `arch::shootdown_tlb` publishes an epoch, sends
  `InterruptIndex::TlbShootdown` through each target LAPIC, and waits
  for per-CPU acknowledgements (`arch/x86_64.rs:39-88`). That path does
  not provide scheduler wakeup or load-balancing notification.

The wakeup contract is therefore "approximate, eventually consistent,
within-CPU-bounded". For an audit-grade kernel targeting single-vCPU
first, this is acceptable. For multi-vCPU it would need follow-up work.

### 5.2 Future ownership split (target, not implemented)

ADR-0001 defines the following target contract. None of these bullets
claims that the notification path exists today:

- **Scheduler policy chooses the target and the need to notify.** It
  owns affinity, availability, migration, and notification suppression.
  Architecture interrupt code must not choose a run queue or inspect
  scheduler policy.
- **The architecture APIC/GIC layer transports the request.** It owns
  vector allocation, delivery, acknowledgement, and architecture
  barriers behind a bounded `request_reschedule(cpu)`-equivalent API.
  The IPI carries no task pointer or queue payload.
- **A scheduler-owned per-target pending bit coalesces requests.** The
  producer first release-publishes the task to the selected queue, then
  sets the bit. Only a clear-to-set transition sends an IPI.
  Notification therefore cannot race ahead of runnable-task publication.
- **The IPI handler only acknowledges and requests rescheduling.** It
  does not allocate, mutate or drain queues, block, acquire subsystem
  locks, or log synchronously. The scheduler acts at a normal safe
  interrupt-return or reschedule boundary.

### 5.3 Lost-wakeup and masking rule (target, not implemented)

The target CPU may clear its pending bit only at a scheduler boundary
while it is inspecting the local queue. It must perform an acquire
observation and recheck that queue after clearing. Work published before
the clear is found by the recheck; work published after the clear sees
the clear bit and sends a new notification. The queue, not the pending
bit, remains the source of truth.

Interrupt masking may delay delivery but must not undo the producer's
queue publication or pending state. Preemption-disabled code with IRQs
enabled may latch the request through the handler, but no context switch
is forced until interrupt-return and the preemption counter permit it.
This keeps the future path within the interrupt rules in ADR-0001 and
prevents a reschedule in the middle of a protected kernel region.

### 5.4 Acceptance boundary

The notification path remains out of scope until both conditions hold:

1. A required SMP-4 regression identifies only its own workers,
   confirms that all workers exit successfully, and observes their
   execution across all four CPUs. Exact-once queue ownership remains a
   model-test obligation. The planned `qemu-smp4-scheduler-smoke` is
   **pending**; no implementation or passing gate result is claimed by
   this review.
2. A repeatable measurement demonstrates that no-IPI wakeup latency
   violates an accepted objective. Distribution across four CPUs is
   necessary scheduler evidence, but is not by itself a latency need.

---

## 6. Exit-cleanup and blocked-task semantics

### 6.1 Task termination

`Task::exit` (called from `Task::terminate_current`, the cleanup path
in `idt.rs`, or the syscall layer) does:

1. Acquire normal write guards for `fx_area`, `tls`, and `ustack`, take
   their allocations, mark the current task for termination, and drop
   those guards (`task/mod.rs:188-200`).
2. Mark a non-root owning process exited. `Task::terminate_current`
   publishes its supplied status before entering `Task::exit`; the
   second `mark_exited(0)` is ignored because the exit code is already
   present.
3. Call `reschedule`. During the next scheduler preparation pass, the
   outgoing task becomes `zombie_task`; on the following pass a task
   marked for termination is transferred to `TaskCleanup::enqueue`
   (`scheduler/mod.rs:157-171, 256-290`).

`TaskCleanup::run` drains those task objects, drops them, and then
retries BPF-owner reclamation until each exited owner can be reclaimed
(`cleanup.rs:76-100`).

### 6.2 Wait-channel blocked-task semantics

When a process exit is published:

- `process.mark_exited(status)` calls `parent_exit_wait.wake_all()`,
  which wakes tasks waiting for that child exit.
- `mark_exited` does not traverse the process's other tasks or their
  wait registrations. No current production test demonstrates the
  cancellation and reclamation behavior for a different task of the
  exiting process that is already parked on an unrelated channel.

The `wait_protocol.rs::tests` and `wait_channel.rs::tests`
(`channel_core_*`) cover the channel core algorithm with mock sinks;
they do NOT cover process-exit interplay for a task parked in a
channel. That gap is documented in the audit doc as a deferred
fixture item.

### 6.3 Zombie task reaping

`TaskCleanup::run` (the cleanup worker task scheduled by
`cleanup.rs:53-64`) consumes dead tasks. It
loops on `cleanup_queue().dequeue()` and:

1. Records an exited task owner's process ID when applicable.
2. Drops the task object.
3. Attempts BPF-owner reclamation under the manager lock and retains
   owners that cannot yet be reclaimed for another pass.

`cleanup_queue` is another intrusive `TaskQueue`, not a bounded ring.
The cleanup worker is therefore part of the resource-reclamation
contract: if it does not run, queued task objects remain live. The
current smoke tests exercise cleanup markers, but there is no separate
host test that proves a bound on cleanup backlog under sustained exit
load.

---

## 7. Open questions for any future ownership/stealing refactor

The current per-CPU topology predates this review. Changes to queue
ownership, work stealing, migration, or wakeup notification are gated
on the following pre-conditions.

### 7.1 What an ownership/stealing refactor would change

- Each per-CPU `TaskQueue` gains an enforceable consumer/steal contract
  instead of relying on an MPSC queue while remote CPUs call
  `try_take`.
- Migration policy replaces sticky-load (e.g., idle-pull, hill
  climbing, or random kick).
- An IPI wakeup path may be added only if measured cross-CPU latency
  requires it. SMP-N support alone does not establish that need.

### 7.2 What it must NOT change without evidence

- The waker picks the CPU. Any "CPU selection policy" must be
  documented and unit-tested with the same `loom` model we use for
  WaitChannel.
- The `WaitChannel` core uses an opaque `W: WaiterSink`; production uses
  `TaskQueue` and host tests use a mock sink. A scheduler queue change
  must preserve the channel algorithm's generation/drain guarantees.

### 7.3 Pre-conditions for the refactor PR

Before an ownership/stealing or wakeup-notification refactor lands, the
following must be true:

1. The planned `qemu-smp4-scheduler-smoke` runs as a required
   regression. It must track its own worker identities and prove those
   workers execute across CPU mask `0x0f`, with every worker exiting
   successfully. **Status: pending** until the implementation and gate
   step land and pass; this document is not that evidence.
2. A `loom`-equivalent model of the `RunQueues` MPSC + cross-CPU
   steal exists and validates at least the same set of orderings as
   the WaitChannel model. A model must be wired into the required gate,
   not merely present as an optional local test.
3. The IPI ownership contract in ADR-0001 and §5 is preserved: the
   scheduler owns policy, the APIC/GIC layer owns transport, and the
   handler is bounded. Implementing it additionally requires the
   measured latency need from §5.4.
4. If the historical ring-3 fault becomes reproducible, a pinned
   artifact and bounded regression protect its eventual fix. The
   current non-reproducing observation is not such a guard.

---

## 8. Approved pre-conditions for the schedule

This review establishes the current contracts. Any follow-on
implementation work must update the ADR with the new contracts and
meet the pre-conditions in §7.3.

**Outcome:** the contract review is complete. It distinguishes the
implemented per-CPU queue/no-reschedule-IPI behavior from the future
notification target. The executable SMP-4 proof and required run-queue
model gate remain pending, and no latency evidence currently justifies
an IPI implementation. No IPI code lands with this documentation update.
