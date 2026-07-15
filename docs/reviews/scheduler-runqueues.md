# Scheduler run-queues design review

**Status:** design review only. No implementation. Establishes current
contracts before any per-CPU-queue or work-stealing refactor lands.

**Scope:** `kernel/src/mcore/mtask/scheduler/{mod,run_queue,run_queue_policy,cleanup,sleep,switch,wait,wait_channel}.rs`
and `kernel/src/mcore/mtask/task/queue.rs`.

**Out of scope:** BPF sched_switch bridge demo, BPF-related task state,
scheduler.test fixtures. BPF is observed by the scheduler but does not
own it.

---

## 1. Current ownership and topology

### 1.1 Global state

`RunQueues` is a unit struct with static methods. There is no struct
instance; everything is a private `static` inside `run_queue.rs`:

```
static RUN_QUEUES:        OnceCell<Box<[TaskQueue]>>         # MAX_SCHEDULER_CPUS = 64 entries
static STEAL_CURSORS:     [AtomicUsize; MAX_SCHEDULER_CPUS]   # one steal cursor per CPU
```

Initialization is via `RunQueues::init()` (called from BSP bring-up).
After init, the `Box<[TaskQueue]>` slice is fixed-size and never
reallocated.

### 1.2 Per-CPU structure

There is NO per-CPU run-queue separation. Each `TaskQueue` is a
shared MPSC queue (`cordyceps::MpscQueue<Task>`) indexed by `cpu_id`.
Every CPU's enqueue path goes through `RunQueues::enqueue(task)` which
routes to `queue(task.last_cpu())`. Dequeue is local-first
(`queue(current_cpu)`); on miss, work-stealing probes other queues.

### 1.3 Last-CPU sticky affinity

`enqueue` uses `task.last_cpu()` (sticky). This means a task that last
ran on CPU 3 gets re-queued to `queue(3)` even when CPU 0 is currently
idle and CPU 3 is busy. The reason given in the code is "sticky-load"
(i.e., preferring the home CPU keeps cache warm). The trade-off is that
this can produce load imbalance: a CPU that just finished a task is
likely to be put back on the runnable list and selected again, while an
idle CPU sits empty.

`last_cpu` is set whenever the task is enqueued (see
`run_queue.rs:40`) and read on each enqueue. There's no decay, no
rebalancing, no idle migration.

### 1.4 Work stealing on miss

`dequeue()` first tries the local CPU's queue. On miss:

```
let cursor = STEAL_CURSORS[current_cpu].fetch_add(1, Ordering::Relaxed);
let online = online_cpu_mask();
let local_bit = 1u64 << current_cpu;
let victim_count = (online & !local_bit).count_ones() as usize;
for ordinal in 0..MAX_STEAL_ATTEMPTS.min(victim_count) {
    let Some(victim) = victim_at(online, current_cpu, cursor + ordinal) else { break; };
    if let Some(task) = queue(victim).try_take() { return Some(task); }
}
None
```

`MAX_STEAL_ATTEMPTS = 4` (configured in `run_queue_policy.rs`). The
steal attempts are bounded; the next dequeue iterates from the rotated
cursor. `victim_at` wraps modulo `victim_count` so the same victim
isn't probed repeatedly.

### 1.5 Why MPSC and not MPMC

`MpscQueue` (multi-producer single-consumer) is what `cordyceps`
provides and what each `TaskQueue` uses. In our topology the consumer
is the local CPU; producers are everywhere (other CPUs, ISR bottom
halves, BPF sched_switch bridge, `WaitChannel::wake_all`, etc.). MPSC
is correct: many producers push, one consumer pops. A second consumer
on the same queue would race.

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

There is **no IPI** in this design. Cross-CPU wakeup is fire-and-forget.

---

## 4. Lock ordering

### 4.1 What locks exist

`RunQueues` does NOT use a single global lock. Each `TaskQueue` is
lock-free (cordyceps MPSC) and the steal-cursor is an `AtomicUsize`.
The "lock-ordering discipline" is really a memory-ordering discipline:

- `enqueue` ends with a release-store equivalent (cordyceps publish).
- `dequeue` begins with an acquire-load (cordycepts consume).
- `try_take` returns `Option<Pin<Box<Task>>>` so a successful steal
  hands ownership atomically.

### 4.2 What locks do OTHER subsystems hold across scheduler calls

The audit branch has documented a small number of locks:

- `Task::kstack`, `Task::ustack`, `Task::tls`, `Task::fx_area` are
  per-task `Option<RwLock<T>>` fields (`task/mod.rs:14, 487-499`).
  These are held by the reschedule path via `force_write_unlock`
  during exit cleanup (`Task::exit` calls `force_write_unlock` on
  each). The audit doc flagged this in finding at ENGINEERING_AUDIT.md
  as a T-row risk; the locks are not currently proven to be held by
  the current task at the moment of unlock. This is documented but not
  resolved.
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

### 4.3 What could deadlock today

The audit doc flagged `Task::force_write_unlock` on `ustack`, `tls`,
and `fx_area` without proving the current task holds those locks
(ENGINEERING_AUDIT.md finding at the systematic-unsafe-sites section).
This is a single-task self-deadlock surface: if the task holds the
write lock and `exit` is called from within the same task, the unlock
panics. This is documented but not exercised by the test suite.

---

## 5. Cross-CPU wakeup / IPI ownership

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
- **No TLB shootdown IPI.** TLB invalidation across CPUs is not
  addressed here — it would require an IPI-side contract, which is
  the next-tier concern after this design review.

The wakeup contract is therefore "approximate, eventually consistent,
within-CPU-bounded". For an audit-grade kernel targeting single-vCPU
first, this is acceptable. For multi-vCPU it would need follow-up work.

---

## 6. Exit-cleanup and blocked-task semantics

### 6.1 Task termination

`Task::exit` (called from `Task::terminate_current`, the cleanup path
in `idt.rs`, or the syscall layer) does:

1. Mark the owning `Process` as exited via
   `process.mark_exited(status)` — publishes to `parent_exit_wait`.
2. Force-unlock `ustack`, `tls`, `fx_area` (see §4.3 caveat).
3. Re-enqueue the task onto `TaskCleanup::enqueue(...)` if
   `should_terminate`, `TaskSleep::enqueue(...)` if sleeping, the
   waiter's queue if waiting, or `RunQueues::enqueue(...)` otherwise.

The terminated task continues to *run* until the next reschedule. The
scheduler picks it up via the path above and runs the appropriate
destructor (cleanup.rs:70-onwards) which iterates the BPF owner ring
and drops BPF state.

### 6.2 Wait-channel blocked-task semantics

When a task is in a `WaitChannel` and the owning `Process` exits:

- `process.mark_exited(status)` calls `parent_exit_wait.wake_all()`,
  which wakes the parent.
- The blocked child task itself is NOT directly woken by
  `mark_exited`. It remains in the channel's wait queue.

If the channel's owner process is gone, the wake-all on `wake_all` is
a no-op for the dead process's tasks. Currently there is no
"drain the channel when the channel's owner process exits" path.
Tasks waiting on a dead process's channel stay parked. This is a
known gap, not a bug; the parent process is gone, so nothing wakes
them. They will be reaped by the per-process teardown, if any.

The `wait_protocol.rs::tests` and `wait_channel.rs::tests`
(`channel_core_*`) cover the channel core algorithm with mock sinks;
they do NOT cover process-exit interplay for a task parked in a
channel. That gap is documented in the audit doc as a deferred
fixture item.

### 6.3 Zombie task reaping

`TaskCleanup::run` (the cleanup worker task spawned by
`cleanup.rs:62-67`) is the only task that *consumes* dead tasks. It
loops on `cleanup_queue().dequeue()` and:

1. Reads the dead task's last BPF owner ID.
2. Walks the BPF owner ring.
3. Reclaims / drops BPF state.

Zombie tasks NOT consumed by `TaskCleanup::run` remain parked on
`cleanup_queue()` indefinitely. The ring buffer has zero leak
pressure today (`cleanup_queue` doesn't grow unboundedly because there
is at most one consumer).

---

## 7. Open questions for any future per-CPU refactor

The user's earlier task list explicitly said: *"Do not implement
per-CPU queues or work stealing before this review establishes the
current contracts."* That is satisfied by this review: the contracts
above exist as-is, and the refactor is gated on the following
pre-conditions being met first:

### 7.1 What a per-CPU-queue refactor would change

- Per-CPU `TaskQueue` becomes the only consumer for that CPU (no
  cross-CPU steal-to-self).
- Migration policy replaces sticky-load (e.g., idle-pull, hill
  climbing, or random kick).
- An IPI wakeup path becomes necessary for cross-CPU latency (today's
  "eventually consistent" is acceptable on SMP-1 but not on SMP-N).

### 7.2 What it must NOT change without evidence

- The waker picks the CPU. Any "CPU selection policy" must be
  documented and unit-tested with the same `loom` model we use for
  WaitChannel.
- The `WaitChannel` core uses an opaque `W: WaiterSink`. The host
  sink is `TaskQueue`. Migrating the host sink to per-CPU still
  preserves the model (it becomes "TaskQueue of last_cpu's CPU"); the
  channel algorithm itself is unchanged. The model-level guarantees
  are preserved.

### 7.3 Pre-conditions for the refactor PR

Before the per-CPU refactor lands, the following must be true:

1. The SMP `--smp 4` smoke runs in CI as a regression (today: optional
   smoke only). The per-CPU refactor would introduce cross-CPU races
   that the existing SMP-1 audit does not exercise.
2. A `loom`-equivalent model of the `RunQueues` MPSC + cross-CPU
   steal exists and validates at least the same set of orderings as
   the WaitChannel model.
3. An IPI ownership contract is documented (which driver owns
   sending IPIs; what the IPIs carry; what the recipient does).
4. A bounded-regression step for the ring-3 fault (see §6.2) — the
   refactor must not regress "channel-drain on exit" if that gap is
   ever closed.

---

## 8. Approved pre-conditions for the schedule

This review establishes the contracts. The user-explicit reject of
per-CPU-queue changes is honored. Any follow-on implementation work
must produce a separate ADR recording the new contracts AND meet the
pre-conditions in §7.3.

**Outcome:** review complete. No code changes land from this branch.
