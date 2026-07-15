# Wait-channel refactor: review checklist

This document is the durable review record for the in-tree refactor
of `kernel::mcore::mtask::scheduler::wait` into a generic
`WaitChannel<W: WaiterSink>` with a `TaskQueue` production
specialization. Approval of this checklist is a hard pre-condition
for the refactor commit to land (per the audit branch's separate-
review-mandatory constraint).

The refactor is **behavior-preserving**: no source-level change to
the 3 production call sites, no public API change to
`WaitChannel::new`, no public API change to `WaitRegistration`,
no public API change to `TaskWait::block_current`. The compiler-
generated `Drop` is unchanged.

## Reviewer

Reviewer: _______________

Approval date: _______________

## Checklist

- [ ] **Trait surface is minimal and correct.** `WaiterSink` has
  exactly 4 items: `type Item; fn enqueue(&self, item: Self::Item);
  fn try_take(&self) -> Option<Self::Item>; fn on_wake(&self, item:
  Self::Item)`. All three methods take `&self`; interior mutability
  is used (production delegates to the MPSC's `&self` enqueue and
  `&self` try_take; host tests use `RefCell`).

- [ ] **`on_wake` takes the item by value, not by reference.** The
  production `TaskQueue` adapter needs to move the item into
  `RunQueues::enqueue` (a static call that consumes its argument).
  `Task` is not `Clone`, so passing `&Self::Item` would not work.
  The trait signature is `on_wake(&self, item: Self::Item)`.

- [ ] **No `W: Default` bound.** The `with_sink` constructor takes
  the sink explicitly: `pub fn with_sink(waiters: W) -> Self`.
  Production uses the specialized `impl WaitChannel<TaskQueue>
  { pub fn new() }`, not the generic constructor with a default.

- [ ] **The production type alias resolves the call-site surface.**
  `pub type WaitChannel = WaitChannel<TaskQueue>` and `pub(crate)
  type WaitRegistration<'a> = WaitRegistration<'a, TaskQueue>` in
  `scheduler::wait`. The 3 call sites
  (`kernel/src/file/pipe.rs:26,27`,
  `kernel/src/mcore/mtask/process/mod.rs:282`) compile unchanged.

- [ ] **The production `WaitRegistration` is a concrete struct
  owning `Arc<WaitChannel>`.** The pre-refactor API stored
  `Option<WaitRegistration>` (a concrete type with `Arc<WaitChannel>`
  + `generation: u64`) in `Task::wait_registration`. The
  post-refactor `WaitRegistration` in `scheduler::wait` matches
  this surface: it owns an `Arc<WaitChannel>` and a `u64`
  generation. The generic `WaitRegistration<'a, W>` in
  `wait_channel.rs` borrows the channel; production does not
  use the generic version.

- [ ] **The `TaskQueue` adapter's `enqueue` matches the pre-refactor
  semantics.** The pre-refactor code did `self.waiters.enqueue(task)`,
  which resolved through `Deref<Target = MpscQueue<Task>>` to
  `MpscQueue::enqueue(&self, item: T::Handle)`. The
  post-refactor code casts `self` to `&MpscQueue<Task>` and
  calls `mpsc.enqueue(item)` with `item: Pin<Box<Task>> =
  T::Handle`. Identical semantics.

- [ ] **The `TaskQueue` adapter's `try_take` matches the
  pre-refactor semantics.** The pre-refactor code did
  `self.waiters.try_take()`, which resolved to
  `TaskQueue::try_take(&self) -> Option<Pin<Box<Task>>>`. The
  post-refactor code calls `TaskQueue::try_take(self)`.
  Identical semantics.

- [ ] **The `TaskQueue` adapter's `on_wake` matches the pre-refactor
  semantics.** The pre-refactor code did
  `task.wake_from_wait(); RunQueues::enqueue(task);`. The
  post-refactor code does `item.wake_from_wait();
  RunQueues::enqueue(item);` with `item: Self::Item`. Identical
  semantics (the static call `RunQueues::enqueue` consumes the
  argument; `wake_from_wait` is `&self` interior-mutable).

- [ ] **No `impl Drop` added or altered.** The pre-refactor
  `WaitChannel` had no `Drop` impl. The post-refactor
  `WaitChannel<W>` has no `Drop` impl. The compiler-generated
  `core::ptr::drop_glue` drops each field in declaration order;
  the production `WaitChannel<TaskQueue>` has the same fields
  and the same declaration order as the pre-refactor
  `WaitChannel`, so the generated drop is byte-identical.

- [ ] **The 3 production call sites compile unchanged.** The
  check: `git diff` against the pre-refactor shows zero
  changes to `kernel/src/file/pipe.rs`,
  `kernel/src/mcore/mtask/process/mod.rs`, and
  `kernel/src/mcore/mtask/scheduler/mod.rs` other than the
  `mod wait_channel;` declaration. The kernel binary builds
  with `cargo build -p kernel --target x86_64-unknown-none
  --features cloud-profile` and produces a working QEMU image
  (verified by the audit gate, modulo the static-check updates
  that are part of this refactor's follow-up).

- [ ] **The `MPSC` enqueue path is `&self`, not `&mut self`.**
  Verified by inspecting `cordyceps::mpsc_queue::MpscQueue::enqueue`
  signature: `pub fn enqueue(&self, element: T::Handle)`. The
  trait method `enqueue(&self, item: Self::Item)` calls this
  through `let mpsc: &MpscQueue<Task> = &**self; mpsc.enqueue(item)`.
  No `&mut self` is acquired.

- [ ] **No new public types are exported from the scheduler
  module.** The generic `WaitChannel<W>` and `WaitRegistration<'a, W>`
  are `pub` (so host tests can use them) but live behind the
  `mod wait_channel;` private module. Production code uses
  the type aliases in `scheduler::wait`, which are re-exported
  via `pub mod wait;`. The external API of the kernel crate
  is unchanged.

- [ ] **Drop note in the commit body.** The refactor's commit
  message includes the note: "no prior `Drop` impl existed; the
  `TaskQueue` production specialization preserves the same
  fields and the same declaration order, so the compiler-
  generated `core::ptr::drop_glue` is byte-identical before and
  after the refactor. No custom `Drop` is added."

## Drop behavior detail (for the reviewer's reference)

The pre-refactor `WaitChannel`:

```rust
pub struct WaitChannel {
    generation: WaitEpoch,
    drain_gate: DrainGate,
    waiters: TaskQueue,
}
```

The post-refactor `WaitChannel<TaskQueue>` (after type alias
resolution):

```rust
pub struct WaitChannel<TaskQueue> {
    generation: WaitEpoch,
    drain_gate: DrainGate,
    waiters: TaskQueue,
}
```

The fields and the declaration order are identical. The compiler-
generated `core::ptr::drop_glue::h<WaitChannel<TaskQueue>>` drops
`generation`, then `drain_gate`, then `waiters` — same as the
pre-refactor `WaitChannel`. No `impl Drop for WaitChannel` is
added in either version. The `Arc<WaitChannel>` clone used in
`WaitRegistration::subscribe` does not affect the field drop
order; `Arc::drop` only decrements the strong count.

## Approval

The refactor commit's body references this document:

```
Reviewed-by: <reviewer>
Refs: docs/reviews/wait-channel-refactor.md
```

The commit does not land without this checklist approved.
