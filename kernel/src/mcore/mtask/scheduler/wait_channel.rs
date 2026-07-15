//! Lock-free `WaitChannel<W>` with a generic `WaiterSink`.
//!
//! The channel is a small primitive shared by timer, child-exit, and pipe
//! events. It owns a [`WaitEpoch`], a [`DrainGate`], and a sink of
//! parked items. Publishers call `wake_all`; waiters subscribe, observe
//! the current generation, then call `park` (typically via a
//! `WaitRegistration`). The protocol is identical to the previous
//! in-tree implementation; the only change is the parametrization of
//! the parked-items store, so the same algorithm can run against
//! host-side mocks (e.g., `MockSink<usize>` for unit tests).
//!
//! Trait surface (4 items): `Item`, `enqueue`, `try_take`, `on_wake`.
//! All three methods take `&self`; the production `TaskQueue`
//! implementation delegates to the underlying MPSC queue's
//! interior-mutability, and the host `MockSink` implementation
//! uses `RefCell`. The `on_wake` callback is invoked once per item
//! the channel takes out of the sink (i.e., once per wake); the
//! production implementation calls `Task::wake_from_wait` and
//! `RunQueues::enqueue`, while the host implementation is a
//! recording no-op.
//!
//! Drop behavior: the current `WaitChannel` does not implement
//! `Drop`. The compiler-generated `core::ptr::drop_glue` for
//! `WaitChannel<TaskQueue>` is unchanged: it drops each field in
//! declaration order. The production specialization preserves the
//! same fields and the same declaration order, so the
//! compiler-generated drop is byte-identical before and after the
//! refactor. No custom `Drop` is added.
//!
//! See `docs/reviews/wait-channel-refactor.md` for the review
//! checklist.

use crate::mcore::mtask::scheduler::wait_protocol::{DrainGate, WaitEpoch};

/// A sink of parked items.
///
/// All methods take `&self`; the production `TaskQueue` adapter
/// delegates to the underlying MPSC queue's interior-mutability,
/// and host tests use `RefCell` wrappers around their mock state.
pub trait WaiterSink {
    /// The item type parked in the sink. For the production
    /// `TaskQueue` adapter this is `Pin<Box<Task>>`; host tests
    /// typically use plain `usize` (a synthetic task id).
    type Item;

    /// Park an item in the sink.
    fn enqueue(&self, item: Self::Item);

    /// Take one item from the sink, if any. Returns `None` if the
    /// sink is empty.
    fn try_take(&self) -> Option<Self::Item>;

    /// Invoked by the channel on each item it takes out of the sink
    /// (i.e., once per wake). The production `TaskQueue` adapter
    /// calls `Task::wake_from_wait` and `RunQueues::enqueue`; host
    /// adapters record or no-op the call.
    ///
    /// Takes the item by value so the production adapter can move
    /// it into `RunQueues::enqueue` (a static call that consumes
    /// its argument). The MPSC's interior mutability handles the
    /// global state mutation; the channel itself never holds an
    /// item past this call.
    fn on_wake(&self, item: Self::Item);
}

/// A lock-free `WaitChannel` generic over a `WaiterSink`.
///
/// The channel owns a [`WaitEpoch`], a [`DrainGate`], and a sink of
/// parked items. Publishers call `wake_all`; waiters call `subscribe`
/// followed by `WaitRegistration::park` (which invokes `park` on
/// the channel).
pub struct WaitChannel<W: WaiterSink> {
    generation: WaitEpoch,
    drain_gate: DrainGate,
    waiters: W,
}

// Manual `Debug` impl: the production `TaskQueue` does not implement
// `Debug` directly, so we cannot derive it. The body is the
// pre-refactor `#[derive(Debug)]` body, which `finish_non_exhaustive`
// the inner fields to avoid leaking `WaitEpoch` and `DrainGate`
// internals.
impl<W: WaiterSink> core::fmt::Debug for WaitChannel<W> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WaitChannel").finish_non_exhaustive()
    }
}

impl<W: WaiterSink> WaitChannel<W> {
    /// Construct a channel with the given sink. Host tests use this
    /// with a `MockSink<usize>`. Production uses the specialized
    /// `impl WaitChannel<TaskQueue> { pub fn new() }` in
    /// `scheduler::wait`, which calls `Self::with_sink(TaskQueue::new())`.
    pub fn with_sink(waiters: W) -> Self {
        Self {
            generation: WaitEpoch::new(),
            drain_gate: DrainGate::new(),
            waiters,
        }
    }

    /// Publish a condition change and wake every task registered
    /// before it.
    ///
    /// This path does not allocate or acquire a blocking lock, so
    /// it can be called by interrupt-side event publishers.
    pub fn wake_all(&self) {
        self.generation.publish();
        self.drain_waiters();
    }

    fn drain_waiters(&self) {
        if !self.drain_gate.request() {
            return;
        }

        loop {
            self.drain_gate.begin_pass();
            while let Some(item) = self.waiters.try_take() {
                self.waiters.on_wake(item);
            }
            if !self.drain_gate.finish_pass() {
                break;
            }
        }
    }

    pub(crate) fn subscribe(&self) -> WaitRegistration<'_, W> {
        WaitRegistration {
            channel: self,
            generation: self.generation.observe(),
        }
    }

    /// Return the current observed generation. Production
    /// `WaitRegistration::subscribe` uses this to capture the
    /// generation before constructing the registration.
    pub(crate) fn subscribe_observed_generation(&self) -> u64 {
        self.generation.observe()
    }

    pub(crate) fn park(&self, item: W::Item, observed_generation: u64) {
        if self.generation.changed_since(observed_generation) {
            self.waiters.on_wake(item);
            return;
        }

        self.waiters.enqueue(item);

        // If a wake raced publication, either its consumer took this
        // task or this producer observes the generation change and
        // completes the drain.
        if self.generation.changed_since(observed_generation) {
            self.drain_waiters();
        }
    }
}

/// A subscribed wait: holds the observed generation and a borrow of
/// the channel. Drop the registration to release the borrow
/// without parking; call `park` to actually park the task.
///
/// Used in host tests and in the production `block_current` flow.
/// Production code that stores a registration in a `Task` uses the
/// concrete `WaitRegistration` in `scheduler::wait`, which owns an
/// `Arc<WaitChannel>` instead of borrowing.
pub struct WaitRegistration<'a, W: WaiterSink> {
    channel: &'a WaitChannel<W>,
    generation: u64,
}

impl<'a, W: WaiterSink> WaitRegistration<'a, W> {
    pub fn park(self, item: W::Item) {
        self.channel.park(item, self.generation);
    }
}
