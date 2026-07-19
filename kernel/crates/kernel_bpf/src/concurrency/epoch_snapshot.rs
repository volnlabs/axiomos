//! Lock-free `EpochSnapshot<T>` reclamation with cfg-swapped atomic imports.
//!
//! One algorithm, one implementation. Behind the `loom-model` feature the
//! atomic imports are swapped to `loom::sync::atomic::*` so the same source
//! runs under loom's permutation checker in `tests/concurrency_model.rs`.
//! Default bare-metal builds (no `loom-model`) use `core::sync::atomic::*`
//! unchanged.
//!
//! Algorithm invariants (unchanged across the cfg-swap):
//!
//! - Readers only touch atomics and never allocate, lock, or alter the
//!   published value's reference count.
//! - Writers are serialized and wait for readers of the previous epoch before
//!   reclaiming the replaced allocation.
//! - The `readers` array has two counters; publishing flips the epoch and
//!   the next batch of readers pins the other counter.
//! - The `readers` counter is `checked_add`-protected against saturation: a
//!   saturated counter fails `read()` closed rather than wrapping.

extern crate alloc;

use alloc::boxed::Box;
#[cfg(not(feature = "loom-model"))]
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::ops::Deref;
use core::ptr::NonNull;
#[cfg(not(feature = "loom-model"))]
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

#[cfg(feature = "loom-model")]
use loom::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

/// Busy-wait hint. On the real kernel build this is `core::hint::spin_loop`,
/// which emits a `pause` instruction and avoids memory-bus contention. Under
/// `loom-model` the same call site uses `loom::thread::yield_now()`, which
/// hands control back to Loom's scheduler so the permutation checker can
/// explore the next interleaving. The two are logically equivalent: both
/// make progress without blocking. This is the standard pattern for testing
/// spin-loop code under Loom.
#[cfg(not(feature = "loom-model"))]
#[inline(always)]
fn cpu_relax() {
    spin_loop();
}

#[cfg(feature = "loom-model")]
#[inline(always)]
fn cpu_relax() {
    loom::thread::yield_now();
}

/// An immutable pointer published to lock-free readers.
///
/// Readers only touch atomics and never allocate, lock, or alter the published
/// value's reference count. Writers are serialized and wait for readers of the
/// previous epoch before reclaiming the replaced allocation.
pub struct EpochSnapshot<T> {
    current: AtomicPtr<T>,
    epoch: AtomicUsize,
    readers: [AtomicUsize; 2],
    writer: AtomicBool,
    _owns_current: PhantomData<Box<T>>,
}

// SAFETY: The snapshot exclusively owns the published Box<T>. Moving that
// ownership is valid when T is Send.
unsafe impl<T: Send> Send for EpochSnapshot<T> {}

// SAFETY: Readers only expose shared references, while a publisher can reclaim
// a value on any thread. T must therefore be both Send and Sync.
unsafe impl<T: Send + Sync> Sync for EpochSnapshot<T> {}

impl<T> EpochSnapshot<T> {
    /// Construct an unpublished snapshot.
    ///
    /// `const` only on the `core::sync::atomic` build. Behind the
    /// `loom-model` feature, `loom::sync::atomic::Atomic*::new` is not
    /// `const fn`, so the same body is exposed as a non-`const` function.
    /// The kernel binary does not enable `loom-model`; the `static
    /// HOOK_SNAPSHOTS` initializer at `kernel/src/bpf/mod.rs:208` therefore
    /// always uses the `const` path.
    #[cfg(not(feature = "loom-model"))]
    pub const fn empty() -> Self {
        Self {
            current: AtomicPtr::new(core::ptr::null_mut()),
            epoch: AtomicUsize::new(0),
            readers: [AtomicUsize::new(0), AtomicUsize::new(0)],
            writer: AtomicBool::new(false),
            _owns_current: PhantomData,
        }
    }

    #[cfg(feature = "loom-model")]
    pub fn empty() -> Self {
        Self {
            current: AtomicPtr::new(core::ptr::null_mut()),
            epoch: AtomicUsize::new(0),
            readers: [AtomicUsize::new(0), AtomicUsize::new(0)],
            writer: AtomicBool::new(false),
            _owns_current: PhantomData,
        }
    }

    /// Borrow the currently published value.
    ///
    /// The returned guard pins the reader epoch until it is dropped. Forgetting
    /// a guard is memory-safe, but it prevents a later publisher from completing.
    pub fn read(&self) -> Option<EpochReadGuard<'_, T>> {
        loop {
            let epoch = self.epoch.load(Ordering::SeqCst) & 1;
            if !self.try_pin_epoch(epoch) {
                return None;
            }

            // A publisher that changed epochs may already be reclaiming the old
            // pointer. Retry before loading or dereferencing any pointer.
            if self.epoch.load(Ordering::SeqCst) & 1 != epoch {
                self.readers[epoch].fetch_sub(1, Ordering::SeqCst);
                cpu_relax();
                continue;
            }

            let Some(ptr) = NonNull::new(self.current.load(Ordering::SeqCst)) else {
                self.readers[epoch].fetch_sub(1, Ordering::SeqCst);
                return None;
            };

            return Some(EpochReadGuard {
                snapshot: self,
                ptr,
                epoch,
            });
        }
    }

    fn try_pin_epoch(&self, epoch: usize) -> bool {
        let readers = &self.readers[epoch];
        let mut count = readers.load(Ordering::SeqCst);
        loop {
            let Some(incremented) = count.checked_add(1) else {
                return false;
            };
            match readers.compare_exchange_weak(
                count,
                incremented,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(observed) => count = observed,
            }
        }
    }

    /// Publish `next` and reclaim the previously published value after a grace
    /// period.
    ///
    /// Calling this while holding a read guard from the same snapshot deadlocks:
    /// the publisher must wait for that guard's epoch to drain.
    pub fn publish(&self, next: Box<T>) {
        let _writer = WriterGuard::acquire(&self.writer);
        let previous_epoch = self.epoch.load(Ordering::SeqCst) & 1;
        let previous = self.current.swap(Box::into_raw(next), Ordering::SeqCst);

        // Readers which start after this point use the other counter. Readers
        // already committed to previous_epoch keep the replaced pointer alive.
        self.epoch.store(previous_epoch ^ 1, Ordering::SeqCst);
        while self.readers[previous_epoch].load(Ordering::SeqCst) != 0 {
            cpu_relax();
        }

        if !previous.is_null() {
            // SAFETY: previous came from Box::into_raw. Serialized publication
            // removed it from `current`, and the previous reader epoch is empty.
            unsafe {
                drop(Box::from_raw(previous));
            }
        }
    }
}

impl<T> Drop for EpochSnapshot<T> {
    fn drop(&mut self) {
        // Use `swap` rather than `get_mut` so the same code works against
        // both `core::sync::atomic::AtomicPtr` (which has `get_mut`) and
        // `loom::sync::atomic::AtomicPtr` (which does not). `&mut self`
        // proves no other thread can hold a guard; `swap` returns the
        // previously published pointer, which we then own and free.
        let current = self.current.swap(core::ptr::null_mut(), Ordering::SeqCst);
        if !current.is_null() {
            // SAFETY: `current` was created by `Box::into_raw` in `publish`.
            // Exclusive `&mut self` access proves no other thread holds a
            // guard or is publishing. The previous-reader epoch must be
            // empty because there is no other thread with access to this
            // `EpochSnapshot`.
            unsafe {
                drop(Box::from_raw(current));
            }
        }
    }
}

impl<T> EpochSnapshot<T> {
    /// Test-only helper: force the current epoch's reader counter to
    /// `usize::MAX` so `read()` returns `None`. Exposed only behind the
    /// `loom-model` feature, which is OFF by default for every shipped
    /// profile. The in-module tests in this file access `self.readers`
    /// directly (they are crate-local); the Loom integration test in
    /// `tests/concurrency_model.rs` uses this helper because integration
    /// tests are compiled as a separate crate and cannot reach
    /// `pub(crate)` fields.
    #[cfg(feature = "loom-model")]
    pub fn force_saturated_reader_counter_for_test(&self) {
        let epoch = self.epoch.load(Ordering::SeqCst) & 1;
        self.readers[epoch].store(usize::MAX, Ordering::SeqCst);
    }

    /// Test-only helper: clear the current epoch's reader counter.
    /// Companion to [`Self::force_saturated_reader_counter_for_test`].
    #[cfg(feature = "loom-model")]
    pub fn clear_reader_counter_for_test(&self) {
        let epoch = self.epoch.load(Ordering::SeqCst) & 1;
        self.readers[epoch].store(0, Ordering::SeqCst);
    }
}

/// A read-side epoch pin for [`EpochSnapshot`].
pub struct EpochReadGuard<'a, T> {
    snapshot: &'a EpochSnapshot<T>,
    ptr: NonNull<T>,
    epoch: usize,
}

impl<T> Deref for EpochReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: publication cannot reclaim this pointer until this guard
        // releases its reader epoch in Drop.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> Drop for EpochReadGuard<'_, T> {
    fn drop(&mut self) {
        self.snapshot.readers[self.epoch].fetch_sub(1, Ordering::SeqCst);
    }
}

struct WriterGuard<'a>(&'a AtomicBool);

impl<'a> WriterGuard<'a> {
    fn acquire(writer: &'a AtomicBool) -> Self {
        while writer
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            cpu_relax();
        }
        Self(writer)
    }
}

impl Drop for WriterGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::atomic::{AtomicBool as StdAtomicBool, AtomicUsize as StdAtomicUsize};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Duration;
    use std::vec::Vec;

    use super::*;

    struct Tracked {
        generation: usize,
        drops: Arc<StdAtomicUsize>,
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn old_reader_keeps_replaced_value_alive_until_guard_drop() {
        let drops = Arc::new(StdAtomicUsize::new(0));
        let snapshot = Arc::new(EpochSnapshot::empty());
        snapshot.publish(Box::new(Tracked {
            generation: 0,
            drops: drops.clone(),
        }));
        let old = snapshot.read().expect("initial snapshot should exist");
        assert_eq!(old.generation, 0);

        let (published_tx, published_rx) = mpsc::channel();
        let publisher_snapshot = snapshot.clone();
        let publisher_drops = drops.clone();
        let publisher = thread::spawn(move || {
            publisher_snapshot.publish(Box::new(Tracked {
                generation: 1,
                drops: publisher_drops,
            }));
            published_tx.send(()).unwrap();
        });

        while snapshot
            .read()
            .is_none_or(|current| current.generation != 1)
        {
            thread::yield_now();
        }
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(
            published_rx
                .recv_timeout(Duration::from_millis(20))
                .is_err()
        );

        drop(old);
        published_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("publisher should finish after the old reader exits");
        publisher.join().unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        drop(snapshot);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[derive(Debug)]
    struct ConsistentValue {
        generation: usize,
        inverse: usize,
        checksum: usize,
    }

    impl ConsistentValue {
        const CHECK_MASK: usize = 0xa5a5_5a5a_a5a5_5a5a;

        fn new(generation: usize) -> Self {
            Self {
                generation,
                inverse: !generation,
                checksum: generation ^ Self::CHECK_MASK,
            }
        }

        fn assert_consistent(&self) {
            assert_eq!(self.inverse, !self.generation);
            assert_eq!(self.checksum, self.generation ^ Self::CHECK_MASK);
        }
    }

    #[test]
    fn concurrent_publishers_and_readers_never_observe_a_torn_value() {
        const PUBLICATIONS: usize = 10_000;
        const READERS: usize = 4;

        let snapshot = Arc::new(EpochSnapshot::empty());
        snapshot.publish(Box::new(ConsistentValue::new(0)));
        let finished = Arc::new(StdAtomicBool::new(false));
        let mut readers = Vec::new();

        for _ in 0..READERS {
            let reader_snapshot = snapshot.clone();
            let reader_finished = finished.clone();
            readers.push(thread::spawn(move || {
                while !reader_finished.load(Ordering::Acquire) {
                    reader_snapshot.read().unwrap().assert_consistent();
                }
                reader_snapshot.read().unwrap().assert_consistent();
            }));
        }

        let second_publisher_snapshot = snapshot.clone();
        let second_publisher = thread::spawn(move || {
            for generation in (2..=PUBLICATIONS).step_by(2) {
                second_publisher_snapshot.publish(Box::new(ConsistentValue::new(generation)));
            }
        });
        for generation in (1..PUBLICATIONS).step_by(2) {
            snapshot.publish(Box::new(ConsistentValue::new(generation)));
        }
        second_publisher.join().unwrap();
        finished.store(true, Ordering::Release);

        for reader in readers {
            reader.join().unwrap();
        }
    }

    #[test]
    fn nested_and_concurrent_readers_each_pin_the_epoch() {
        let snapshot = Arc::new(EpochSnapshot::empty());
        snapshot.publish(Box::new(7usize));
        let first = snapshot.read().unwrap();
        let second = snapshot.read().unwrap();

        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let reader_snapshot = snapshot.clone();
        let reader = thread::spawn(move || {
            let guard = reader_snapshot.read().unwrap();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            assert_eq!(*guard, 7);
        });
        held_rx.recv().unwrap();

        let (published_tx, published_rx) = mpsc::channel();
        let publisher_snapshot = snapshot.clone();
        let publisher = thread::spawn(move || {
            publisher_snapshot.publish(Box::new(9));
            published_tx.send(()).unwrap();
        });

        drop(first);
        drop(second);
        assert!(
            published_rx
                .recv_timeout(Duration::from_millis(20))
                .is_err()
        );
        release_tx.send(()).unwrap();
        published_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("all readers have released the previous epoch");
        reader.join().unwrap();
        publisher.join().unwrap();
        assert_eq!(*snapshot.read().unwrap(), 9);
    }

    #[test]
    fn reads_do_not_require_clone_or_reference_counting() {
        struct NotClone(usize);

        let snapshot = EpochSnapshot::empty();
        snapshot.publish(Box::new(NotClone(42)));

        for _ in 0..100 {
            assert_eq!(snapshot.read().unwrap().0, 42);
        }
    }

    #[test]
    fn empty_snapshot_reads_none_and_drop_reclaims_current_value() {
        let drops = Arc::new(StdAtomicUsize::new(0));
        let snapshot = EpochSnapshot::empty();
        assert!(snapshot.read().is_none());

        snapshot.publish(Box::new(Tracked {
            generation: 4,
            drops: drops.clone(),
        }));
        assert_eq!(snapshot.read().unwrap().generation, 4);
        drop(snapshot);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn saturated_reader_counter_fails_closed_without_wrapping() {
        let snapshot = EpochSnapshot::empty();
        snapshot.publish(Box::new(11usize));
        let epoch = snapshot.epoch.load(Ordering::SeqCst) & 1;
        snapshot.readers[epoch].store(usize::MAX, Ordering::SeqCst);

        assert!(snapshot.read().is_none());
        assert_eq!(snapshot.readers[epoch].load(Ordering::SeqCst), usize::MAX);

        snapshot.readers[epoch].store(0, Ordering::SeqCst);
        assert_eq!(*snapshot.read().unwrap(), 11);
    }
}
