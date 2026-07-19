//! Loom model tests for `EpochSnapshot` reclamation.
//!
//! Gated by the `loom-model` feature. Run via:
//!   cargo test -p kernel_bpf --features loom-model,cloud-profile --test concurrency_model
//!
//! Loom exhaustively explores the interleavings of the publisher and reader
//! threads under a permutation checker. The atomic imports in
//! `epoch_snapshot.rs` are cfg-swapped to `loom::sync::atomic` behind this
//! feature, so the test exercises the same algorithm as the kernel binary.
//!
//! Supported-lifecycle tests only:
//!   - publish/read
//!   - old-reader delayed reclamation
//!   - publish after readers drop
//!   - saturated reader counter
//!
//! A "publish after drop" test is intentionally NOT included. A read guard
//! borrows the snapshot, so Rust ownership correctly prevents dropping the
//! snapshot while a guard exists; manufacturing that race with an `Arc`
//! wrapper would test the wrapper, not `EpochSnapshot`.

#![cfg(feature = "loom-model")]

use kernel_bpf::concurrency::epoch_snapshot::EpochSnapshot;
use loom::sync::Arc;
use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::thread;

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
        assert_eq!(
            self.inverse, !self.generation,
            "torn read: inverse mismatch"
        );
        assert_eq!(
            self.checksum,
            self.generation ^ Self::CHECK_MASK,
            "torn read: checksum mismatch"
        );
    }
}

#[test]
fn publish_read_does_not_return_torn_value() {
    loom::model(|| {
        let snapshot = Arc::new(EpochSnapshot::<ConsistentValue>::empty());
        snapshot.publish(Box::new(ConsistentValue::new(42)));

        let reader_snapshot = snapshot.clone();
        let reader = thread::spawn(move || {
            // The reader may observe either 42 (before the publisher runs)
            // or 43 (after). Both must be internally consistent.
            let guard = reader_snapshot.read().expect("snapshot is published");
            guard.assert_consistent();
            assert!(guard.generation == 42 || guard.generation == 43);
        });

        let publisher_snapshot = snapshot.clone();
        let publisher = thread::spawn(move || {
            publisher_snapshot.publish(Box::new(ConsistentValue::new(43)));
        });

        let _ = reader.join();
        let _ = publisher.join();

        // The final published value is internally consistent.
        let final_value = snapshot.read().expect("snapshot is published");
        final_value.assert_consistent();
    });
}

#[test]
fn old_reader_delays_reclamation_until_guard_drop() {
    loom::model(|| {
        let drops = Arc::new(AtomicUsize::new(0));
        let snapshot = Arc::new(EpochSnapshot::<Tracked>::empty());
        snapshot.publish(Box::new(Tracked {
            generation: 0,
            drops: drops.clone(),
        }));

        let old_guard = snapshot.read().expect("initial snapshot is published");
        assert_eq!(old_guard.generation, 0);

        // Publisher is racing; it must wait for `old_guard` to drop.
        let publisher_drops = drops.clone();
        let publisher_snapshot = snapshot.clone();
        let publisher = thread::spawn(move || {
            publisher_snapshot.publish(Box::new(Tracked {
                generation: 1,
                drops: publisher_drops,
            }));
        });

        // While the old guard is held, the previously published value's Drop
        // must not have run.
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        drop(old_guard);
        publisher.join().unwrap();

        // After both the old guard is dropped and the publisher completes,
        // the first value's Drop must have run exactly once.
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn publish_after_all_readers_drop_completes_without_waiting() {
    loom::model(|| {
        let drops = Arc::new(AtomicUsize::new(0));
        let snapshot = Arc::new(EpochSnapshot::<Tracked>::empty());
        snapshot.publish(Box::new(Tracked {
            generation: 0,
            drops: drops.clone(),
        }));

        // Drop the only reader before publishing; the publisher must complete
        // without waiting.
        {
            let _guard = snapshot.read().unwrap();
        }

        snapshot.publish(Box::new(Tracked {
            generation: 1,
            drops: drops.clone(),
        }));

        // The first value's Drop must have run exactly once.
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        // Drop the snapshot itself; the second value's Drop runs.
        drop(snapshot);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn saturated_reader_counter_fails_closed_without_wrapping() {
    loom::model(|| {
        let snapshot = Arc::new(EpochSnapshot::<usize>::empty());
        snapshot.publish(Box::new(11usize));

        snapshot.force_saturated_reader_counter_for_test();

        // read() must return None while the counter is saturated.
        assert!(snapshot.read().is_none());
        // The counter must not be corrupted; clearing restores read().
        snapshot.clear_reader_counter_for_test();
        assert_eq!(*snapshot.read().unwrap(), 11);
    });
}

struct Tracked {
    generation: usize,
    drops: Arc<AtomicUsize>,
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
