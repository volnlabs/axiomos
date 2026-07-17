use alloc::boxed::Box;
use alloc::vec::Vec;
#[cfg(not(loom))]
use core::sync::atomic::{AtomicUsize, Ordering};

use cordyceps::Linked;
use cordyceps::mpsc_queue::Links;
#[cfg(loom)]
use loom::sync::atomic::{AtomicUsize, Ordering};

use crate::{MAX_STEAL_ATTEMPTS, RunQueue, victim_at};

/// One runnable queue and rotating steal cursor per tracked CPU.
pub struct RunQueueSet<T>
where
    T: Linked<Links<T>>,
{
    queues: Box<[RunQueue<T>]>,
    steal_cursors: Box<[AtomicUsize]>,
}

impl<T> RunQueueSet<T>
where
    T: Linked<Links<T>>,
{
    /// Construct `queue_count` queues using a distinct intrusive stub for each.
    ///
    /// # Panics
    ///
    /// Panics unless `queue_count` is between 1 and 64 inclusive.
    #[must_use]
    pub fn new(queue_count: usize, mut stub: impl FnMut() -> T::Handle) -> Self {
        assert!(
            (1..=u64::BITS as usize).contains(&queue_count),
            "run queue count must be between 1 and 64"
        );

        let mut queues = Vec::with_capacity(queue_count);
        let mut steal_cursors = Vec::with_capacity(queue_count);
        for _ in 0..queue_count {
            queues.push(RunQueue::new(stub()));
            steal_cursors.push(AtomicUsize::new(0));
        }

        Self {
            queues: queues.into_boxed_slice(),
            steal_cursors: steal_cursors.into_boxed_slice(),
        }
    }

    /// Publish an item to a selected CPU's queue.
    ///
    /// # Panics
    ///
    /// Panics if `target_cpu` exceeds the configured queue capacity.
    pub fn enqueue_on(&self, target_cpu: usize, item: T::Handle) {
        self.queue(target_cpu).enqueue(item);
    }

    /// Try the current CPU's queue first, then at most four rotating victims.
    ///
    /// # Panics
    ///
    /// Panics if `current_cpu` or an online CPU exceeds the configured queue
    /// capacity.
    #[must_use]
    pub fn try_take_from(
        &self,
        current_cpu: usize,
        online_mask: impl FnOnce() -> u64,
    ) -> Option<T::Handle> {
        if let Some(item) = self.queue(current_cpu).try_take() {
            return Some(item);
        }

        let cursor = self.steal_cursors[current_cpu].fetch_add(1, Ordering::Relaxed);
        let online_mask = online_mask();
        self.assert_valid_online_mask(online_mask);
        let local_bit = 1u64 << current_cpu;
        let victim_count = (online_mask & !local_bit).count_ones() as usize;
        for ordinal in 0..MAX_STEAL_ATTEMPTS.min(victim_count) {
            let Some(victim) = victim_at(online_mask, current_cpu, cursor + ordinal) else {
                break;
            };
            if let Some(item) = self.queue(victim).try_take() {
                return Some(item);
            }
        }
        None
    }

    fn queue(&self, cpu_id: usize) -> &RunQueue<T> {
        self.queues
            .get(cpu_id)
            .expect("CPU id exceeds scheduler queue capacity")
    }

    fn assert_valid_online_mask(&self, online_mask: u64) {
        let valid_mask = if self.queues.len() == u64::BITS as usize {
            u64::MAX
        } else {
            (1u64 << self.queues.len()) - 1
        };
        assert_eq!(
            online_mask & !valid_mask,
            0,
            "online CPU mask exceeds scheduler queue capacity"
        );
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use core::pin::Pin;
    use core::ptr::NonNull;

    use cordyceps::Linked;
    use cordyceps::mpsc_queue::Links;

    use super::*;

    struct Entry {
        links: Links<Self>,
        id: usize,
    }

    impl Entry {
        fn new(id: usize) -> Pin<Box<Self>> {
            Box::pin(Self {
                links: Links::default(),
                id,
            })
        }
    }

    unsafe impl Linked<Links<Self>> for Entry {
        type Handle = Pin<Box<Self>>;

        fn into_ptr(handle: Self::Handle) -> NonNull<Self> {
            // SAFETY: the boxed entry remains pinned while owned by the queue.
            unsafe { NonNull::from(Box::leak(Pin::into_inner_unchecked(handle))) }
        }

        unsafe fn from_ptr(ptr: NonNull<Self>) -> Self::Handle {
            // SAFETY: Cordyceps only returns pointers created by `into_ptr`.
            unsafe { Pin::new_unchecked(Box::from_raw(ptr.as_ptr())) }
        }

        unsafe fn links(ptr: NonNull<Self>) -> NonNull<Links<Self>> {
            // SAFETY: `ptr` identifies a live Entry owned by the queue.
            let links = unsafe { &raw mut (*ptr.as_ptr()).links };
            // SAFETY: a field address derived from a non-null live Entry is non-null.
            unsafe { NonNull::new_unchecked(links) }
        }
    }

    fn queues(count: usize) -> RunQueueSet<Entry> {
        RunQueueSet::new(count, || Entry::new(usize::MAX))
    }

    #[test]
    fn local_queue_wins_before_remote_work() {
        let queues = queues(3);
        queues.enqueue_on(1, Entry::new(11));
        queues.enqueue_on(2, Entry::new(22));

        assert_eq!(
            queues
                .try_take_from(1, || panic!("local dequeue must not load the online mask"))
                .unwrap()
                .id,
            11
        );
        assert_eq!(queues.try_take_from(2, || 0b111).unwrap().id, 22);
    }

    #[test]
    fn bounded_rotation_reaches_a_later_victim_on_the_next_pass() {
        let queues = queues(6);
        queues.enqueue_on(5, Entry::new(55));

        // Cursor zero probes CPUs 1, 2, 3, and 4 only.
        assert!(queues.try_take_from(0, || 0b11_1111).is_none());
        // Cursor one probes CPUs 2, 3, 4, and 5.
        assert_eq!(queues.try_take_from(0, || 0b11_1111).unwrap().id, 55);
    }
}
