#![cfg(loom)]

use std::boxed::Box;
use std::pin::Pin;
use std::ptr::NonNull;

use cordyceps::Linked;
use cordyceps::mpsc_queue::Links;
use kernel_run_queue::RunQueueSet;
use loom::sync::Arc;
use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::thread;

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

fn queues() -> RunQueueSet<Entry> {
    RunQueueSet::new(2, || Entry::new(usize::MAX))
}

fn record(seen: &AtomicUsize, entry: Pin<Box<Entry>>) {
    let bit = 1usize << entry.id;
    let previous = seen.fetch_or(bit, Ordering::SeqCst);
    assert_eq!(previous & bit, 0, "entry dequeued more than once");
}

fn drain_after_quiescence(queues: &RunQueueSet<Entry>, seen: &AtomicUsize) {
    for cpu in 0..2 {
        while let Some(entry) = queues.try_take_from(cpu, || 1u64 << cpu) {
            record(seen, entry);
        }
    }
}

#[test]
fn local_consumer_and_remote_stealer_do_not_duplicate_or_lose() {
    loom::model(|| {
        let queues = Arc::new(queues());
        let seen = Arc::new(AtomicUsize::new(0));
        queues.enqueue_on(1, Entry::new(0));
        queues.enqueue_on(1, Entry::new(1));

        let local_queues = queues.clone();
        let local_seen = seen.clone();
        let local = thread::spawn(move || {
            if let Some(entry) = local_queues.try_take_from(1, || 0b11) {
                record(&local_seen, entry);
            }
        });

        if let Some(entry) = queues.try_take_from(0, || 0b11) {
            record(&seen, entry);
        }
        local.join().unwrap();

        drain_after_quiescence(&queues, &seen);
        assert_eq!(seen.load(Ordering::SeqCst), 0b11);
    });
}

#[test]
fn producer_publication_racing_remote_steal_remains_retryable() {
    loom::model(|| {
        let queues = Arc::new(queues());
        let seen = Arc::new(AtomicUsize::new(0));

        let producer_queues = queues.clone();
        let producer = thread::spawn(move || {
            producer_queues.enqueue_on(1, Entry::new(0));
        });

        if let Some(entry) = queues.try_take_from(0, || 0b11) {
            record(&seen, entry);
        }
        producer.join().unwrap();

        drain_after_quiescence(&queues, &seen);
        assert_eq!(seen.load(Ordering::SeqCst), 0b1);
    });
}
