use cordyceps::mpsc_queue::Links;
use cordyceps::{Linked, MpscQueue};

/// One nonblocking intrusive runnable queue.
///
/// Producers never wait. A competing consumer or an in-progress producer is
/// intentionally treated as a miss so a scheduler pass remains bounded.
pub struct RunQueue<T>
where
    T: Linked<Links<T>>,
{
    inner: MpscQueue<T>,
}

impl<T> RunQueue<T>
where
    T: Linked<Links<T>>,
{
    #[must_use]
    pub fn new(stub: T::Handle) -> Self {
        Self {
            inner: MpscQueue::new_with_stub(stub),
        }
    }

    pub fn enqueue(&self, item: T::Handle) {
        self.inner.enqueue(item);
    }

    /// Dequeue an item, waiting through transient producer or consumer races.
    pub fn dequeue(&self) -> Option<T::Handle> {
        self.inner.dequeue()
    }

    /// Attempt one dequeue without spinning.
    ///
    /// `Empty`, `Inconsistent`, and `Busy` are all scheduler misses; a later
    /// scheduling pass retries the queue.
    pub fn try_take(&self) -> Option<T::Handle> {
        self.inner.try_dequeue().ok()
    }
}

impl<T> core::fmt::Debug for RunQueue<T>
where
    T: Linked<Links<T>>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RunQueue").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::format;
    use core::pin::Pin;
    use core::ptr::NonNull;

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

    fn queue() -> RunQueue<Entry> {
        RunQueue::new(Entry::new(usize::MAX))
    }

    #[test]
    fn dequeue_returns_an_enqueued_item() {
        let queue = queue();
        queue.enqueue(Entry::new(7));

        assert_eq!(queue.dequeue().unwrap().id, 7);
    }

    #[test]
    fn try_take_reports_empty_then_returns_an_enqueued_item() {
        let queue = queue();

        assert!(queue.try_take().is_none());
        queue.enqueue(Entry::new(11));
        assert_eq!(queue.try_take().unwrap().id, 11);
        assert!(queue.try_take().is_none());
    }

    #[test]
    fn debug_output_keeps_intrusive_state_opaque() {
        let queue = queue();

        assert_eq!(format!("{queue:?}"), "RunQueue { .. }");
    }
}
