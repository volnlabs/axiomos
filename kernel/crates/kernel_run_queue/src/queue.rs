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
