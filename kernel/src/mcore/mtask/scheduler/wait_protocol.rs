use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug)]
pub struct WaitEpoch(AtomicU64);

impl WaitEpoch {
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    #[must_use]
    pub fn observe(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    pub fn publish(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    #[must_use]
    pub fn changed_since(&self, observed: u64) -> bool {
        self.0.load(Ordering::SeqCst) != observed
    }
}

#[derive(Debug)]
pub struct DrainGate {
    active: AtomicBool,
    requested: AtomicBool,
}

impl DrainGate {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            requested: AtomicBool::new(false),
        }
    }

    /// Request a drain and report whether this caller owns the drain loop.
    #[must_use]
    pub fn request(&self) -> bool {
        self.requested.store(true, Ordering::Release);
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub fn begin_pass(&self) {
        self.requested.store(false, Ordering::Release);
    }

    /// Release drain ownership, reacquiring it when a concurrent request raced
    /// the end of the pass.
    #[must_use]
    pub fn finish_pass(&self) -> bool {
        self.active.store(false, Ordering::Release);
        self.requested.load(Ordering::Acquire)
            && self
                .active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::DrainGate;

    #[derive(Default)]
    struct WaitModel {
        generation: u64,
        observed: Option<u64>,
        queued: bool,
        runnable: bool,
    }

    impl WaitModel {
        fn subscribe(&mut self) {
            self.observed = Some(self.generation);
        }

        fn publish_waiter(&mut self) {
            if self.observed != Some(self.generation) {
                self.runnable = true;
            } else {
                self.queued = true;
            }
        }

        fn post_publish_check(&mut self) {
            if self.observed != Some(self.generation) {
                self.queued = false;
                self.runnable = true;
            }
        }

        fn wake_all(&mut self) {
            self.generation += 1;
            if self.queued {
                self.queued = false;
                self.runnable = true;
            }
        }
    }

    #[test]
    fn wake_before_queue_publication_is_not_lost() {
        let mut model = WaitModel::default();
        model.subscribe();
        model.wake_all();
        model.publish_waiter();
        model.post_publish_check();
        assert!(model.runnable);
        assert!(!model.queued);
    }

    #[test]
    fn wake_after_queue_publication_drains_waiter() {
        let mut model = WaitModel::default();
        model.subscribe();
        model.publish_waiter();
        model.wake_all();
        model.post_publish_check();
        assert!(model.runnable);
        assert!(!model.queued);
    }

    #[test]
    fn unchanged_condition_leaves_waiter_parked() {
        let mut model = WaitModel::default();
        model.subscribe();
        model.publish_waiter();
        model.post_publish_check();
        assert!(!model.runnable);
        assert!(model.queued);
    }

    #[test]
    fn concurrent_drain_request_is_handed_to_active_owner() {
        let gate = DrainGate::new();
        assert!(gate.request());
        gate.begin_pass();
        assert!(!gate.request());
        assert!(gate.finish_pass());

        gate.begin_pass();
        assert!(!gate.finish_pass());
        assert!(gate.request());
    }
}
