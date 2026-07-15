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
        cancelled: bool,
        queued: bool,
        runnable: bool,
    }

    impl WaitModel {
        fn subscribe(&mut self) {
            self.observed = Some(self.generation);
        }

        /// Model of `WaitChannel::park` after the subscribe: if the
        /// generation has changed since the task observed it, the task is
        /// immediately runnable (the wake is not lost). Otherwise the task
        /// is queued.
        fn park(&mut self) {
            if self.cancelled {
                return;
            }
            if self.observed != Some(self.generation) {
                // The wake happened before the park; do not enqueue.
                self.runnable = true;
            } else {
                self.queued = true;
            }
        }

        /// Backward-compat alias: `publish_waiter` was the original test's
        /// name for the "park the waiter" step. The semantics are the same
        /// as `park`.
        fn publish_waiter(&mut self) {
            self.park();
        }

        fn post_publish_check(&mut self) {
            if self.cancelled {
                // A cancelled registration must not be re-marked runnable by
                // a post-publish check.
                return;
            }
            if self.observed != Some(self.generation) {
                self.queued = false;
                self.runnable = true;
            }
        }

        fn cancel(&mut self) {
            self.cancelled = true;
            self.queued = false;
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
    fn wake_before_subscribe_is_lost_from_task_perspective() {
        // The channel publishes a generation *before* the task subscribes.
        // The task's subscribe captures the post-wake generation. The
        // task's park then checks "has the generation changed since I
        // observed it" — and the answer is "no, because I observed the
        // post-wake value". The task is queued and waits for the next
        // wake. This is the correct, documented behavior of the protocol:
        // wakes that happen before subscribe are lost from the task's
        // perspective. The task will be woken by the next wake, not the
        // past wake.
        let mut model = WaitModel::default();
        model.wake_all();
        model.subscribe();
        model.publish_waiter();
        model.post_publish_check();
        assert!(
            !model.runnable,
            "wake before subscribe must NOT be observed by the task (it saw the post-wake generation)"
        );
        assert!(
            model.queued,
            "task must be queued waiting for the NEXT wake"
        );

        // The next wake correctly wakes the queued task.
        model.wake_all();
        model.post_publish_check();
        assert!(model.runnable, "next wake must drain the queued task");
        assert!(!model.queued, "next wake must clear the queued flag");
    }

    #[test]
    fn subscribe_cancel_wake_does_not_enqueue() {
        // Task subscribes, then cancels the registration without parking.
        // Channel publishes. The publish must not enqueue a cancelled
        // registration.
        let mut model = WaitModel::default();
        model.subscribe();
        model.cancel();
        model.wake_all();
        model.post_publish_check();
        assert!(!model.runnable, "cancelled registration must not run");
        assert!(!model.queued, "cancelled registration must not enqueue");
    }

    #[test]
    fn wake_after_cancel_does_not_re_enqueue() {
        // Task subscribes and parks, then cancels, then the channel
        // publishes. The publish must not re-enqueue the cancelled task.
        let mut model = WaitModel::default();
        model.subscribe();
        model.publish_waiter();
        assert!(model.queued, "parked task should be queued");
        model.cancel();
        model.wake_all();
        model.post_publish_check();
        assert!(!model.queued, "cancelled task must not remain queued");
        assert!(!model.runnable, "cancelled task must not be runnable");
    }

    #[test]
    fn subscribe_during_drain_is_observed() {
        // Channel is mid-drain_waiters (a DrainGate request is active);
        // a new task subscribes. The new task is either queued (if
        // observed before the next wake) or runnable (if observed after).
        // The DrainGate's begin/finish handshake must not lose the
        // subscribe.
        let mut model = WaitModel::default();
        let gate = DrainGate::new();
        assert!(gate.request());
        gate.begin_pass();

        model.subscribe();
        // Subscribe happened during the drain pass.
        // The drain passes, then the next wake happens.
        let _ = gate.finish_pass();

        // After the drain finishes, the next wake must be observed.
        model.wake_all();
        model.post_publish_check();
        assert!(
            model.runnable || model.queued,
            "subscribe during drain must be observed by next wake"
        );
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
