use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct InterruptibleSleepState {
    state: AtomicU64,
}

impl InterruptibleSleepState {
    const INACTIVE: u64 = 0;
    const ACTIVE: u64 = 1;
    const INTERRUPT_REQUESTED: u64 = 2;

    pub(crate) const fn new() -> Self {
        Self {
            state: AtomicU64::new(Self::INACTIVE),
        }
    }

    pub(crate) fn begin(&self) -> u64 {
        loop {
            let current = self.state.load(Ordering::Acquire);
            assert_eq!(
                current & 3,
                Self::INACTIVE,
                "process already has an interruptible sleeper"
            );
            let generation = (current >> 2).wrapping_add(1);
            let next = (generation << 2) | Self::ACTIVE;
            if self
                .state
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return generation;
            }
        }
    }

    #[must_use]
    pub(crate) fn request_interrupt(&self) -> bool {
        let current = self.state.load(Ordering::Acquire);
        current & 3 == Self::ACTIVE
            && self
                .state
                .compare_exchange(
                    current,
                    (current & !3) | Self::INTERRUPT_REQUESTED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    #[must_use]
    pub(crate) fn interrupt_requested(&self, generation: u64) -> bool {
        self.state.load(Ordering::Acquire) == (generation << 2) | Self::INTERRUPT_REQUESTED
    }

    pub(crate) fn finish(&self, generation: u64) -> bool {
        loop {
            let current = self.state.load(Ordering::Acquire);
            assert_eq!(current >> 2, generation, "sleep generation changed");
            assert!(
                matches!(current & 3, Self::ACTIVE | Self::INTERRUPT_REQUESTED),
                "sleep generation completed twice"
            );
            if self
                .state
                .compare_exchange(
                    current,
                    (generation << 2) | Self::INACTIVE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return current & 3 == Self::INTERRUPT_REQUESTED;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninterrupted_generation_finishes_without_interrupt() {
        let state = InterruptibleSleepState::new();
        let generation = state.begin();

        assert!(!state.interrupt_requested(generation));
        assert!(!state.finish(generation));
    }

    #[test]
    fn interrupt_is_observed_once_for_the_active_generation() {
        let state = InterruptibleSleepState::new();
        let generation = state.begin();

        assert!(state.request_interrupt());
        assert!(!state.request_interrupt());
        assert!(state.interrupt_requested(generation));
        assert!(state.finish(generation));
    }

    #[test]
    fn completed_sleep_advances_to_a_fresh_generation() {
        let state = InterruptibleSleepState::new();
        let first = state.begin();
        assert!(!state.finish(first));

        let second = state.begin();
        assert_eq!(second, first + 1);
        assert!(!state.interrupt_requested(first));
        assert!(!state.finish(second));
    }

    #[test]
    #[should_panic(expected = "process already has an interruptible sleeper")]
    fn second_sleeper_is_rejected_while_generation_is_active() {
        let state = InterruptibleSleepState::new();
        let _ = state.begin();
        let _ = state.begin();
    }
}
