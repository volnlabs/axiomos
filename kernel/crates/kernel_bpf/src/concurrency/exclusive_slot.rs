//! Nonblocking single-invocation publication slot.

extern crate alloc;

use alloc::boxed::Box;
use core::fmt;
use core::ops::Deref;
#[cfg(not(feature = "loom-model"))]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "loom-model")]
use loom::sync::atomic::{AtomicUsize, Ordering};

use super::epoch_snapshot::{EpochReadGuard, EpochSnapshot};

const OPEN: usize = 0;
const ACTIVE: usize = 1;
const TRANSITION: usize = 2;

/// Why an invocation could not enter an exclusive slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnterError {
    TransitionBusy,
    ExecutionBusy,
    Empty,
}

/// Why a transition guard could not be acquired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    Busy,
}

/// Invocation attempts skipped by the slot, grouped by cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotSkipCounts {
    pub transition_busy: usize,
    pub execution_busy: usize,
    pub empty: usize,
}

/// One privately published value with nonblocking transition and invocation gates.
pub struct ExclusiveSlot<T> {
    snapshot: EpochSnapshot<T>,
    state: AtomicUsize,
    transition_busy_skips: AtomicUsize,
    execution_busy_skips: AtomicUsize,
    empty_skips: AtomicUsize,
}

impl<T> ExclusiveSlot<T> {
    #[cfg(not(feature = "loom-model"))]
    pub const fn empty() -> Self {
        Self {
            snapshot: EpochSnapshot::empty(),
            state: AtomicUsize::new(OPEN),
            transition_busy_skips: AtomicUsize::new(0),
            execution_busy_skips: AtomicUsize::new(0),
            empty_skips: AtomicUsize::new(0),
        }
    }

    #[cfg(feature = "loom-model")]
    pub fn empty() -> Self {
        Self {
            snapshot: EpochSnapshot::empty(),
            state: AtomicUsize::new(OPEN),
            transition_busy_skips: AtomicUsize::new(0),
            execution_busy_skips: AtomicUsize::new(0),
            empty_skips: AtomicUsize::new(0),
        }
    }

    /// Try to begin the slot's sole active invocation.
    pub fn try_enter(&self) -> Result<ExclusiveReadGuard<'_, T>, EnterError> {
        match self
            .state
            .compare_exchange(OPEN, ACTIVE, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {}
            Err(TRANSITION) => {
                increment_saturating(&self.transition_busy_skips);
                return Err(EnterError::TransitionBusy);
            }
            Err(ACTIVE) => {
                increment_saturating(&self.execution_busy_skips);
                return Err(EnterError::ExecutionBusy);
            }
            Err(_) => unreachable!("invalid exclusive slot state"),
        }

        match self.snapshot.read() {
            Some(snapshot) => Ok(ExclusiveReadGuard {
                snapshot: Some(snapshot),
                state: &self.state,
            }),
            None => {
                self.state.store(OPEN, Ordering::SeqCst);
                increment_saturating(&self.empty_skips);
                Err(EnterError::Empty)
            }
        }
    }

    /// Try to exclude both new transitions and invocations without waiting.
    pub fn try_transition(&self) -> Result<ExclusiveTransitionGuard<'_, T>, TransitionError> {
        if self
            .state
            .compare_exchange(OPEN, TRANSITION, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(TransitionError::Busy);
        }

        Ok(ExclusiveTransitionGuard {
            slot: self,
            current: self.snapshot.read(),
            mutated: false,
        })
    }

    /// Snapshot of skipped invocation counters. Counters saturate at usize::MAX.
    pub fn skipped(&self) -> SlotSkipCounts {
        SlotSkipCounts {
            transition_busy: self.transition_busy_skips.load(Ordering::SeqCst),
            execution_busy: self.execution_busy_skips.load(Ordering::SeqCst),
            empty: self.empty_skips.load(Ordering::SeqCst),
        }
    }
}

/// The slot's only active invocation.
pub struct ExclusiveReadGuard<'a, T> {
    snapshot: Option<EpochReadGuard<'a, T>>,
    state: &'a AtomicUsize,
}

impl<T> Deref for ExclusiveReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.snapshot.as_deref().expect("live exclusive read guard")
    }
}

impl<T> fmt::Debug for ExclusiveReadGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExclusiveReadGuard(..)")
    }
}

impl<T> Drop for ExclusiveReadGuard<'_, T> {
    fn drop(&mut self) {
        // Publication must never observe active=false while the epoch remains pinned.
        drop(self.snapshot.take());
        self.state.store(OPEN, Ordering::SeqCst);
    }
}

/// A nonblocking transition gate. Dropping it reopens the slot.
pub struct ExclusiveTransitionGuard<'a, T> {
    slot: &'a ExclusiveSlot<T>,
    current: Option<EpochReadGuard<'a, T>>,
    mutated: bool,
}

impl<T> ExclusiveTransitionGuard<'_, T> {
    /// Inspect the value that was current when the transition began.
    pub fn current(&self) -> Option<&T> {
        self.current.as_deref()
    }

    /// Publish one preallocated value while retaining the transition gate.
    pub fn publish(&mut self, next: Box<T>) {
        assert!(!self.mutated, "exclusive transition already mutated");
        drop(self.current.take());
        self.slot.snapshot.publish(next);
        self.mutated = true;
    }

    /// Remove the current value without allocating while retaining the gate.
    pub fn clear(&mut self) {
        assert!(!self.mutated, "exclusive transition already mutated");
        drop(self.current.take());
        self.slot.snapshot.clear();
        self.mutated = true;
    }
}

impl<T> fmt::Debug for ExclusiveTransitionGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExclusiveTransitionGuard(..)")
    }
}

impl<T> Drop for ExclusiveTransitionGuard<'_, T> {
    fn drop(&mut self) {
        drop(self.current.take());
        self.slot.state.store(OPEN, Ordering::SeqCst);
    }
}

fn increment_saturating(counter: &AtomicUsize) {
    let mut current = counter.load(Ordering::SeqCst);
    while current != usize::MAX {
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}
