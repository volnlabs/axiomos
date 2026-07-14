#![cfg(feature = "fault-injection")]

//! Test-only fault-injection controller for `kernel_physical_memory`.
//!
//! Two layers of state are kept:
//! - `BUDGET: AtomicU32` — number of remaining `checkpoint()` calls that
//!   return `false` (i.e., "no fault this call"). After the budget is
//!   exhausted, the next call returns `true`.
//! - `DISARMED: AtomicBool` — when `true`, every `checkpoint()` returns
//!   `false` regardless of `BUDGET`. Initial state is disarmed.
//!
//! `SERIAL: spin::Mutex<()>` serializes the controller against
//! `cargo test`'s parallel-test-thread model. `armed(budget, f)` holds
//! the mutex for the lifetime of `f`, so two threads cannot race-arm
//! the controller. The lock is acquired last (after the controller is
//! observed consistent) and released first (before the controller is
//! mutated) on the way out via `ArmGuard::Drop`.
//!
//! Default features: the entire file is `#[cfg]`-gated out of the build,
//! so production callers see a byte-identical crate. Enable with
//! `cargo test -p kernel_physical_memory --features fault-injection`.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

static BUDGET: AtomicU32 = AtomicU32::new(u32::MAX);
static DISARMED: AtomicBool = AtomicBool::new(true);
static SERIAL: Mutex<()> = Mutex::new(());

/// Arm the controller with `budget` remaining checkpoints before the next
/// fault fires. Subsequent calls to `checkpoint()` will return `false`
/// exactly `budget` times, then `true`.
#[allow(dead_code)]
pub(crate) fn arm(budget: u32) {
    BUDGET.store(budget, Ordering::SeqCst);
    DISARMED.store(false, Ordering::SeqCst);
}

/// Re-disarm the controller so every `checkpoint()` returns `false`. Use
/// when a test needs to verify the no-fault path even after a previous
/// `arm`.
#[allow(dead_code)]
pub(crate) fn disarm() {
    DISARMED.store(true, Ordering::SeqCst);
}

/// Check the controller. Returns `true` if the call should report a fault;
/// `false` otherwise. Decrements `BUDGET` when armed and not yet exhausted.
pub(crate) fn checkpoint() -> bool {
    if DISARMED.load(Ordering::SeqCst) {
        return false;
    }
    let prev = BUDGET.load(Ordering::SeqCst);
    if prev == 0 {
        return true;
    }
    BUDGET.store(prev - 1, Ordering::SeqCst);
    false
}

/// RAII guard that owns `SERIAL` and the previous controller state. On
/// drop, restores `BUDGET` and `DISARMED` to their pre-armed values, then
/// releases the mutex.
///
/// Drop order: field drop is reverse declaration in current Rust, but we
/// restore the controller state explicitly via `Drop::drop` before the
/// `serial` field drops last (Rust struct field drop is declaration
/// order; we put `serial` last so it drops last after our manual
/// restore).
struct ArmGuard {
    prev_budget: u32,
    prev_disarmed: bool,
    /// Held for the lifetime of the `armed` scope; consumed by Drop.
    /// `#[allow(dead_code)]` because the field is only read by Drop
    /// glue, and the compiler cannot see that access for the live-code
    /// analysis.
    #[allow(dead_code)]
    serial: spin::MutexGuard<'static, ()>,
}

impl ArmGuard {
    fn enter(budget: u32) -> Self {
        let serial = SERIAL.lock();
        let prev_budget = BUDGET.swap(budget, Ordering::SeqCst);
        let prev_disarmed = DISARMED.swap(false, Ordering::SeqCst);
        Self {
            prev_budget,
            prev_disarmed,
            serial,
        }
    }
}

impl Drop for ArmGuard {
    fn drop(&mut self) {
        // Restore controller state BEFORE the serial field drops so any
        // observer taking SERIAL after us sees the restored pair.
        BUDGET.store(self.prev_budget, Ordering::SeqCst);
        DISARMED.store(self.prev_disarmed, Ordering::SeqCst);
        // `serial` (the MutexGuard) drops after this method returns,
        // releasing the mutex last.
    }
}

/// Run `f` under an armed controller. The serial mutex is held for the
/// full scope; controller state is restored to whatever it was before
/// `armed` was called. A panic inside `f` propagates after `ArmGuard`'s
/// `Drop` runs the state-restore logic.
///
/// Currently only consumed by tests in this crate. Production callers
/// can wire up cross-crate consumption in a follow-up after the
/// feature forwarding is proven.
#[allow(dead_code)]
pub(crate) fn armed<R>(budget: u32, f: impl FnOnce() -> R) -> R {
    let _guard = ArmGuard::enter(budget);
    f()
}

/// Test-only probe: report whether the controller is currently
/// disarmed. Acquires `SERIAL` briefly so the read sees a consistent
/// snapshot — concurrent `armed` from another test thread cannot race
/// against this read.
///
/// Call only OUTSIDE an active `armed` scope (the `spin::Mutex` is
/// non-reentrant, so calling this from within an `armed` block would
/// deadlock against the `ArmGuard` that already holds `SERIAL`).
#[allow(dead_code)]
pub(crate) fn is_disarmed() -> bool {
    let _guard = SERIAL.lock();
    DISARMED.load(Ordering::SeqCst)
}
