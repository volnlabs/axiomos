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
//! the controller. The mutex is non-reentrant; do NOT call `is_disarmed`
//! or any other SERIAL-acquiring helper from inside an active `armed`
//! scope.
//!
//! Cross-crate surface policy (enforced by the audit-gate static check):
//! - The module is `pub` so kernel test harnesses can name it as
//!   `kernel_physical_memory::fault`.
//! - Only `armed` is `pub`. `arm`, `disarm`, `checkpoint`, and
//!   `is_disarmed` are `pub(crate)`. `ArmGuard` and the statics are
//!   private.
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
/// drop, restores `BUDGET` and `DISARMED` to their pre-armed values via
/// two separate atomic stores, then releases the mutex.
///
/// The two restore stores are NOT a paired atomic state transition —
/// they are independent `SeqCst` stores, and a panic between them could
/// leave one restored and the other leaked. In practice the only way
/// this happens is a double-panic (which aborts), but callers that
/// require joint restoration should not rely on this. The single-CPU
/// test harness is acceptable for this scenario; multi-CPU callers
/// would need a different guarantee.
///
/// Rust struct field drop order is declaration order: `prev_budget`
/// (no-op), `prev_disarmed` (no-op), then `serial` (releases the
/// mutex). Both restore stores happen inside `Drop::drop` so they
/// complete before the MutexGuard field drops.
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
        // Two separate atomic stores; see the type-level docstring
        // for the joint-restoration caveat.
        BUDGET.store(self.prev_budget, Ordering::SeqCst);
        DISARMED.store(self.prev_disarmed, Ordering::SeqCst);
        // `serial` (the MutexGuard) drops after this method returns,
        // releasing the mutex last so any observer taking SERIAL after
        // us sees a (possibly-not-fully-jointly-restored) but at-least
        // stores-completed state.
    }
}

/// Run `f` under an armed controller. The serial mutex is held for the
/// full scope; controller state is restored to whatever it was before
/// `armed` was called (subject to the joint-restoration caveat on
/// `ArmGuard::drop`). A panic inside `f` propagates after `ArmGuard`'s
/// `Drop` runs the state-restore logic.
///
/// This is the SOLE public entry point of the controller from outside
/// the crate. Cross-crate callers (the kernel test harness) arm the
/// controller by entering a scope; the RAII guard handles teardown.
#[allow(dead_code)]
pub fn armed<R>(budget: u32, f: impl FnOnce() -> R) -> R {
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
