//! Kernel watchdog safety hooks.

pub fn trigger_estop() -> i64 {
    crate::actuation::watchdog_estop_trigger()
}

pub fn invariant_failed(reason: &str) -> i64 {
    log::error!("watchdog invariant failed: {}", reason);
    trigger_estop()
}
