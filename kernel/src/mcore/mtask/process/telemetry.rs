use core::sync::atomic::AtomicUsize;

#[derive(Default)]
pub struct Telemetry {
    pub page_faults: AtomicUsize,
    #[cfg(feature = "audit-diagnostics")]
    pub pipe_read_blocks: AtomicUsize,
    #[cfg(feature = "audit-diagnostics")]
    pub child_wait_blocks: AtomicUsize,
}
