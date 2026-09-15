//! Inhibited MCU preparation for one explicitly requested control-link session.

use core::num::NonZeroU32;

use shrike_link::{Decoder, Msg};

use crate::fpga::{BitstreamManifest, FpgaLifecycle, FpgaPlatform, LifecycleError};
use crate::transport::{LinkQuiescence, TelemetryTx, TransportError};
use crate::{ByteIo, EstopLine, MicrosClock};

#[derive(Clone, Copy, Debug)]
pub struct RequalificationRequest {
    pub session: NonZeroU32,
    pub manifest: BitstreamManifest,
    pub ready_timeout_us: u64,
    /// Absolute deadline in the supplied MicrosClock domain, also used by the
    /// outer owner's subsequent exact-session offer wait. Not the 80 ms handoff.
    pub deadline_us: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Cause<E> {
    Transport(TransportError),
    Fpga(LifecycleError<E>),
    HardwareStop,
    UnexpectedTraffic,
    QueueFull,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Failure<E> {
    pub cause: Cause<E>,
    /// Preserve the original failure even if clearing the UART also fails.
    pub io_reset_failed: bool,
}

/// Total preparation drain/TX passes; the following offer wait independently
/// uses the same ceiling. A frozen clock or permanent backpressure cannot hold
/// the owner forever. Requires target qualification, not a time or WCET claim.
pub const MAX_POLLS: u32 = 1_048_576;

fn check<E>(
    clock: &impl MicrosClock,
    estop: &mut impl EstopLine,
    previous: &mut u64,
    deadline: u64,
) -> Result<(), Cause<E>> {
    let stopped = estop.asserted();
    let now = clock.now_us();
    if stopped {
        return Err(Cause::HardwareStop);
    }
    if now < *previous {
        return Err(Cause::Transport(TransportError::ClockRegression));
    }
    if now >= deadline {
        return Err(Cause::Transport(TransportError::TimedOut));
    }
    *previous = now;
    Ok(())
}

fn require_rx_idle<E>(io: &mut impl ByteIo) -> Result<(), Cause<E>> {
    match io.read() {
        Ok(None) => Ok(()),
        // Pi must remain silent until Prepared has arrived and its own fresh
        // drain has completed. Any byte here, including an e-stop, aborts.
        Ok(Some(_)) => Err(Cause::UnexpectedTraffic),
        Err(_) => Err(Cause::Transport(TransportError::Io)),
    }
}

/// Drain locally, configure reset state, then send one complete Prepared frame.
/// Does not issue any motor command, release e-stop, or establish a session.
/// Success leaves UART RX intact for the outer owner's exact SessionOffer wait;
/// that owner must use request.deadline_us and keep ordinary commands inhibited.
pub fn prepare<IO: ByteIo, CK: MicrosClock, ES: EstopLine, P: FpgaPlatform>(
    request: RequalificationRequest,
    io: &mut IO,
    clock: &CK,
    estop: &mut ES,
    fpga: &mut FpgaLifecycle<P>,
) -> Result<(), Failure<P::Error>> {
    let mut previous = clock.now_us();
    fpga.fail_safe("explicit MCU preparation");
    let mut decoder = Decoder::new();
    let mut tx = TelemetryTx::new();
    let mut remaining = MAX_POLLS;
    let result = (|| {
        check(clock, estop, &mut previous, request.deadline_us)?;
        let mut drain = LinkQuiescence::begin(io, fpga, &mut decoder, &mut tx, clock)
            .map_err(Cause::Transport)?;
        check(clock, estop, &mut previous, request.deadline_us)?;
        loop {
            remaining = remaining
                .checked_sub(1)
                .ok_or(Cause::Transport(TransportError::PollLimit))?;
            check(clock, estop, &mut previous, request.deadline_us)?;
            let quiet = drain.poll(io, clock).map_err(Cause::Transport)?;
            check(clock, estop, &mut previous, request.deadline_us)?;
            if quiet {
                break;
            }
        }
        // No accepted zero command here: it would start the FPGA watchdog
        // before Pi's following >=200 ms quiet interval and consume sequence 0.
        fpga.configure(request.manifest, request.ready_timeout_us)
            .map_err(Cause::Fpga)?;
        check(clock, estop, &mut previous, request.deadline_us)?;
        require_rx_idle(io)?;
        check(clock, estop, &mut previous, request.deadline_us)?;
        if !tx.queue_priority(Msg::Prepared {
            session: request.session.get(),
        }) {
            return Err(Cause::QueueFull);
        }
        loop {
            remaining = remaining
                .checked_sub(1)
                .ok_or(Cause::Transport(TransportError::PollLimit))?;
            check(clock, estop, &mut previous, request.deadline_us)?;
            require_rx_idle(io)?;
            check(clock, estop, &mut previous, request.deadline_us)?;
            tx.service(io).map_err(Cause::Transport)?;
            check(clock, estop, &mut previous, request.deadline_us)?;
            if tx.pending_frames() != 0 {
                continue;
            }
            let idle = io
                .tx_idle()
                .map_err(|_| Cause::Transport(TransportError::Io))?;
            check(clock, estop, &mut previous, request.deadline_us)?;
            // Include receive faults/traffic arriving during the final idle
            // observation; never reset them away into successful readiness.
            require_rx_idle(io)?;
            check(clock, estop, &mut previous, request.deadline_us)?;
            if idle {
                return Ok(());
            }
        }
    })();
    result.map_err(|cause| {
        fpga.fail_safe("MCU preparation failed");
        Failure {
            cause,
            io_reset_failed: io.reset().is_err(),
        }
    })
}
