//! Hardware-independent control loop. All real-time safety logic lives in
//! `shrike_link` (codec + watchdog); this just wires bytes -> decode ->
//! watchdog -> motors and emits periodic sensor frames. Generic over a few thin
//! traits so the RP2040 peripherals (or a host mock) plug in at the edges.

use shrike_link::watchdog::{Output, Watchdog};
#[cfg(test)]
use shrike_link::{encode, MAX_FRAME};
use shrike_link::{Decoder, Msg};

use crate::fpga::{FpgaLifecycle, FpgaPlatform, LifecycleError};
use crate::transport::TelemetryTx;

/// Keep serial input from monopolizing one control-loop iteration when the
/// UART is continuously ready; watchdog, motors, and telemetry get service.
const RX_BYTES_PER_ITERATION: usize = 64;

/// Non-blocking byte transport (the UART to the Pi5).
pub trait ByteIo {
    type Error;

    /// Next received byte, or `None` if none ready.
    fn read(&mut self) -> Option<u8>;
    /// Try to transmit a prefix. `Ok(0)` is backpressure.
    fn try_write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error>;
    /// Clear software and hardware receive/transmit state.
    fn reset(&mut self) -> Result<(), Self::Error>;
}

/// Atomic paired-motor boundary owned by the FPGA lifecycle. Before calling
/// [`run`], the outer driver must configure the sink and establish zero output;
/// the loop never configures, rearms, or creates a new control session.
pub trait MotorPairSink {
    type Error;

    fn apply(&mut self, seq: u8, left: i16, right: i16) -> Result<(), Self::Error>;
    /// Trusted fail-safe path; implementations must make both outputs safe.
    fn inhibit(&mut self);
}

impl<P: FpgaPlatform> MotorPairSink for FpgaLifecycle<P> {
    type Error = LifecycleError<P::Error>;

    fn apply(&mut self, seq: u8, left: i16, right: i16) -> Result<(), Self::Error> {
        self.runtime_command(seq, left, right, 0)
    }

    fn inhibit(&mut self) {
        self.fail_safe("control loop terminal stop/fault");
    }
}

/// Monotonic microsecond clock.
pub trait MicrosClock {
    fn now_us(&self) -> u64;
}

/// Ultrasonic ranger: fire a ping, later collect its echo time.
pub trait Ultrasonic {
    fn trigger(&mut self);
    /// Latest completed echo time in microseconds, if one is ready.
    fn take_echo_us(&mut self) -> Option<u16>;
}

/// The independent hardware e-stop line as seen by the MCU. (The non-bypassable
/// guarantee is the FPGA gate; reading it here is defense in depth + telemetry.)
pub trait EstopLine {
    /// `&mut` because embedded-hal 1.0 `InputPin` reads take `&mut self`.
    fn asserted(&mut self) -> bool;
}

/// Tunables — all defaulted in `main.rs`, surfaced here so a bench can adjust.
pub struct Config {
    /// Watchdog: max gap between fresh Pi5 frames before motors fail safe.
    pub link_timeout_us: u64,
    /// How often to fire the ultrasonic + report a Sensor frame.
    pub ping_period_us: u64,
    /// Shrike->Pi heartbeat cadence, independent of sensor echo availability.
    pub peer_heartbeat_period_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    HardwareEstop,
    SoftwareEstop,
    WatchdogExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultReason {
    Decode,
    UnexpectedMessage,
    MotorSink,
    Io,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RunTermination {
    #[default]
    IterationLimit,
    Stop(StopReason),
    Fault(FaultReason),
}

/// Result of a bounded run or terminal stop/fault. Borrowed peripherals remain
/// available to the outer driver for explicit reset and FPGA requalification.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RunSummary {
    pub iterations: u32,
    /// Pairs whose sink call completed with an accepted-sequence acknowledgement.
    pub motor_pairs_accepted: u32,
    pub motor_inhibit_calls: u32,
    /// Bytes accepted by local UART writes, not observed delivery.
    pub bytes_written: u64,
    /// Software-owned frames rejected by capacity or discarded on termination/reset.
    /// Loss from resetting the hardware UART FIFO is unknown and not included.
    pub telemetry_frames_dropped: u64,
    pub estop_asserts: u32,
    pub termination: RunTermination,
    /// A reset failure is reported without hiding the stop/fault that triggered it.
    pub io_reset_failed: bool,
}

fn terminate<IO: ByteIo, S: MotorPairSink>(
    io: &mut IO,
    motors: &mut S,
    mut summary: RunSummary,
    termination: RunTermination,
    tx: &TelemetryTx,
) -> Option<RunSummary> {
    motors.inhibit();
    summary.motor_inhibit_calls = summary.motor_inhibit_calls.wrapping_add(1);
    summary.termination = termination;
    summary.bytes_written = tx.accepted_bytes();
    summary.telemetry_frames_dropped = summary
        .telemetry_frames_dropped
        .saturating_add(tx.pending_frames());
    summary.io_reset_failed = io.reset().is_err();
    Some(summary)
}

/// Run until the iteration bound or a terminal stop/fault. Motor commands are
/// submitted once, in decode order; cached watchdog output is never replayed.
/// The caller supplies a freshly qualified sink already holding zero output.
/// After any return, drain/requalify explicitly before starting a new run; this
/// function never establishes a link session or rearms a stopped FPGA.
pub fn run<IO, CK, US, ES, S>(
    io: &mut IO,
    clock: &CK,
    ultra: &mut US,
    estop: &mut ES,
    motors: &mut S,
    cfg: Config,
    max_iterations: Option<u32>,
) -> Option<RunSummary>
where
    IO: ByteIo,
    CK: MicrosClock,
    US: Ultrasonic,
    ES: EstopLine,
    S: MotorPairSink,
{
    let mut tx = TelemetryTx::new();
    let mut dec = Decoder::new();
    let mut wd = Watchdog::new(cfg.link_timeout_us);
    let mut last_ping: u64 = 0;
    let mut last_peer_heartbeat: u64 = 0;
    let mut peer_heartbeat_seq: u16 = 0;
    let mut summary = RunSummary::default();
    let mut command_applied = false;

    if max_iterations == Some(0) {
        return terminate(io, motors, summary, RunTermination::IterationLimit, &tx);
    }

    loop {
        summary.iterations = summary.iterations.wrapping_add(1);

        let mut now = clock.now_us();
        let mut hw_estop = estop.asserted();
        if hw_estop {
            summary.estop_asserts = summary.estop_asserts.wrapping_add(1);
        }
        wd.set_hardware_estop(hw_estop);
        if hw_estop {
            return terminate(
                io,
                motors,
                summary,
                RunTermination::Stop(StopReason::HardwareEstop),
                &tx,
            );
        }
        if command_applied && wd.output(now) == Output::SafeStop {
            return terminate(
                io,
                motors,
                summary,
                RunTermination::Stop(StopReason::WatchdogExpired),
                &tx,
            );
        }

        for _ in 0..RX_BYTES_PER_ITERATION {
            let Some(b) = io.read() else { break };
            let Some(decoded) = dec.push(b) else {
                continue;
            };
            let msg = match decoded {
                Ok(msg) => msg,
                Err(_) => {
                    return terminate(
                        io,
                        motors,
                        summary,
                        RunTermination::Fault(FaultReason::Decode),
                        &tx,
                    );
                }
            };

            now = clock.now_us();
            hw_estop = estop.asserted();
            if hw_estop {
                summary.estop_asserts = summary.estop_asserts.wrapping_add(1);
                wd.set_hardware_estop(true);
                return terminate(
                    io,
                    motors,
                    summary,
                    RunTermination::Stop(StopReason::HardwareEstop),
                    &tx,
                );
            }

            match msg {
                Msg::MotorSetpoint { seq, left, right } => {
                    let accepted = wd.on_msg(&msg, now);
                    let output = wd.output(now);
                    if !accepted {
                        if command_applied && output == Output::SafeStop {
                            return terminate(
                                io,
                                motors,
                                summary,
                                RunTermination::Stop(StopReason::WatchdogExpired),
                                &tx,
                            );
                        }
                        continue;
                    }
                    if output != (Output::Drive { left, right }) {
                        return terminate(
                            io,
                            motors,
                            summary,
                            RunTermination::Stop(StopReason::WatchdogExpired),
                            &tx,
                        );
                    }

                    hw_estop = estop.asserted();
                    if hw_estop {
                        summary.estop_asserts = summary.estop_asserts.wrapping_add(1);
                        wd.set_hardware_estop(true);
                        return terminate(
                            io,
                            motors,
                            summary,
                            RunTermination::Stop(StopReason::HardwareEstop),
                            &tx,
                        );
                    }
                    let before_apply = clock.now_us();
                    if wd.output(before_apply) == Output::SafeStop {
                        return terminate(
                            io,
                            motors,
                            summary,
                            RunTermination::Stop(StopReason::WatchdogExpired),
                            &tx,
                        );
                    }
                    if motors.apply(seq, left, right).is_err() {
                        return terminate(
                            io,
                            motors,
                            summary,
                            RunTermination::Fault(FaultReason::MotorSink),
                            &tx,
                        );
                    }
                    command_applied = true;
                    summary.motor_pairs_accepted = summary.motor_pairs_accepted.wrapping_add(1);

                    let after_apply = clock.now_us();
                    hw_estop = estop.asserted();
                    if hw_estop {
                        summary.estop_asserts = summary.estop_asserts.wrapping_add(1);
                        wd.set_hardware_estop(true);
                        return terminate(
                            io,
                            motors,
                            summary,
                            RunTermination::Stop(StopReason::HardwareEstop),
                            &tx,
                        );
                    }
                    if wd.output(after_apply) == Output::SafeStop {
                        return terminate(
                            io,
                            motors,
                            summary,
                            RunTermination::Stop(StopReason::WatchdogExpired),
                            &tx,
                        );
                    }
                }
                Msg::Estop { .. } => {
                    let _ = wd.on_msg(&msg, now);
                    return terminate(
                        io,
                        motors,
                        summary,
                        RunTermination::Stop(StopReason::SoftwareEstop),
                        &tx,
                    );
                }
                Msg::HeartbeatToShrike { .. } => {
                    let _ = wd.on_msg(&msg, now);
                    if command_applied && wd.output(now) == Output::SafeStop {
                        return terminate(
                            io,
                            motors,
                            summary,
                            RunTermination::Stop(StopReason::WatchdogExpired),
                            &tx,
                        );
                    }
                }
                Msg::Sensor { .. } | Msg::HeartbeatToPi { .. } => {
                    return terminate(
                        io,
                        motors,
                        summary,
                        RunTermination::Fault(FaultReason::UnexpectedMessage),
                        &tx,
                    );
                }
            }
        }

        now = clock.now_us();
        hw_estop = estop.asserted();
        if hw_estop {
            summary.estop_asserts = summary.estop_asserts.wrapping_add(1);
            wd.set_hardware_estop(true);
            return terminate(
                io,
                motors,
                summary,
                RunTermination::Stop(StopReason::HardwareEstop),
                &tx,
            );
        }
        if command_applied && wd.output(now) == Output::SafeStop {
            return terminate(
                io,
                motors,
                summary,
                RunTermination::Stop(StopReason::WatchdogExpired),
                &tx,
            );
        }

        if now.wrapping_sub(last_ping) >= cfg.ping_period_us {
            ultra.trigger();
            last_ping = now;
        }
        if let Some(echo) = ultra.take_echo_us() {
            let msg = Msg::Sensor {
                ultrasonic_echo_us: echo,
                estop_line: hw_estop,
                flags: 0,
            };
            if !tx.queue(msg) {
                summary.telemetry_frames_dropped =
                    summary.telemetry_frames_dropped.saturating_add(1);
            }
        }

        if cfg.peer_heartbeat_period_us > 0
            && now.wrapping_sub(last_peer_heartbeat) >= cfg.peer_heartbeat_period_us
        {
            let msg = Msg::HeartbeatToPi {
                seq: peer_heartbeat_seq,
            };
            peer_heartbeat_seq = peer_heartbeat_seq.wrapping_add(1);
            last_peer_heartbeat = now;
            if !tx.queue(msg) {
                summary.telemetry_frames_dropped =
                    summary.telemetry_frames_dropped.saturating_add(1);
            }
        }
        if tx.service(io).is_err() {
            return terminate(
                io,
                motors,
                summary,
                RunTermination::Fault(FaultReason::Io),
                &tx,
            );
        }

        if let Some(limit) = max_iterations {
            if summary.iterations >= limit {
                return terminate(io, motors, summary, RunTermination::IterationLimit, &tx);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::cell::{Cell, RefCell};

    use super::*;

    const MAX_CAPTURED_BYTES: usize = MAX_FRAME * 8;
    const MAX_MOTOR_CALLS: usize = 8;

    struct ByteCapture {
        bytes: [u8; MAX_CAPTURED_BYTES],
        len: usize,
    }

    impl ByteCapture {
        const fn new() -> Self {
            Self {
                bytes: [0; MAX_CAPTURED_BYTES],
                len: 0,
            }
        }

        fn extend_from_slice(&mut self, bytes: &[u8]) {
            let end = self.len + bytes.len();
            assert!(end <= self.bytes.len(), "test output capture overflow");
            self.bytes[self.len..end].copy_from_slice(bytes);
            self.len = end;
        }

        fn as_slice(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }

    struct TestIo<'a> {
        input: &'a [u8],
        next: usize,
        output: &'a RefCell<ByteCapture>,
    }

    impl<'a> TestIo<'a> {
        fn new(input: &'a [u8], output: &'a RefCell<ByteCapture>) -> Self {
            Self {
                input,
                next: 0,
                output,
            }
        }
    }

    impl ByteIo for TestIo<'_> {
        type Error = ();

        fn read(&mut self) -> Option<u8> {
            let byte = self.input.get(self.next).copied();
            self.next = self.next.saturating_add(1);
            byte
        }

        fn try_write(&mut self, bytes: &[u8]) -> Result<usize, ()> {
            self.output.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn reset(&mut self) -> Result<(), ()> {
            self.next = self.input.len();
            Ok(())
        }
    }

    struct ContinuousIo<'a> {
        input: &'a [u8],
        next: usize,
        output: &'a RefCell<ByteCapture>,
    }

    impl<'a> ByteIo for ContinuousIo<'a> {
        type Error = ();

        fn read(&mut self) -> Option<u8> {
            let byte = self.input.get(self.next).copied().unwrap_or(0);
            self.next = self.next.saturating_add(1);
            Some(byte)
        }

        fn try_write(&mut self, bytes: &[u8]) -> Result<usize, ()> {
            self.output.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn reset(&mut self) -> Result<(), ()> {
            self.next = self.input.len();
            Ok(())
        }
    }

    struct SequenceClock<'a> {
        samples: &'a [u64],
        next: Cell<usize>,
    }

    impl<'a> SequenceClock<'a> {
        const fn new(samples: &'a [u64]) -> Self {
            Self {
                samples,
                next: Cell::new(0),
            }
        }
    }

    impl MicrosClock for SequenceClock<'_> {
        fn now_us(&self) -> u64 {
            let next = self.next.get();
            let sample = self
                .samples
                .get(next)
                .or_else(|| self.samples.last())
                .copied()
                .unwrap_or(0);
            self.next.set(next.saturating_add(1));
            sample
        }
    }

    struct PanickingClock {
        calls: Cell<u8>,
    }

    impl MicrosClock for PanickingClock {
        fn now_us(&self) -> u64 {
            if self.calls.replace(self.calls.get().wrapping_add(1)) == 0 {
                0
            } else {
                panic!("stop unbounded control-loop test")
            }
        }
    }

    struct TestUltrasonic<'a> {
        echoes: &'a [Option<u16>],
        next: usize,
        triggers: &'a Cell<u32>,
    }

    impl<'a> TestUltrasonic<'a> {
        const fn new(echoes: &'a [Option<u16>], triggers: &'a Cell<u32>) -> Self {
            Self {
                echoes,
                next: 0,
                triggers,
            }
        }
    }

    impl Ultrasonic for TestUltrasonic<'_> {
        fn trigger(&mut self) {
            self.triggers.set(self.triggers.get().wrapping_add(1));
        }

        fn take_echo_us(&mut self) -> Option<u16> {
            let echo = self.echoes.get(self.next).copied().flatten();
            self.next = self.next.saturating_add(1);
            echo
        }
    }

    struct TestEstop<'a> {
        samples: &'a [bool],
        next: usize,
    }

    impl<'a> TestEstop<'a> {
        const fn new(samples: &'a [bool]) -> Self {
            Self { samples, next: 0 }
        }
    }

    impl EstopLine for TestEstop<'_> {
        fn asserted(&mut self) -> bool {
            let asserted = self
                .samples
                .get(self.next)
                .or_else(|| self.samples.last())
                .copied()
                .unwrap_or(false);
            self.next = self.next.saturating_add(1);
            asserted
        }
    }

    struct MotorLog {
        duties: [i16; MAX_MOTOR_CALLS],
        len: usize,
    }

    impl MotorLog {
        const fn new() -> Self {
            Self {
                duties: [0; MAX_MOTOR_CALLS],
                len: 0,
            }
        }

        fn push(&mut self, duty: i16) {
            assert!(self.len < self.duties.len(), "test motor log overflow");
            self.duties[self.len] = duty;
            self.len += 1;
        }

        fn as_slice(&self) -> &[i16] {
            &self.duties[..self.len]
        }
    }

    struct TestMotors<'a> {
        left: &'a RefCell<MotorLog>,
        right: &'a RefCell<MotorLog>,
    }

    impl MotorPairSink for TestMotors<'_> {
        type Error = ();

        fn apply(&mut self, _: u8, left: i16, right: i16) -> Result<(), Self::Error> {
            self.left.borrow_mut().push(left);
            self.right.borrow_mut().push(right);
            Ok(())
        }

        fn inhibit(&mut self) {
            self.left.borrow_mut().push(0);
            self.right.borrow_mut().push(0);
        }
    }

    fn config(link_timeout_us: u64, ping_period_us: u64, heartbeat_us: u64) -> Config {
        Config {
            link_timeout_us,
            ping_period_us,
            peer_heartbeat_period_us: heartbeat_us,
        }
    }

    fn decode_output(bytes: &[u8]) -> ([Option<Msg>; 8], usize) {
        let mut decoder = Decoder::new();
        let mut messages = [None; 8];
        let mut count = 0;
        for &byte in bytes {
            if let Some(result) = decoder.push(byte) {
                assert!(count < messages.len(), "too many captured messages");
                messages[count] = Some(result.expect("control loop emitted an invalid frame"));
                count += 1;
            }
        }
        (messages, count)
    }

    #[test]
    fn zero_iteration_limit_exits_safe_without_running_the_loop() {
        let output = RefCell::new(ByteCapture::new());
        let triggers = Cell::new(0);
        let left = RefCell::new(MotorLog::new());
        let right = RefCell::new(MotorLog::new());

        let summary = run(
            &mut TestIo::new(&[], &output),
            &SequenceClock::new(&[0]),
            &mut TestUltrasonic::new(&[None], &triggers),
            &mut TestEstop::new(&[false]),
            &mut TestMotors {
                left: &left,
                right: &right,
            },
            config(100, u64::MAX, 0),
            Some(0),
        )
        .expect("bounded run must return a summary");

        assert_eq!(summary.iterations, 0);
        assert_eq!(summary.motor_pairs_accepted, 0);
        assert_eq!(summary.motor_inhibit_calls, 1);
        assert_eq!(left.borrow().as_slice(), [0]);
        assert_eq!(right.borrow().as_slice(), [0]);
        assert_eq!(triggers.get(), 0);
        assert_eq!(output.borrow().as_slice(), []);
    }

    #[test]
    fn fresh_setpoint_drives_then_link_timeout_coasts() {
        let mut frame = [0; MAX_FRAME];
        let frame_len = encode(
            &Msg::MotorSetpoint {
                seq: 1,
                left: 400,
                right: -250,
            },
            &mut frame,
        )
        .unwrap();
        let output = RefCell::new(ByteCapture::new());
        let triggers = Cell::new(0);
        let left = RefCell::new(MotorLog::new());
        let right = RefCell::new(MotorLog::new());

        let summary = run(
            &mut TestIo::new(&frame[..frame_len], &output),
            &SequenceClock::new(&[1, 1, 1, 1, 1, 12]),
            &mut TestUltrasonic::new(&[None, None], &triggers),
            &mut TestEstop::new(&[false]),
            &mut TestMotors {
                left: &left,
                right: &right,
            },
            config(10, u64::MAX, 100),
            Some(2),
        )
        .unwrap();

        assert_eq!(summary.motor_pairs_accepted, 1);
        assert_eq!(summary.motor_inhibit_calls, 1);
        assert_eq!(left.borrow().as_slice(), [400, 0]);
        assert_eq!(right.borrow().as_slice(), [-250, 0]);
    }

    #[test]
    fn continuous_rx_still_services_motor_and_heartbeat() {
        let mut frame = [0; MAX_FRAME];
        let frame_len = encode(
            &Msg::MotorSetpoint {
                seq: 1,
                left: -400,
                right: 250,
            },
            &mut frame,
        )
        .unwrap();
        let output = RefCell::new(ByteCapture::new());
        let triggers = Cell::new(0);
        let left = RefCell::new(MotorLog::new());
        let right = RefCell::new(MotorLog::new());

        let summary = run(
            &mut ContinuousIo {
                input: &frame[..frame_len],
                next: 0,
                output: &output,
            },
            &SequenceClock::new(&[1]),
            &mut TestUltrasonic::new(&[None, None], &triggers),
            &mut TestEstop::new(&[false]),
            &mut TestMotors {
                left: &left,
                right: &right,
            },
            config(100, u64::MAX, 1),
            Some(2),
        )
        .unwrap();

        assert_eq!(summary.motor_pairs_accepted, 1);
        assert!(summary.bytes_written > 0);
        assert_eq!(left.borrow().as_slice()[0], -400);
        assert_eq!(right.borrow().as_slice()[0], 250);
    }

    #[test]
    #[should_panic(expected = "stop unbounded control-loop test")]
    fn absent_iteration_limit_continues_into_the_next_iteration() {
        let output = RefCell::new(ByteCapture::new());
        let triggers = Cell::new(0);
        let left = RefCell::new(MotorLog::new());
        let right = RefCell::new(MotorLog::new());

        let _ = run(
            &mut TestIo::new(&[], &output),
            &PanickingClock {
                calls: Cell::new(0),
            },
            &mut TestUltrasonic::new(&[None], &triggers),
            &mut TestEstop::new(&[false]),
            &mut TestMotors {
                left: &left,
                right: &right,
            },
            config(100, u64::MAX, 0),
            None,
        );
    }

    #[test]
    fn corrupt_frame_is_dropped_and_decoder_accepts_following_command() {
        let mut corrupt = [0; MAX_FRAME];
        let corrupt_len = encode(
            &Msg::MotorSetpoint {
                seq: 9,
                left: 900,
                right: 900,
            },
            &mut corrupt,
        )
        .unwrap();
        corrupt[5] ^= 1;

        let mut valid = [0; MAX_FRAME];
        let valid_len = encode(
            &Msg::MotorSetpoint {
                seq: 1,
                left: 20,
                right: -30,
            },
            &mut valid,
        )
        .unwrap();
        let mut input = [0; MAX_FRAME * 2];
        input[..corrupt_len].copy_from_slice(&corrupt[..corrupt_len]);
        input[corrupt_len..corrupt_len + valid_len].copy_from_slice(&valid[..valid_len]);

        let output = RefCell::new(ByteCapture::new());
        let triggers = Cell::new(0);
        let left = RefCell::new(MotorLog::new());
        let right = RefCell::new(MotorLog::new());
        let summary = run(
            &mut TestIo::new(&input[..corrupt_len + valid_len], &output),
            &SequenceClock::new(&[1]),
            &mut TestUltrasonic::new(&[None], &triggers),
            &mut TestEstop::new(&[false]),
            &mut TestMotors {
                left: &left,
                right: &right,
            },
            config(100, u64::MAX, 0),
            Some(1),
        )
        .unwrap();

        assert_eq!(
            summary.termination,
            RunTermination::Fault(FaultReason::Decode)
        );
        assert_eq!(summary.motor_pairs_accepted, 0);
        assert_eq!(left.borrow().as_slice(), [0]);
        assert_eq!(right.borrow().as_slice(), [0]);
    }

    #[test]
    fn hardware_estop_dominates_and_release_does_not_rearm_stale_setpoint() {
        let mut frame = [0; MAX_FRAME];
        let frame_len = encode(
            &Msg::MotorSetpoint {
                seq: 1,
                left: 500,
                right: 500,
            },
            &mut frame,
        )
        .unwrap();
        let output = RefCell::new(ByteCapture::new());
        let triggers = Cell::new(0);
        let left = RefCell::new(MotorLog::new());
        let right = RefCell::new(MotorLog::new());

        let summary = run(
            &mut TestIo::new(&frame[..frame_len], &output),
            &SequenceClock::new(&[1, 2, 3]),
            &mut TestUltrasonic::new(&[None, None, None], &triggers),
            &mut TestEstop::new(&[true, true, false]),
            &mut TestMotors {
                left: &left,
                right: &right,
            },
            config(100, u64::MAX, 0),
            Some(3),
        )
        .unwrap();

        assert_eq!(summary.estop_asserts, 1);
        assert_eq!(summary.motor_pairs_accepted, 0);
        assert_eq!(summary.motor_inhibit_calls, 1);
        assert_eq!(left.borrow().as_slice(), [0]);
        assert_eq!(right.borrow().as_slice(), [0]);
    }

    #[test]
    fn hardware_release_cannot_clear_an_operator_stop() {
        // One RX batch per iteration. Soft stop at t=1, physical stop at t=2,
        // then a new motor command alongside physical release at t=3.
        let mut input = [0u8; RX_BYTES_PER_ITERATION * 3];
        encode(&Msg::Estop { assert: true }, &mut input).unwrap();
        encode(
            &Msg::MotorSetpoint {
                seq: 1,
                left: 400,
                right: 400,
            },
            &mut input[RX_BYTES_PER_ITERATION * 2..],
        )
        .unwrap();
        let output = RefCell::new(ByteCapture::new());
        let triggers = Cell::new(0);
        let left = RefCell::new(MotorLog::new());
        let right = RefCell::new(MotorLog::new());
        run(
            &mut TestIo::new(&input, &output),
            &SequenceClock::new(&[1, 2, 3]),
            &mut TestUltrasonic::new(&[None, None, None], &triggers),
            &mut TestEstop::new(&[false, true, false]),
            &mut TestMotors {
                left: &left,
                right: &right,
            },
            config(100, u64::MAX, 0),
            Some(3),
        )
        .unwrap();
        assert_eq!(left.borrow().as_slice(), [0]);
        assert_eq!(right.borrow().as_slice(), [0]);
    }

    #[test]
    fn periodic_telemetry_uses_wrapping_time_and_increments_heartbeat_sequence() {
        let output = RefCell::new(ByteCapture::new());
        let triggers = Cell::new(0);
        let left = RefCell::new(MotorLog::new());
        let right = RefCell::new(MotorLog::new());
        let summary = run(
            &mut TestIo::new(&[], &output),
            &SequenceClock::new(&[u64::MAX - 4, u64::MAX - 4, 6, 6]),
            &mut TestUltrasonic::new(&[Some(123), Some(456)], &triggers),
            &mut TestEstop::new(&[false, false]),
            &mut TestMotors {
                left: &left,
                right: &right,
            },
            config(100, 10, 10),
            Some(2),
        )
        .unwrap();

        let output = output.borrow();
        let (messages, count) = decode_output(output.as_slice());
        assert_eq!(triggers.get(), 2);
        assert_eq!(summary.bytes_written as usize, output.len);
        assert_eq!(count, 4);
        assert_eq!(
            &messages[..count],
            [
                Some(Msg::Sensor {
                    ultrasonic_echo_us: 123,
                    estop_line: false,
                    flags: 0,
                }),
                Some(Msg::HeartbeatToPi { seq: 0 }),
                Some(Msg::Sensor {
                    ultrasonic_echo_us: 456,
                    estop_line: false,
                    flags: 0,
                }),
                Some(Msg::HeartbeatToPi { seq: 1 }),
            ]
        );
    }
}
