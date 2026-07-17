//! Hardware-independent control loop. All real-time safety logic lives in
//! `shrike_link` (codec + watchdog); this just wires bytes -> decode ->
//! watchdog -> motors and emits periodic sensor frames. Generic over a few thin
//! traits so the RP2040 peripherals (or a host mock) plug in at the edges.

use shrike_link::watchdog::{Output, Watchdog};
use shrike_link::{encode, Decoder, Msg, MAX_FRAME};

use crate::motor::MotorChannel;

/// Non-blocking byte transport (the UART to the Pi5).
pub trait ByteIo {
    /// Next received byte, or `None` if none ready.
    fn read(&mut self) -> Option<u8>;
    /// Best-effort transmit.
    fn write(&mut self, bytes: &[u8]);
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

/// Counters recorded during a bounded run, returned when `run` stops after
/// the requested number of iterations. The production firmware never
/// inspects this struct; the host simulation crate uses it to assert
/// that the control loop reached the expected state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RunSummary {
    /// Number of loop iterations actually executed.
    pub iterations: u32,
    /// Number of `MotorChannel::drive` calls (one per actuated side per
    /// iteration that produced `Output::Drive`).
    pub motor_drive_calls: u32,
    /// Number of `MotorChannel::coast` calls (one per actuated side per
    /// iteration that produced `Output::SafeStop`).
    pub motor_coast_calls: u32,
    /// Total bytes written via `ByteIo::write`.
    pub bytes_written: u32,
    /// Number of `EstopLine::asserted` samples that returned `true`, including
    /// both the assertion edge and subsequent held samples.
    pub estop_asserts: u32,
}

/// Run the control loop.
///
/// - When `max_iterations` is `None`, the loop runs forever (production
///   behavior used by `firmware/shrike/rp2040/src/main.rs`).
/// - When `max_iterations` is `Some(n)`, the loop returns after `n`
///   iterations with a `RunSummary`. The host simulation crate uses this
///   bounded form to exercise the production control loop under mocks.
pub fn run<IO, CK, US, ES, ML, MR>(
    mut io: IO,
    clock: CK,
    mut ultra: US,
    mut estop: ES,
    mut left: ML,
    mut right: MR,
    cfg: Config,
    max_iterations: Option<u32>,
) -> Option<RunSummary>
where
    IO: ByteIo,
    CK: MicrosClock,
    US: Ultrasonic,
    ES: EstopLine,
    ML: MotorChannel,
    MR: MotorChannel,
{
    let mut dec = Decoder::new();
    let mut wd = Watchdog::new(cfg.link_timeout_us);
    let mut last_ping: u64 = 0;
    let mut last_peer_heartbeat: u64 = 0;
    let mut peer_heartbeat_seq: u16 = 0;
    let mut prev_estop = false;
    let mut summary = RunSummary::default();

    loop {
        summary.iterations = summary.iterations.wrapping_add(1);

        let now = clock.now_us();

        // 1. Mirror the hardware e-stop line's EDGES into the watchdog, so a
        //    hard e-stop disarms it exactly like a soft Estop: setpoints that
        //    arrive while the line is asserted cannot arm motion, and after
        //    release a FRESH setpoint is required before driving resumes (no
        //    stale-command restart). Edge-triggered, not every loop, so a held
        //    e-stop never refreshes link liveness and mask a dead link.
        let hw_estop = estop.asserted();
        if hw_estop {
            summary.estop_asserts = summary.estop_asserts.wrapping_add(1);
        }
        if hw_estop != prev_estop {
            wd.on_msg(&Msg::Estop { assert: hw_estop }, now);
            prev_estop = hw_estop;
        }

        // 2. Drain the UART, feeding decoded Pi5 messages to the watchdog.
        while let Some(b) = io.read() {
            if let Some(Ok(msg)) = dec.push(b) {
                wd.on_msg(&msg, now);
            }
            // Decode errors (CRC/len/unknown) are intentionally dropped: a
            // corrupt frame must never reach actuation.
        }

        // 3. Decide. The hardware line also dominates directly (defense in
        //    depth — independent of the edge-mirror above); the watchdog
        //    independently stays disarmed until a fresh post-release setpoint.
        let out = if hw_estop {
            Output::SafeStop
        } else {
            wd.output(now)
        };

        // 4. Actuate.
        match out {
            Output::Drive { left: l, right: r } => {
                left.drive(l);
                right.drive(r);
                summary.motor_drive_calls = summary.motor_drive_calls.wrapping_add(2);
            }
            Output::SafeStop => {
                left.coast();
                right.coast();
                summary.motor_coast_calls = summary.motor_coast_calls.wrapping_add(2);
            }
        }

        // 5. Periodic ultrasonic ping + Sensor report back to the Pi5.
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
            let mut buf = [0u8; MAX_FRAME];
            if let Ok(n) = encode(&msg, &mut buf) {
                io.write(&buf[..n]);
                summary.bytes_written = summary.bytes_written.wrapping_add(n as u32);
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
            let mut buf = [0u8; MAX_FRAME];
            if let Ok(n) = encode(&msg, &mut buf) {
                io.write(&buf[..n]);
                summary.bytes_written = summary.bytes_written.wrapping_add(n as u32);
            }
        }

        if let Some(limit) = max_iterations {
            if summary.iterations >= limit {
                return Some(summary);
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
        fn read(&mut self) -> Option<u8> {
            let byte = self.input.get(self.next).copied();
            self.next = self.next.saturating_add(1);
            byte
        }

        fn write(&mut self, bytes: &[u8]) {
            self.output.borrow_mut().extend_from_slice(bytes);
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

    struct TestMotor<'a> {
        log: &'a RefCell<MotorLog>,
    }

    impl MotorChannel for TestMotor<'_> {
        fn drive(&mut self, duty: i16) {
            self.log.borrow_mut().push(duty);
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
    fn zero_iteration_limit_still_executes_one_safe_iteration() {
        let output = RefCell::new(ByteCapture::new());
        let triggers = Cell::new(0);
        let left = RefCell::new(MotorLog::new());
        let right = RefCell::new(MotorLog::new());

        let summary = run(
            TestIo::new(&[], &output),
            SequenceClock::new(&[0]),
            TestUltrasonic::new(&[None], &triggers),
            TestEstop::new(&[false]),
            TestMotor { log: &left },
            TestMotor { log: &right },
            config(100, u64::MAX, 0),
            Some(0),
        )
        .expect("bounded run must return a summary");

        assert_eq!(summary.iterations, 1);
        assert_eq!(summary.motor_drive_calls, 0);
        assert_eq!(summary.motor_coast_calls, 2);
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
            TestIo::new(&frame[..frame_len], &output),
            SequenceClock::new(&[1, 12]),
            TestUltrasonic::new(&[None, None], &triggers),
            TestEstop::new(&[false, false]),
            TestMotor { log: &left },
            TestMotor { log: &right },
            config(10, u64::MAX, 100),
            Some(2),
        )
        .unwrap();

        assert_eq!(summary.motor_drive_calls, 2);
        assert_eq!(summary.motor_coast_calls, 2);
        assert_eq!(left.borrow().as_slice(), [400, 0]);
        assert_eq!(right.borrow().as_slice(), [-250, 0]);
    }

    #[test]
    #[should_panic(expected = "stop unbounded control-loop test")]
    fn absent_iteration_limit_continues_into_the_next_iteration() {
        let output = RefCell::new(ByteCapture::new());
        let triggers = Cell::new(0);
        let left = RefCell::new(MotorLog::new());
        let right = RefCell::new(MotorLog::new());

        let _ = run(
            TestIo::new(&[], &output),
            PanickingClock {
                calls: Cell::new(0),
            },
            TestUltrasonic::new(&[None], &triggers),
            TestEstop::new(&[false]),
            TestMotor { log: &left },
            TestMotor { log: &right },
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
            TestIo::new(&input[..corrupt_len + valid_len], &output),
            SequenceClock::new(&[1]),
            TestUltrasonic::new(&[None], &triggers),
            TestEstop::new(&[false]),
            TestMotor { log: &left },
            TestMotor { log: &right },
            config(100, u64::MAX, 0),
            Some(1),
        )
        .unwrap();

        assert_eq!(summary.motor_drive_calls, 2);
        assert_eq!(left.borrow().as_slice(), [20]);
        assert_eq!(right.borrow().as_slice(), [-30]);
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
            TestIo::new(&frame[..frame_len], &output),
            SequenceClock::new(&[1, 2, 3]),
            TestUltrasonic::new(&[None, None, None], &triggers),
            TestEstop::new(&[true, true, false]),
            TestMotor { log: &left },
            TestMotor { log: &right },
            config(100, u64::MAX, 0),
            Some(3),
        )
        .unwrap();

        assert_eq!(summary.estop_asserts, 2);
        assert_eq!(summary.motor_drive_calls, 0);
        assert_eq!(summary.motor_coast_calls, 6);
        assert_eq!(left.borrow().as_slice(), [0, 0, 0]);
        assert_eq!(right.borrow().as_slice(), [0, 0, 0]);
    }

    #[test]
    fn periodic_telemetry_uses_wrapping_time_and_increments_heartbeat_sequence() {
        let output = RefCell::new(ByteCapture::new());
        let triggers = Cell::new(0);
        let left = RefCell::new(MotorLog::new());
        let right = RefCell::new(MotorLog::new());
        let summary = run(
            TestIo::new(&[], &output),
            SequenceClock::new(&[u64::MAX - 4, 6]),
            TestUltrasonic::new(&[Some(123), Some(456)], &triggers),
            TestEstop::new(&[false, false]),
            TestMotor { log: &left },
            TestMotor { log: &right },
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
