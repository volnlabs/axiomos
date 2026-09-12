//! Bounded reverse-link frame ownership and reset-drain prerequisites.

use shrike_link::tx::TxState;
use shrike_link::{Decoder, Msg, MAX_FRAME};

use crate::{ByteIo, MicrosClock, MotorPairSink};

/// Errors require inhibition and a fresh drain; partial frames cannot be retried
/// blindly after an I/O failure with an unknown accepted prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Io,
    InvalidWriteCount,
    ClockRegression,
}

/// One active frame and one pending frame. Overflow rejects a whole message;
/// the caller counts the loss. This carries telemetry only, not M5 safe acks.
#[derive(Default)]
pub struct TelemetryTx {
    frame: TxState,
    pending: Option<Msg>,
    accepted_bytes: u64,
}

impl TelemetryTx {
    pub const fn new() -> Self {
        Self {
            frame: TxState::new(),
            pending: None,
            accepted_bytes: 0,
        }
    }

    pub fn queue(&mut self, msg: Msg) -> bool {
        if !matches!(msg, Msg::Sensor { .. } | Msg::HeartbeatToPi { .. }) {
            return false;
        }
        self.promote();
        if self.frame.is_idle() {
            self.frame.start(&msg, 0)
        } else if self.pending.is_none() {
            self.pending = Some(msg);
            true
        } else {
            false
        }
    }

    /// Make at most 2*MAX_FRAME one-byte nonblocking attempts. Only an accepted
    /// byte advances TxState; a full UART leaves the same byte at its head.
    pub fn service(&mut self, io: &mut impl ByteIo) -> Result<usize, TransportError> {
        let mut accepted = 0;
        for _ in 0..MAX_FRAME * 2 {
            self.promote();
            let Some(byte) = self.frame.peek_byte() else {
                break;
            };
            match io.try_write(&[byte]).map_err(|_| TransportError::Io)? {
                0 => break,
                1 => {
                    self.frame.next_byte();
                    self.accepted_bytes = self.accepted_bytes.saturating_add(1);
                    accepted += 1;
                }
                _ => return Err(TransportError::InvalidWriteCount),
            }
        }
        Ok(accepted)
    }

    pub const fn accepted_bytes(&self) -> u64 {
        self.accepted_bytes
    }

    pub fn pending_frames(&self) -> u64 {
        u64::from(!self.frame.is_idle()) + u64::from(self.pending.is_some())
    }

    fn promote(&mut self) {
        if self.frame.is_idle() {
            if let Some(msg) = self.pending.take() {
                // Both permitted telemetry shapes always fit MAX_FRAME.
                let started = self.frame.start(&msg, 0);
                debug_assert!(started);
            }
        }
    }
}

/// Local prerequisite for session establishment, not a session or rearm token.
/// Both peers must prohibit motion and transmission during this procedure.
/// The target must qualify ByteIo::reset against its real queues/FIFOs; these
/// host checks cannot prove that a remote peer or UART has become quiescent.
pub struct LinkQuiescence {
    quiet_since: Option<u64>,
    last_poll: u64,
}

impl LinkQuiescence {
    pub const QUIET_US: u64 = 200_000;

    pub fn begin(
        io: &mut impl ByteIo,
        sink: &mut impl MotorPairSink,
        decoder: &mut Decoder,
        tx: &mut TelemetryTx,
        clock: &impl MicrosClock,
    ) -> Result<Self, TransportError> {
        sink.inhibit();
        *decoder = Decoder::new();
        *tx = TelemetryTx::new();
        io.reset().map_err(|_| TransportError::Io)?;
        let now = clock.now_us();
        Ok(Self {
            quiet_since: Some(now),
            last_poll: now,
        })
    }

    /// Drain at most 64 received bytes; every observed byte restarts the full
    /// quiet interval. Clock regression requires another explicit begin.
    pub fn poll(
        &mut self,
        io: &mut impl ByteIo,
        clock: &impl MicrosClock,
    ) -> Result<bool, TransportError> {
        let Some(mut quiet_since) = self.quiet_since else {
            return Err(TransportError::ClockRegression);
        };
        for _ in 0..64 {
            let before_read = clock.now_us();
            if before_read < self.last_poll {
                self.quiet_since = None;
                return Err(TransportError::ClockRegression);
            }
            let received = io.read().is_some();
            let after_read = clock.now_us();
            if after_read < before_read {
                self.quiet_since = None;
                return Err(TransportError::ClockRegression);
            }
            self.last_poll = after_read;
            if !received {
                return Ok(before_read - quiet_since >= Self::QUIET_US);
            }
            quiet_since = after_read;
            self.quiet_since = Some(after_read);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use self::std::cell::Cell;
    use self::std::collections::VecDeque;
    use self::std::rc::Rc;
    use self::std::vec::Vec;
    use super::*;
    use crate::MicrosClock;

    #[derive(Default)]
    struct Io {
        rx: VecDeque<u8>,
        wire: Vec<u8>,
        quota: usize,
        fail_write: bool,
        fail_reset: bool,
        over_report: bool,
        resets: usize,
        clock: Option<Rc<Cell<u64>>>,
        reset_elapsed_us: u64,
        read_elapsed_us: VecDeque<u64>,
    }
    impl ByteIo for Io {
        type Error = ();
        fn read(&mut self) -> Option<u8> {
            let received = self.rx.pop_front();
            if let (Some(clock), Some(elapsed)) = (&self.clock, self.read_elapsed_us.pop_front()) {
                clock.set(clock.get().saturating_add(elapsed));
            }
            received
        }
        fn try_write(&mut self, bytes: &[u8]) -> Result<usize, ()> {
            if self.fail_write {
                return Err(());
            }
            if self.over_report {
                return Ok(bytes.len() + 1);
            }
            let n = bytes.len().min(self.quota);
            self.wire.extend_from_slice(&bytes[..n]);
            self.quota -= n;
            Ok(n)
        }
        fn reset(&mut self) -> Result<(), ()> {
            self.resets += 1;
            if self.fail_reset {
                return Err(());
            }
            self.rx.clear();
            if let Some(clock) = &self.clock {
                clock.set(clock.get().saturating_add(self.reset_elapsed_us));
            }
            // Already captured bytes are historical; only queued RX is modeled.
            Ok(())
        }
    }
    #[derive(Default)]
    struct Sink {
        stopped: bool,
    }
    impl MotorPairSink for Sink {
        type Error = ();
        fn apply(&mut self, _: u8, _: i16, _: i16) -> Result<(), ()> {
            panic!("drain must never drive")
        }
        fn inhibit(&mut self) {
            self.stopped = true;
        }
    }
    struct Clock(Rc<Cell<u64>>);
    impl Clock {
        fn new(now: u64) -> Self {
            Self(Rc::new(Cell::new(now)))
        }
        fn set(&self, now: u64) {
            self.0.set(now);
        }
    }
    impl MicrosClock for Clock {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
    }
    fn messages(wire: &[u8]) -> Vec<Msg> {
        let mut decoder = Decoder::new();
        wire.iter()
            .filter_map(|&b| decoder.push(b))
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn every_partial_frame_offset_survives_backpressure_without_interleaving() {
        let first = Msg::HeartbeatToPi { seq: 7 };
        let second = Msg::Sensor {
            ultrasonic_echo_us: 126,
            estop_line: true,
            flags: 0,
        };
        for split in 0..=8 {
            let mut tx = TelemetryTx::new();
            let mut io = Io {
                quota: split,
                ..Io::default()
            };
            assert!(tx.queue(first));
            assert!(tx.queue(second));
            assert!(!tx.queue(Msg::HeartbeatToPi { seq: 999 }));
            assert_eq!(tx.service(&mut io), Ok(split));
            io.quota = usize::MAX;
            tx.service(&mut io).unwrap();
            assert_eq!(messages(&io.wire), [first, second]);
            assert_eq!(tx.service(&mut io), Ok(0));
        }
    }

    #[test]
    fn reverse_tx_rejects_motion_and_transport_errors() {
        let mut tx = TelemetryTx::new();
        assert!(!tx.queue(Msg::MotorSetpoint {
            seq: 1,
            left: 0,
            right: 0
        }));
        assert!(tx.queue(Msg::HeartbeatToPi { seq: 1 }));
        let mut io = Io {
            fail_write: true,
            ..Io::default()
        };
        assert_eq!(tx.service(&mut io), Err(TransportError::Io));
        io.fail_write = false;
        io.over_report = true;
        assert_eq!(tx.service(&mut io), Err(TransportError::InvalidWriteCount));
        assert!(io.wire.is_empty());
    }

    #[test]
    fn reset_discards_partial_decoder_tx_and_hardware_queues_then_requires_quiet() {
        let mut tx = TelemetryTx::new();
        let mut io = Io {
            quota: 3,
            ..Io::default()
        };
        let mut sink = Sink::default();
        let mut decoder = Decoder::new();
        decoder.push(0x7e);
        decoder.push(1);
        tx.queue(Msg::HeartbeatToPi { seq: 99 });
        tx.service(&mut io).unwrap();
        io.rx.extend([1, 2, 3]);
        let clock = Clock::new(100);
        let mut drain =
            LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, &clock).unwrap();
        assert!(sink.stopped);
        assert_eq!(io.resets, 1);
        assert!(io.rx.is_empty());
        assert_eq!(io.wire.len(), 3); // physical actions are not rolled back
        io.quota = usize::MAX;
        assert_eq!(tx.service(&mut io), Ok(0));
        clock.set(200_099);
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        io.rx.push_back(0x7e); // delayed peer data restarts the entire quiet interval
        clock.set(200_100);
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        clock.set(400_099);
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        clock.set(400_100);
        assert_eq!(drain.poll(&mut io, &clock), Ok(true));
        assert!(sink.stopped); // eligibility does not rearm or manufacture a session
        let mut frame = [0; shrike_link::MAX_FRAME];
        let msg = Msg::HeartbeatToShrike { seq: 2 };
        let n = shrike_link::encode(&msg, &mut frame).unwrap();
        let decoded: Vec<_> = frame[..n].iter().filter_map(|&b| decoder.push(b)).collect();
        assert_eq!(decoded, [Ok(msg)]);
    }

    #[test]
    fn drain_work_is_bounded_and_reset_or_clock_failure_cannot_become_ready() {
        let mut io = Io::default();
        let mut sink = Sink::default();
        let mut decoder = Decoder::new();
        let mut tx = TelemetryTx::new();
        let clock = Clock::new(1);
        let mut drain =
            LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, &clock).unwrap();
        io.rx.extend(core::iter::repeat_n(7, 65));
        clock.set(300_000);
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        assert_eq!(io.rx.len(), 1);
        clock.set(300_001);
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        clock.set(300_000);
        assert_eq!(
            drain.poll(&mut io, &clock),
            Err(TransportError::ClockRegression)
        );
        clock.set(900_000);
        assert_eq!(
            drain.poll(&mut io, &clock),
            Err(TransportError::ClockRegression)
        );
        io.fail_reset = true;
        assert!(LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, &clock).is_err());
        assert!(sink.stopped);
    }

    #[test]
    fn reset_elapsed_time_is_not_credited_to_the_quiet_interval() {
        let clock = Clock::new(0);
        let mut io = Io {
            clock: Some(clock.0.clone()),
            reset_elapsed_us: 50,
            ..Io::default()
        };
        let mut sink = Sink::default();
        let mut decoder = Decoder::new();
        let mut tx = TelemetryTx::new();
        let mut drain =
            LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, &clock).unwrap();

        clock.set(200_000);
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        clock.set(200_050);
        assert_eq!(drain.poll(&mut io, &clock), Ok(true));
    }

    #[test]
    fn receive_elapsed_time_is_not_credited_to_the_quiet_interval() {
        let clock = Clock::new(0);
        let mut io = Io {
            clock: Some(clock.0.clone()),
            read_elapsed_us: [50, 0, 0, 0].into(),
            ..Io::default()
        };
        let mut sink = Sink::default();
        let mut decoder = Decoder::new();
        let mut tx = TelemetryTx::new();
        let mut drain =
            LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, &clock).unwrap();

        io.rx.push_back(1);
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        clock.set(200_000);
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        clock.set(200_050);
        assert_eq!(drain.poll(&mut io, &clock), Ok(true));
    }

    #[test]
    fn empty_observation_before_deadline_does_not_use_later_return_time() {
        let clock = Clock::new(0);
        let mut io = Io {
            clock: Some(clock.0.clone()),
            read_elapsed_us: [50, 0].into(),
            ..Io::default()
        };
        let mut sink = Sink::default();
        let mut decoder = Decoder::new();
        let mut tx = TelemetryTx::new();
        let mut drain =
            LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, &clock).unwrap();

        clock.set(199_950);
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        assert_eq!(clock.now_us(), 200_000);
        assert_eq!(drain.poll(&mut io, &clock), Ok(true));
    }
}
