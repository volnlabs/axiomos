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
    DeadlineOverflow,
    TimedOut,
}

/// One active frame and one pending frame. Priority replies may replace
/// telemetry, but a started frame and an acknowledgement are never evicted.
#[derive(Default)]
pub struct TelemetryTx {
    frame: TxState,
    active: Option<Msg>,
    active_started: bool,
    pending: Option<Msg>,
    accepted_bytes: u64,
    dropped_telemetry: u64,
}

impl TelemetryTx {
    pub const fn new() -> Self {
        Self {
            frame: TxState::new(),
            active: None,
            active_started: false,
            pending: None,
            accepted_bytes: 0,
            dropped_telemetry: 0,
        }
    }

    pub fn queue(&mut self, msg: Msg) -> bool {
        if !matches!(msg, Msg::Sensor { .. } | Msg::HeartbeatToPi { .. }) {
            return false;
        }
        self.promote();
        if self.frame.is_idle() {
            self.start(msg)
        } else if self.pending.is_none() {
            self.pending = Some(msg);
            true
        } else {
            false
        }
    }

    /// Queue a session/safety acknowledgement ahead of telemetry. An exact
    /// duplicate is idempotent; a distinct acknowledgement receives bounded
    /// backpressure when both ownership slots already contain acknowledgements.
    pub fn queue_priority(&mut self, msg: Msg) -> bool {
        if !is_priority(msg) {
            return false;
        }
        // Validate the complete canonical frame before inspecting or mutating
        // either ownership slot. In particular, an invalid identity must not
        // evict telemetry and later disappear when `TxState::start` rejects it.
        let mut encoded = [0; MAX_FRAME];
        if shrike_link::encode(&msg, &mut encoded).is_err() {
            return false;
        }
        if self.active == Some(msg) || self.pending == Some(msg) {
            return true;
        }
        if self.frame.is_idle() {
            return self.start(msg);
        }

        if self.active.is_some_and(is_priority) {
            return self.replace_pending_telemetry(msg);
        }
        if !self.active_started {
            self.frame.cancel_unsent();
            if self.active.take().is_some_and(is_telemetry) {
                self.dropped_telemetry = self.dropped_telemetry.saturating_add(1);
            }
            return self.start(msg);
        }
        self.replace_pending_telemetry(msg)
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
                    self.active_started = true;
                    self.frame.next_byte();
                    self.accepted_bytes = self.accepted_bytes.saturating_add(1);
                    accepted += 1;
                    if self.frame.is_idle() {
                        self.active = None;
                        self.active_started = false;
                    }
                }
                _ => return Err(TransportError::InvalidWriteCount),
            }
        }
        Ok(accepted)
    }

    pub const fn accepted_bytes(&self) -> u64 {
        self.accepted_bytes
    }

    pub const fn dropped_telemetry(&self) -> u64 {
        self.dropped_telemetry
    }

    pub fn pending_frames(&self) -> u64 {
        u64::from(!self.frame.is_idle()) + u64::from(self.pending.is_some())
    }

    fn promote(&mut self) {
        if self.frame.is_idle() {
            if let Some(msg) = self.pending.take() {
                let started = self.start(msg);
                debug_assert!(started);
            }
        }
    }

    fn start(&mut self, msg: Msg) -> bool {
        let started = self.frame.start(&msg, 0);
        if started {
            self.active = Some(msg);
            self.active_started = false;
        }
        started
    }

    fn replace_pending_telemetry(&mut self, msg: Msg) -> bool {
        match self.pending {
            Some(pending) if is_priority(pending) => false,
            Some(_) => {
                self.pending = Some(msg);
                self.dropped_telemetry = self.dropped_telemetry.saturating_add(1);
                true
            }
            None => {
                self.pending = Some(msg);
                true
            }
        }
    }
}

const fn is_priority(msg: Msg) -> bool {
    matches!(msg, Msg::SessionReady { .. } | Msg::SafeAck { .. })
}

const fn is_telemetry(msg: Msg) -> bool {
    matches!(msg, Msg::Sensor { .. } | Msg::HeartbeatToPi { .. })
}

/// Local prerequisite for session establishment, not a session or rearm token.
/// Both peers must prohibit motion and transmission during this procedure.
/// The target must qualify ByteIo::reset against its real queues/FIFOs; these
/// host checks cannot prove that a remote peer or UART has become quiescent.
pub struct LinkQuiescence {
    /// A fault poisons this drain attempt until a fresh successful `begin`.
    quiet_since: Result<u64, TransportError>,
    last_poll: u64,
    deadline: u64,
}

impl LinkQuiescence {
    pub const QUIET_US: u64 = 200_000;
    /// The reference profile's local UART attempt limit; unrelated to the
    /// 80 ms controller handoff timeout. Activity never extends this deadline.
    pub const TIMEOUT_US: u64 = 1_000_000;

    pub fn begin(
        io: &mut impl ByteIo,
        sink: &mut impl MotorPairSink,
        decoder: &mut Decoder,
        tx: &mut TelemetryTx,
        clock: &impl MicrosClock,
    ) -> Result<Self, TransportError> {
        let started = clock.now_us();
        sink.inhibit();
        *decoder = Decoder::new();
        *tx = TelemetryTx::new();
        io.reset().map_err(|_| TransportError::Io)?;
        let now = clock.now_us();
        let mut drain = Self {
            quiet_since: Ok(now),
            last_poll: started,
            deadline: started
                .checked_add(Self::TIMEOUT_US)
                .ok_or(TransportError::DeadlineOverflow)?,
        };
        drain.check_time(now)?;
        Ok(drain)
    }

    fn check_time(&mut self, now: u64) -> Result<(), TransportError> {
        self.quiet_since?;
        let error = if now < self.last_poll {
            Some(TransportError::ClockRegression)
        } else if now >= self.deadline {
            Some(TransportError::TimedOut)
        } else {
            None
        };
        if let Some(error) = error {
            self.quiet_since = Err(error);
            return Err(error);
        }
        self.last_poll = now;
        Ok(())
    }

    /// Drain at most 64 received bytes; every observed byte restarts the full
    /// quiet interval. RX or clock faults retain their first cause and require
    /// another explicit begin; neither is an idle observation.
    pub fn poll(
        &mut self,
        io: &mut impl ByteIo,
        clock: &impl MicrosClock,
    ) -> Result<bool, TransportError> {
        let mut quiet_since = self.quiet_since?;
        for _ in 0..64 {
            let before_read = clock.now_us();
            self.check_time(before_read)?;
            let received = match io.read() {
                Ok(byte) => byte.is_some(),
                Err(_) => {
                    self.quiet_since = Err(TransportError::Io);
                    return Err(TransportError::Io);
                }
            };
            let after_read = clock.now_us();
            self.check_time(after_read)?;
            if !received {
                // One extra microsecond covers timer quantization after I/O.
                return Ok(before_read - quiet_since > Self::QUIET_US);
            }
            quiet_since = after_read;
            self.quiet_since = Ok(after_read);
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
        fail_read: bool,
        fail_reset: bool,
        over_report: bool,
        resets: usize,
        reads: usize,
        clock: Option<Rc<Cell<u64>>>,
        reset_elapsed_us: u64,
        read_elapsed_us: VecDeque<u64>,
    }
    impl ByteIo for Io {
        type Error = ();
        fn read(&mut self) -> Result<Option<u8>, ()> {
            self.reads += 1;
            if self.fail_read {
                return Err(());
            }
            let received = self.rx.pop_front();
            if let (Some(clock), Some(elapsed)) = (&self.clock, self.read_elapsed_us.pop_front()) {
                clock.set(clock.get().saturating_add(elapsed));
            }
            Ok(received)
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
    fn priority_reply_never_truncates_a_started_frame_at_any_byte_offset() {
        let telemetry = Msg::Sensor {
            ultrasonic_echo_us: 126,
            estop_line: true,
            flags: 0,
        };
        let displaced = Msg::HeartbeatToPi { seq: 9 };
        let reply = Msg::SafeAck {
            session: 7,
            correlation: 0x0102_0304_0506_0708,
            sequence: 4,
        };
        let mut encoded = [0; MAX_FRAME];
        let telemetry_len = shrike_link::encode(&telemetry, &mut encoded).unwrap();

        for split in 0..=telemetry_len {
            let mut tx = TelemetryTx::new();
            let mut io = Io {
                quota: split,
                ..Io::default()
            };
            assert!(tx.queue(telemetry));
            assert!(tx.queue(displaced));
            assert_eq!(tx.service(&mut io), Ok(split));
            assert!(tx.queue_priority(reply));
            assert_eq!(tx.dropped_telemetry(), 1);

            io.quota = usize::MAX;
            tx.service(&mut io).unwrap();
            let expected = if split == 0 {
                std::vec![reply, displaced]
            } else {
                std::vec![telemetry, reply]
            };
            assert_eq!(messages(&io.wire), expected, "split {split}");
        }
    }

    #[test]
    fn priority_capacity_is_exact_and_acknowledgements_are_idempotent_not_evicted() {
        let ready = Msg::SessionReady { session: 11 };
        let ack = Msg::SafeAck {
            session: 11,
            correlation: 29,
            sequence: 3,
        };
        let other = Msg::SafeAck {
            session: 11,
            correlation: 30,
            sequence: 3,
        };
        let mut tx = TelemetryTx::new();
        assert!(tx.queue_priority(ready));
        assert!(tx.queue_priority(ready));
        assert!(tx.queue_priority(ack));
        assert!(tx.queue_priority(ack));
        assert!(!tx.queue_priority(other));
        assert!(!tx.queue(Msg::HeartbeatToPi { seq: 1 }));
        assert_eq!(tx.pending_frames(), 2);
        assert_eq!(tx.dropped_telemetry(), 0);

        let mut io = Io {
            quota: usize::MAX,
            ..Io::default()
        };
        tx.service(&mut io).unwrap();
        assert_eq!(messages(&io.wire), [ready, ack]);
    }

    #[test]
    fn priority_rejects_unrelated_messages_and_counts_each_telemetry_eviction() {
        let mut tx = TelemetryTx::new();
        assert!(!tx.queue_priority(Msg::HeartbeatToPi { seq: 1 }));
        assert!(tx.queue(Msg::HeartbeatToPi { seq: 2 }));
        assert!(tx.queue(Msg::HeartbeatToPi { seq: 3 }));
        assert!(tx.queue_priority(Msg::SessionReady { session: 9 }));
        assert_eq!(tx.dropped_telemetry(), 1);
        assert_eq!(tx.pending_frames(), 2);
    }

    #[test]
    fn invalid_priority_identity_cannot_mutate_or_evict_queued_frames() {
        let first = Msg::HeartbeatToPi { seq: 17 };
        let second = Msg::Sensor {
            ultrasonic_echo_us: 81,
            estop_line: false,
            flags: 2,
        };
        let mut tx = TelemetryTx::new();
        assert!(tx.queue(first));
        assert!(tx.queue(second));
        let mut io = Io {
            quota: 1,
            ..Io::default()
        };
        assert_eq!(tx.service(&mut io), Ok(1));
        let before = (
            tx.pending_frames(),
            tx.accepted_bytes(),
            tx.dropped_telemetry(),
        );

        for invalid in [
            Msg::SessionReady { session: 0 },
            Msg::SafeAck {
                session: 0,
                correlation: 1,
                sequence: 0,
            },
            Msg::SafeAck {
                session: 1,
                correlation: 0,
                sequence: 0,
            },
        ] {
            assert!(!tx.queue_priority(invalid));
            assert_eq!(
                (
                    tx.pending_frames(),
                    tx.accepted_bytes(),
                    tx.dropped_telemetry(),
                ),
                before
            );
        }

        io.quota = usize::MAX;
        tx.service(&mut io).unwrap();
        assert_eq!(messages(&io.wire), [first, second]);
        assert_eq!(tx.dropped_telemetry(), 0);
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
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        clock.set(400_100 + 1);
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
    fn rx_error_at_quiet_boundary_stays_invalid_until_a_fresh_successful_begin() {
        let mut io = Io::default();
        let mut sink = Sink::default();
        let mut decoder = Decoder::new();
        let mut tx = TelemetryTx::new();
        let clock = Clock::new(0);
        let mut drain =
            LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, &clock).unwrap();
        assert!(io.rx.is_empty());
        clock.set(LinkQuiescence::QUIET_US);
        io.fail_read = true; // A sticky hardware overrun can accompany an empty FIFO.
        assert_eq!(drain.poll(&mut io, &clock), Err(TransportError::Io));
        let reads = io.reads;
        io.fail_read = false;
        for now in [400_000, 0, 800_000] {
            clock.set(now);
            assert_eq!(drain.poll(&mut io, &clock), Err(TransportError::Io));
            assert_eq!(io.reads, reads, "a faulted drain must not resume I/O");
        }
        io.fail_reset = true;
        assert!(LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, &clock).is_err());
        assert_eq!(drain.poll(&mut io, &clock), Err(TransportError::Io));
        io.fail_reset = false;
        let mut fresh =
            LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, &clock).unwrap();
        clock.set(999_999);
        assert_eq!(fresh.poll(&mut io, &clock), Ok(false));
        clock.set(1_000_000);
        assert_eq!(fresh.poll(&mut io, &clock), Ok(false));
        clock.set(1_000_000 + 1);
        assert_eq!(fresh.poll(&mut io, &clock), Ok(true));
        assert!(sink.stopped);
    }

    #[test]
    fn rx_error_cannot_replace_an_earlier_clock_fault() {
        let mut io = Io::default();
        let mut sink = Sink::default();
        let mut decoder = Decoder::new();
        let mut tx = TelemetryTx::new();
        let clock = Clock::new(10);
        let mut drain =
            LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, &clock).unwrap();
        clock.set(9);
        assert_eq!(
            drain.poll(&mut io, &clock),
            Err(TransportError::ClockRegression)
        );
        io.fail_read = true;
        clock.set(300_000);
        assert_eq!(
            drain.poll(&mut io, &clock),
            Err(TransportError::ClockRegression)
        );
        assert_eq!(io.reads, 0);
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
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        clock.set(200_050 + 1);
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
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        clock.set(200_050 + 1);
        assert_eq!(drain.poll(&mut io, &clock), Ok(true));
    }

    #[test]
    fn drain_activity_cannot_extend_the_attempt_deadline_or_revive_failure() {
        let clock = Clock::new(0);
        let mut io = Io::default();
        let mut sink = Sink::default();
        let mut decoder = Decoder::new();
        let mut tx = TelemetryTx::new();
        let mut drain =
            LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, &clock).unwrap();
        for now in (50_000..1_000_000).step_by(50_000) {
            clock.set(now);
            io.rx.push_back(1);
            assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        }
        clock.set(1_000_000);
        assert_eq!(drain.poll(&mut io, &clock), Err(TransportError::TimedOut));
        let reads = io.reads;
        for now in [1_300_000, 0] {
            clock.set(now);
            assert_eq!(drain.poll(&mut io, &clock), Err(TransportError::TimedOut));
            assert_eq!(io.reads, reads);
        }
        assert!(sink.stopped);
        assert!(io.wire.is_empty());
    }

    #[test]
    fn drain_deadline_includes_reset_and_read_io_and_rejects_overflow() {
        for (start, reset_elapsed, error) in [
            (0, 1_000_000, TransportError::TimedOut),
            (u64::MAX - 999_999, 0, TransportError::DeadlineOverflow),
        ] {
            let clock = Clock::new(start);
            let mut io = Io {
                clock: Some(clock.0.clone()),
                reset_elapsed_us: reset_elapsed,
                ..Io::default()
            };
            let mut sink = Sink::default();
            assert_eq!(
                LinkQuiescence::begin(
                    &mut io,
                    &mut sink,
                    &mut Decoder::new(),
                    &mut TelemetryTx::new(),
                    &clock
                )
                .err(),
                Some(error)
            );
            assert!(sink.stopped);
            assert_eq!(io.resets, 1);
        }
        for received in [false, true] {
            let clock = Clock::new(0);
            let mut io = Io {
                clock: Some(clock.0.clone()),
                read_elapsed_us: [1].into(),
                ..Io::default()
            };
            let mut drain = LinkQuiescence::begin(
                &mut io,
                &mut Sink::default(),
                &mut Decoder::new(),
                &mut TelemetryTx::new(),
                &clock,
            )
            .unwrap();
            if received {
                io.rx.push_back(1);
            }
            clock.set(999_999);
            assert_eq!(drain.poll(&mut io, &clock), Err(TransportError::TimedOut));
            assert_eq!(io.reads, 1);
            assert_eq!(drain.poll(&mut io, &clock), Err(TransportError::TimedOut));
            assert_eq!(io.reads, 1);
        }
    }

    #[test]
    fn reset_clock_reversal_rejects_the_attempt_after_inhibiting() {
        struct ReversingClock(Cell<u64>);
        impl MicrosClock for ReversingClock {
            fn now_us(&self) -> u64 {
                let now = self.0.get();
                self.0.set(now - 1);
                now
            }
        }
        let mut io = Io::default();
        let mut sink = Sink::default();
        let result = LinkQuiescence::begin(
            &mut io,
            &mut sink,
            &mut Decoder::new(),
            &mut TelemetryTx::new(),
            &ReversingClock(Cell::new(10)),
        );
        assert_eq!(result.err(), Some(TransportError::ClockRegression));
        assert!(sink.stopped);
        assert_eq!(io.resets, 1);
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
        assert_eq!(drain.poll(&mut io, &clock), Ok(false));
        clock.set(200_001);
        assert_eq!(drain.poll(&mut io, &clock), Ok(true));
    }
}
