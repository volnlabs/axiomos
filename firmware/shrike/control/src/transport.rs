//! Bounded reverse-link frame ownership and reset-drain prerequisites.

use shrike_link::tx::TxState;
use shrike_link::{Decoder, Msg, MAX_FRAME};

use crate::{ByteIo, MotorPairSink};

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
        now: u64,
    ) -> Result<Self, TransportError> {
        sink.inhibit();
        *decoder = Decoder::new();
        *tx = TelemetryTx::new();
        io.reset().map_err(|_| TransportError::Io)?;
        Ok(Self {
            quiet_since: Some(now),
            last_poll: now,
        })
    }

    /// Drain at most 64 received bytes; every observed byte restarts the full
    /// quiet interval. Clock regression requires another explicit begin.
    pub fn poll(&mut self, io: &mut impl ByteIo, now: u64) -> Result<bool, TransportError> {
        if now < self.last_poll || self.quiet_since.is_none() {
            self.quiet_since = None;
            return Err(TransportError::ClockRegression);
        }
        self.last_poll = now;
        for _ in 0..64 {
            if io.read().is_none() {
                return Ok(now - self.quiet_since.unwrap() >= Self::QUIET_US);
            }
            self.quiet_since = Some(now);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use self::std::collections::VecDeque;
    use self::std::vec::Vec;
    use super::*;

    #[derive(Default)]
    struct Io {
        rx: VecDeque<u8>,
        wire: Vec<u8>,
        quota: usize,
        fail_write: bool,
        fail_reset: bool,
        over_report: bool,
        resets: usize,
    }
    impl ByteIo for Io {
        type Error = ();
        fn read(&mut self) -> Option<u8> {
            self.rx.pop_front()
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
        let mut drain =
            LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, 100).unwrap();
        assert!(sink.stopped);
        assert_eq!(io.resets, 1);
        assert!(io.rx.is_empty());
        assert_eq!(io.wire.len(), 3); // physical actions are not rolled back
        io.quota = usize::MAX;
        assert_eq!(tx.service(&mut io), Ok(0));
        assert_eq!(drain.poll(&mut io, 200_099), Ok(false));
        io.rx.push_back(0x7e); // delayed peer data restarts the entire quiet interval
        assert_eq!(drain.poll(&mut io, 200_100), Ok(false));
        assert_eq!(drain.poll(&mut io, 400_099), Ok(false));
        assert_eq!(drain.poll(&mut io, 400_100), Ok(true));
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
        let mut drain =
            LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, 1).unwrap();
        io.rx.extend(core::iter::repeat_n(7, 65));
        assert_eq!(drain.poll(&mut io, 300_000), Ok(false));
        assert_eq!(io.rx.len(), 1);
        assert_eq!(drain.poll(&mut io, 300_001), Ok(false));
        assert_eq!(
            drain.poll(&mut io, 300_000),
            Err(TransportError::ClockRegression)
        );
        assert_eq!(
            drain.poll(&mut io, 900_000),
            Err(TransportError::ClockRegression)
        );
        io.fail_reset = true;
        assert!(LinkQuiescence::begin(&mut io, &mut sink, &mut decoder, &mut tx, 900_000).is_err());
        assert!(sink.stopped);
    }
}
