//! Bounded frame-aware control-link transmit state.

use crate::{encode, Msg, MAX_FRAME};

#[derive(Clone, Copy)]
struct Frame {
    bytes: [u8; MAX_FRAME],
    len: u8,
    sent: u8,
    motor_pair: Option<(i16, i16)>,
    estop_assert: bool,
    queued_at: u64,
}

pub struct TxState {
    active: Option<Frame>,
    pending_motor: Option<(i16, i16, u64)>,
    last_motor_on_wire: (i16, i16),
}

impl TxState {
    pub const fn new() -> Self {
        Self {
            active: None,
            pending_motor: None,
            last_motor_on_wire: (0, 0),
        }
    }

    pub fn start(&mut self, msg: &Msg, now: u64) -> bool {
        if self.active.is_some() {
            return false;
        }
        let mut bytes = [0; MAX_FRAME];
        let Ok(len) = encode(msg, &mut bytes) else {
            return false;
        };
        self.active = Some(Frame {
            bytes,
            len: len as u8,
            sent: 0,
            motor_pair: match *msg {
                Msg::MotorSetpoint { left, right, .. } => Some((left, right)),
                _ => None,
            },
            estop_assert: matches!(msg, Msg::Estop { assert: true }),
            queued_at: now,
        });
        true
    }

    /// Inspect the next byte without relinquishing it to a backpressured UART.
    /// Call `next_byte` only after the transport accepts this byte.
    pub fn peek_byte(&self) -> Option<u8> {
        let frame = self.active.as_ref()?;
        Some(frame.bytes[frame.sent as usize])
    }

    pub fn next_byte(&mut self) -> Option<u8> {
        let frame = self.active.as_mut()?;
        let byte = frame.bytes[frame.sent as usize];
        frame.sent += 1;
        if frame.sent == frame.len {
            if let Some(pair) = frame.motor_pair {
                self.last_motor_on_wire = pair;
            } else if frame.estop_assert {
                self.last_motor_on_wire = (0, 0);
            }
            self.active = None;
        }
        Some(byte)
    }

    pub fn cancel_unsent(&mut self) {
        if self.active.is_some_and(|frame| frame.sent == 0) {
            self.active = None;
        }
    }

    pub const fn is_idle(&self) -> bool {
        self.active.is_none()
    }
    pub fn replace_motor(&mut self, left: i16, right: i16, now: u64) {
        self.pending_motor = Some((left, right, now));
    }
    /// Supersede obsolete unsent motion with a safe pair. A partial frame must
    /// finish, after which this pair is next.
    pub fn prioritize_motor(&mut self, left: i16, right: i16, now: u64) {
        // A safe motor value cannot cancel a queued e-stop or its release.
        if self
            .active
            .is_some_and(|frame| frame.motor_pair.is_some() && frame.sent == 0)
        {
            self.active = None;
        }
        self.pending_motor = Some((left, right, now));
    }
    pub fn clear_motor(&mut self) {
        self.pending_motor = None;
    }
    pub fn take_motor(&mut self) -> Option<(i16, i16, u64)> {
        let (left, right, queued_at) = self.pending_motor?;
        let reverses = |current: i16, target: i16| {
            current != 0 && target != 0 && current.signum() != target.signum()
        };
        if reverses(self.last_motor_on_wire.0, left) || reverses(self.last_motor_on_wire.1, right) {
            Some((0, 0, queued_at))
        } else {
            self.pending_motor.take()
        }
    }

    /// Drop motor work that has not put a byte on the wire within the sender
    /// bound. A partial frame must finish; bytes may already be in a UART FIFO.
    pub fn discard_expired_motor(&mut self, now: u64, timeout: u64) {
        if self
            .pending_motor
            .is_some_and(|(_, _, at)| now.saturating_sub(at) >= timeout)
        {
            self.pending_motor = None;
        }
        if self.active.is_some_and(|frame| {
            frame.motor_pair.is_some()
                && frame.sent == 0
                && now.saturating_sub(frame.queued_at) >= timeout
        }) {
            self.active = None;
        }
    }
}

impl Default for TxState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decoder;

    #[test]
    fn a_backpressured_writer_keeps_the_same_byte_until_accepted() {
        let mut tx = TxState::new();
        assert!(tx.start(&Msg::HeartbeatToPi { seq: 7 }, 0));
        let mut decoder = Decoder::new();
        let mut result = None;
        while let Some(byte) = tx.peek_byte() {
            for _ in 0..4 {
                assert_eq!(tx.peek_byte(), Some(byte));
            }
            assert_eq!(tx.next_byte(), Some(byte));
            result = decoder.push(byte).or(result);
        }
        assert_eq!(result, Some(Ok(Msg::HeartbeatToPi { seq: 7 })));
        assert!(tx.is_idle());
    }

    #[test]
    fn safe_zero_cannot_cancel_an_unsent_estop() {
        let mut tx = TxState::new();
        assert!(tx.start(&Msg::Estop { assert: true }, 0));
        tx.prioritize_motor(0, 0, 1);
        assert!(!tx.is_idle());
        let mut decoder = Decoder::new();
        let mut decoded = None;
        while let Some(byte) = tx.next_byte() {
            decoded = decoder.push(byte).or(decoded);
        }
        assert_eq!(decoded.unwrap().unwrap(), Msg::Estop { assert: true });
        assert_eq!(tx.take_motor(), Some((0, 0, 1)));
    }

    #[test]
    fn stalled_tx_keeps_one_frame_and_latest_of_one_hundred_complete_pairs() {
        let mut tx = TxState::new();
        assert!(tx.start(&Msg::HeartbeatToShrike { seq: 1 }, 0));
        for n in 0..100 {
            tx.replace_motor(n, -n, n as u64);
        }
        assert_eq!(tx.take_motor(), Some((99, -99, 99)));
        assert!(!tx.start(
            &Msg::MotorSetpoint {
                seq: 1,
                left: 1,
                right: 2
            },
            100
        ));
    }

    #[test]
    fn stop_cancels_unsent_but_follows_a_complete_partial_frame() {
        let motor = Msg::MotorSetpoint {
            seq: 7,
            left: 300,
            right: -400,
        };
        let mut tx = TxState::new();
        assert!(tx.start(&motor, 0));
        tx.replace_motor(500, 600, 0);
        tx.clear_motor();
        tx.cancel_unsent();
        assert!(tx.start(&Msg::Estop { assert: true }, 0));

        let mut decoder = Decoder::new();
        while let Some(byte) = tx.next_byte() {
            if let Some(decoded) = decoder.push(byte) {
                assert_eq!(decoded.unwrap(), Msg::Estop { assert: true });
            }
        }
        assert!(tx.start(&Msg::Estop { assert: false }, 1));
        while tx.next_byte().is_some() {}
        assert_eq!(tx.take_motor(), None);

        assert!(tx.start(&motor, 0));
        let first = tx.next_byte().unwrap();
        tx.cancel_unsent();
        assert!(!tx.start(&Msg::Estop { assert: true }, 0));
        let mut wire = [0u8; MAX_FRAME];
        wire[0] = first;
        let mut len = 1;
        while let Some(byte) = tx.next_byte() {
            wire[len] = byte;
            len += 1;
        }
        let mut decoder = Decoder::new();
        let mut decoded = None;
        for byte in &wire[..len] {
            decoded = decoder.push(*byte).or(decoded);
        }
        assert_eq!(decoded.unwrap().unwrap(), motor);
        assert!(tx.start(&Msg::Estop { assert: true }, 0));
    }

    #[test]
    fn stalled_unsent_motor_expires_even_while_other_link_activity_can_continue() {
        let mut tx = TxState::new();
        assert!(tx.start(&Msg::HeartbeatToShrike { seq: 9 }, 10));
        tx.replace_motor(100, 200, 10);
        tx.discard_expired_motor(109, 100);
        assert_eq!(tx.take_motor(), Some((100, 200, 10)));
        tx.replace_motor(300, 400, 10);
        // Receiving peer heartbeats updates LinkSession, not this independent
        // sender age. The stalled active frame remains bounded to one frame.
        tx.discard_expired_motor(110, 100);
        assert_eq!(tx.take_motor(), None);
        assert!(!tx.is_idle());
        while tx.next_byte().is_some() {}
        assert!(tx.start(
            &Msg::MotorSetpoint {
                seq: 1,
                left: 500,
                right: -500,
            },
            10,
        ));
        tx.discard_expired_motor(110, 100);
        assert!(tx.is_idle());
    }

    #[test]
    fn promotion_preserves_age_and_priority_safe_pair_supersedes_unsent_motion() {
        let mut tx = TxState::new();
        tx.replace_motor(700, 700, 10);
        let (left, right, queued_at) = tx.take_motor().unwrap();
        assert!(tx.start(
            &Msg::MotorSetpoint {
                seq: 1,
                left,
                right,
            },
            queued_at,
        ));
        tx.discard_expired_motor(109, 100);
        assert!(!tx.is_idle());
        tx.discard_expired_motor(110, 100);
        assert!(tx.is_idle());

        assert!(tx.start(
            &Msg::MotorSetpoint {
                seq: 2,
                left: 600,
                right: -600,
            },
            200,
        ));
        tx.prioritize_motor(0, 0, 201);
        assert!(tx.is_idle());
        assert_eq!(tx.take_motor(), Some((0, 0, 201)));
    }

    #[test]
    fn overwritten_zero_still_crosses_zero_on_wire_before_reverse() {
        let mut tx = TxState::new();
        assert!(tx.start(
            &Msg::MotorSetpoint {
                seq: 1,
                left: 200,
                right: 200,
            },
            0,
        ));
        while tx.next_byte().is_some() {}

        tx.replace_motor(0, 0, 1);
        tx.replace_motor(-200, -200, 2);
        let (left, right, at) = tx.take_motor().unwrap();
        assert_eq!((left, right), (0, 0));
        assert!(tx.start(
            &Msg::MotorSetpoint {
                seq: 2,
                left,
                right,
            },
            at,
        ));
        let mut decoder = Decoder::new();
        let mut decoded = None;
        while let Some(byte) = tx.next_byte() {
            decoded = decoder.push(byte).or(decoded);
        }
        assert_eq!(
            decoded.unwrap().unwrap(),
            Msg::MotorSetpoint {
                seq: 2,
                left: 0,
                right: 0,
            }
        );

        assert_eq!(tx.take_motor(), Some((-200, -200, 2)));
    }
}
