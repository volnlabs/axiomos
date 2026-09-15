//! Bounded frame-aware control-link transmit state.

use crate::{encode, Msg, MAX_FRAME};

/// Captured by the managed executor. Correlation only; never actuation authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MotorOrigin {
    pub cycle: u64,
    pub generation: u64,
    pub artifact_handle: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MotorRequest {
    pub left: i16,
    pub right: i16,
    pub queued_at: u64,
    pub origin: Option<MotorOrigin>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MotorFrame {
    pub request: MotorRequest,
    pub sequence: u8,
    /// A zero crossing inserted by TX while the original target remains pending.
    pub intermediate_zero: bool,
}

/// Observed removals returned directly by a mutation, never queued or retained.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MotorDiscards {
    pub pending: Option<MotorRequest>,
    pub frame: Option<MotorFrame>,
}

const _: () = assert!(core::mem::size_of::<MotorDiscards>() <= 128);

#[derive(Clone, Copy)]
struct Frame {
    bytes: [u8; MAX_FRAME],
    len: u8,
    sent: u8,
    motor: Option<MotorFrame>,
    clears_motor: bool,
    queued_at: u64,
}

pub struct TxState {
    active: Option<Frame>,
    pending_motor: Option<MotorRequest>,
    last_motor_on_wire: (i16, i16),
}

const _: () = assert!(core::mem::size_of::<TxState>() <= 256);

impl TxState {
    pub fn replace_motor_request(&mut self, request: MotorRequest) -> MotorDiscards {
        MotorDiscards {
            pending: self.pending_motor.replace(request),
            frame: None,
        }
    }
    /// Busy/encode failure preserves the exact pending request, including a
    /// reversal target. The sequence is consumed only when Some is returned.
    pub fn start_pending_motor(&mut self, sequence: u8) -> Option<MotorFrame> {
        let (request, intermediate_zero) = self.next_motor()?;
        if !self.start(
            &Msg::MotorSetpoint {
                seq: sequence,
                left: request.left,
                right: request.right,
            },
            request.queued_at,
        ) {
            return None;
        }
        let motor = MotorFrame {
            request,
            sequence,
            intermediate_zero,
        };
        self.active
            .as_mut()
            .expect("successful start owns active frame")
            .motor = Some(motor);
        if !intermediate_zero {
            self.pending_motor = None;
        }
        Some(motor)
    }
    /// Advance only after UART acceptance. Completion means all frame bytes
    /// entered the local UART; it is not a peer/FPGA acknowledgement.
    pub fn next_byte_with_motor_completion(&mut self) -> Option<(u8, Option<MotorFrame>)> {
        let frame = self.active.as_mut()?;
        let byte = frame.bytes[frame.sent as usize];
        frame.sent += 1;
        let complete = if frame.sent == frame.len {
            let motor = frame.motor;
            if let Some(motor) = motor {
                self.last_motor_on_wire = (motor.request.left, motor.request.right);
            } else if frame.clears_motor {
                self.last_motor_on_wire = (0, 0);
            }
            self.active = None;
            motor
        } else {
            None
        };
        Some((byte, complete))
    }

    pub fn pending_motor(&self) -> Option<MotorRequest> {
        self.pending_motor
    }
    pub fn active_motor(&self) -> Option<MotorFrame> {
        self.active.as_ref()?.motor
    }
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
            motor: match *msg {
                Msg::MotorSetpoint { seq, left, right } => Some(MotorFrame {
                    request: MotorRequest {
                        left,
                        right,
                        queued_at: now,
                        origin: None,
                    },
                    sequence: seq,
                    intermediate_zero: false,
                }),
                _ => None,
            },
            clears_motor: matches!(
                msg,
                Msg::Estop { assert: true } | Msg::SafeBarrier { .. } | Msg::SessionOffer { .. }
            ),
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
        self.next_byte_with_motor_completion().map(|(byte, _)| byte)
    }

    pub fn cancel_unsent(&mut self) -> MotorDiscards {
        MotorDiscards {
            pending: None,
            frame: if self.active.is_some_and(|frame| frame.sent == 0) {
                self.active.take().and_then(|frame| frame.motor)
            } else {
                None
            },
        }
    }

    pub const fn is_idle(&self) -> bool {
        self.active.is_none()
    }
    pub fn replace_motor(&mut self, left: i16, right: i16, now: u64) {
        self.replace_motor_request(MotorRequest {
            left,
            right,
            queued_at: now,
            origin: None,
        });
    }
    /// Supersede obsolete unsent motion with a safe pair. A partial frame must
    /// finish, after which this pair is next.
    pub fn prioritize_motor(&mut self, left: i16, right: i16, now: u64) {
        self.prioritize_motor_request(MotorRequest {
            left,
            right,
            queued_at: now,
            origin: None,
        });
    }

    pub fn prioritize_motor_request(&mut self, request: MotorRequest) -> MotorDiscards {
        // A safe motor value cannot cancel a queued e-stop or its release.
        let mut discarded = if self
            .active
            .is_some_and(|frame| frame.motor.is_some() && frame.sent == 0)
        {
            self.cancel_unsent()
        } else {
            MotorDiscards::default()
        };
        discarded.pending = self.pending_motor.replace(request);
        discarded
    }
    pub fn clear_motor(&mut self) -> MotorDiscards {
        MotorDiscards {
            pending: self.pending_motor.take(),
            frame: None,
        }
    }
    pub fn take_motor(&mut self) -> Option<(i16, i16, u64)> {
        // Legacy tuple callers cannot accidentally strip a managed origin.
        if self.pending_motor?.origin.is_some() {
            return None;
        }
        let (request, intermediate) = self.next_motor()?;
        if !intermediate {
            self.pending_motor = None;
        }
        Some((request.left, request.right, request.queued_at))
    }

    fn next_motor(&self) -> Option<(MotorRequest, bool)> {
        let request = self.pending_motor?;
        let reverses = |current: i16, target: i16| {
            current != 0 && target != 0 && current.signum() != target.signum()
        };
        if reverses(self.last_motor_on_wire.0, request.left)
            || reverses(self.last_motor_on_wire.1, request.right)
        {
            Some((
                MotorRequest {
                    left: 0,
                    right: 0,
                    ..request
                },
                true,
            ))
        } else {
            Some((request, false))
        }
    }

    /// Drop motor work that has not put a byte on the wire within the sender
    /// bound. A partial frame must finish; bytes may already be in a UART FIFO.
    pub fn discard_expired_motor(&mut self, now: u64, timeout: u64) -> MotorDiscards {
        let mut discarded = MotorDiscards::default();
        if self
            .pending_motor
            .is_some_and(|request| now.saturating_sub(request.queued_at) >= timeout)
        {
            discarded.pending = self.pending_motor.take();
        }
        if self.active.is_some_and(|frame| {
            frame.motor.is_some()
                && frame.sent == 0
                && now.saturating_sub(frame.queued_at) >= timeout
        }) {
            discarded.frame = self.cancel_unsent().frame;
        }
        discarded
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
    fn discarded_motor_custody_reports_original_owners_once() {
        let mut tx = TxState::new();
        let old = MotorRequest {
            left: 100,
            right: -200,
            queued_at: 1,
            origin: Some(MotorOrigin {
                cycle: 7,
                generation: 9,
                artifact_handle: 0,
            }),
        };
        let new = MotorRequest {
            queued_at: 2,
            origin: None,
            ..old
        };
        assert_eq!(tx.replace_motor_request(old), MotorDiscards::default());
        assert_eq!(
            tx.replace_motor_request(new),
            MotorDiscards {
                pending: Some(old),
                frame: None
            }
        );
        assert_eq!(tx.pending_motor(), Some(new));
        assert_eq!(tx.clear_motor().pending, Some(new));
        assert_eq!(tx.clear_motor(), MotorDiscards::default());
        let mut bytes = [0; MAX_FRAME];
        let len = encode(
            &Msg::MotorSetpoint {
                seq: 255,
                left: old.left,
                right: old.right,
            },
            &mut bytes,
        )
        .unwrap();
        for action in 0..3 {
            for offset in 0..=len {
                let mut tx = TxState::new();
                tx.replace_motor_request(old);
                let frame = tx.start_pending_motor(255).unwrap();
                for _ in 0..offset {
                    tx.next_byte();
                }
                tx.replace_motor_request(new);
                let safe = MotorRequest {
                    left: 0,
                    right: 0,
                    queued_at: 100,
                    ..new
                };
                let discarded = match action {
                    0 => {
                        let mut dropped = tx.clear_motor();
                        dropped.frame = tx.cancel_unsent().frame;
                        dropped
                    }
                    1 => tx.prioritize_motor_request(safe),
                    _ => {
                        assert_eq!(tx.discard_expired_motor(9, 10), MotorDiscards::default());
                        tx.discard_expired_motor(12, 10)
                    }
                };
                assert_eq!(discarded.pending, Some(new));
                assert_eq!(discarded.frame, (offset == 0).then_some(frame));
                assert_eq!(tx.pending_motor(), (action == 1).then_some(safe));
                assert_eq!(tx.cancel_unsent(), MotorDiscards::default());
                assert_eq!(tx.discard_expired_motor(12, 10), MotorDiscards::default());
                let mut completion = None;
                while let Some((_, done)) = tx.next_byte_with_motor_completion() {
                    if done.is_some() {
                        assert!(completion.is_none());
                        completion = done;
                    }
                }
                assert_eq!(completion, (offset > 0 && offset < len).then_some(frame));
            }
        }
    }

    #[test]
    fn tagged_motor_origin_survives_busy_reversal_and_complete_frame() {
        let mut tx = TxState::new();
        let origin = MotorOrigin {
            cycle: 1 << 40,
            generation: 1 << 41,
            artifact_handle: 0,
        };
        let request = MotorRequest {
            left: 200,
            right: 200,
            queued_at: 10,
            origin: Some(origin),
        };
        tx.replace_motor_request(request);
        assert_eq!(tx.take_motor(), None); // Legacy tuple API cannot strip origin.
        let first = tx.start_pending_motor(255).unwrap();
        assert_eq!(first.request, request);
        assert!(!first.intermediate_zero);
        while let Some((_, complete)) = tx.next_byte_with_motor_completion() {
            assert_eq!(complete, tx.is_idle().then_some(first));
        }
        let reverse = MotorRequest {
            left: -200,
            right: -200,
            queued_at: 11,
            origin: Some(MotorOrigin {
                cycle: origin.cycle + 1,
                ..origin
            }),
        };
        tx.replace_motor_request(reverse);
        assert!(tx.start(&Msg::HeartbeatToShrike { seq: 7 }, 11));
        assert_eq!(tx.start_pending_motor(0), None);
        while tx.next_byte().is_some() {}
        let zero = tx.start_pending_motor(0).unwrap();
        assert_eq!(zero.request.origin, reverse.origin);
        assert_eq!((zero.request.left, zero.request.right), (0, 0));
        assert!(zero.intermediate_zero);
        // A pending newer cycle cannot relabel the already-started zero frame.
        tx.next_byte();
        let newer = MotorRequest {
            queued_at: 12,
            origin: Some(MotorOrigin {
                cycle: origin.cycle + 2,
                ..origin
            }),
            ..reverse
        };
        tx.replace_motor_request(newer);
        while let Some((_, complete)) = tx.next_byte_with_motor_completion() {
            assert_eq!(complete, tx.is_idle().then_some(zero));
        }
        let framed = tx.start_pending_motor(1).unwrap();
        assert_eq!(framed.request, newer);
        assert!(!framed.intermediate_zero);
        let mut decoder = Decoder::new();
        let mut decoded = None;
        while let Some((byte, complete)) = tx.next_byte_with_motor_completion() {
            decoded = decoder.push(byte).or(decoded);
            assert_eq!(complete, tx.is_idle().then_some(framed));
        }
        assert_eq!(
            decoded,
            Some(Ok(Msg::MotorSetpoint {
                seq: 1,
                left: -200,
                right: -200
            }))
        );
        assert_eq!(tx.start_pending_motor(2), None);
    }

    #[test]
    fn tagged_origin_expires_or_retires_with_its_own_frame_at_every_byte_offset() {
        let request = MotorRequest {
            left: 300,
            right: -400,
            queued_at: 1,
            origin: Some(MotorOrigin {
                cycle: 9,
                generation: 2,
                artifact_handle: 17,
            }),
        };
        let mut encoded = [0; MAX_FRAME];
        let len = encode(
            &Msg::MotorSetpoint {
                seq: 3,
                left: request.left,
                right: request.right,
            },
            &mut encoded,
        )
        .unwrap();
        for offset in 0..=len {
            let mut tx = TxState::new();
            tx.replace_motor_request(request);
            let frame = tx.start_pending_motor(3).unwrap();
            for _ in 0..offset {
                tx.next_byte();
            }
            tx.replace_motor_request(MotorRequest {
                queued_at: 2,
                ..request
            });
            tx.discard_expired_motor(100, 50);
            tx.cancel_unsent();
            assert_eq!(tx.pending_motor(), None);
            assert_eq!(
                tx.active_motor(),
                (offset > 0 && offset < len).then_some(frame)
            );
            let mut completed = None;
            while let Some((_, completion)) = tx.next_byte_with_motor_completion() {
                if completion.is_some() {
                    assert!(completed.is_none());
                    completed = completion;
                }
            }
            assert_eq!(completed, (offset > 0 && offset < len).then_some(frame));
            assert_eq!(tx.active_motor(), None);
            tx.replace_motor_request(request);
            tx.prioritize_motor(0, 0, 101);
            let safe = tx.start_pending_motor(4).unwrap();
            assert_eq!(safe.request.origin, None);
            assert_eq!((safe.request.left, safe.request.right), (0, 0));
            tx.clear_motor();
            assert_eq!(tx.pending_motor(), None);
        }
    }

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
