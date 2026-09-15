//! Bounded Pi-side session and safe-barrier correlation. The platform owns
//! drain/requalification and physical I/O; these states never assert motion.

use crate::tx::{HandoffFrame, MotorDiscards, TxState};
use crate::Msg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarrierIdentity {
    pub session: u32,
    pub correlation: u64,
    pub sequence: u8,
}

impl BarrierIdentity {
    pub const fn message(self) -> Msg {
        Msg::SafeBarrier {
            session: self.session,
            correlation: self.correlation,
            sequence: self.sequence,
        }
    }
}

/// A consumed matching acknowledgement, eligible at a release boundary. No
/// public constructor or Clone: identity data alone is not a publication permit.
#[derive(Debug, PartialEq, Eq)]
pub struct SafeReceipt {
    identity: BarrierIdentity,
    operation: u64,
}

impl SafeReceipt {
    pub const fn identity(&self) -> BarrierIdentity {
        self.identity
    }
    pub const fn operation(&self) -> u64 {
        self.operation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffError {
    NotEstablished,
    Busy,
    BadIdentity,
    InvalidTimeout,
    Exhausted,
    Stale,
    TimedOut,
    ClockReversed,
    InvalidRelease,
}

#[derive(Clone, Copy)]
enum Transmission {
    Pending,
    Started,
    Sent,
}

#[derive(Clone, Copy)]
struct Barrier {
    identity: BarrierIdentity,
    operation: u64,
    deadline: u64,
    last_seen: u64,
    tx: Transmission,
    acknowledged_at: Option<u64>,
}

#[derive(Clone, Copy)]
struct Offer {
    deadline: u64,
    last_seen: u64,
    tx: Transmission,
}

#[derive(Clone, Copy)]
enum Phase {
    Disarmed,
    Offering(Offer),
    Ready,
    Barrier(Barrier),
}

/// One session and one transaction. Times are in the caller's single monotonic
/// tick domain; the Pi supplies an exact 80 ms timeout from its physical clock.
pub struct Handoff {
    phase: Phase,
    last_session: u32,
    last_correlation: u64,
}

impl Default for Handoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Handoff {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Disarmed,
            last_session: 0,
            last_correlation: 0,
        }
    }

    /// Caller must first inhibit both peers, drain software/FIFOs/decoder, keep
    /// 200 ms quiet and explicitly requalify/rearm. This method does no such I/O.
    /// IDs are unique only in this object's lifetime, never claimed across boot.
    /// `now` and `timeout` use the caller's monotonic physical-counter ticks.
    pub fn offer_after_drain(&mut self, now: u64, timeout: u64) -> Result<Msg, HandoffError> {
        if !matches!(self.phase, Phase::Disarmed) {
            return Err(HandoffError::Busy);
        }
        if timeout == 0 {
            return Err(HandoffError::InvalidTimeout);
        }
        let deadline = now.checked_add(timeout).ok_or(HandoffError::Exhausted)?;
        let session = self
            .last_session
            .checked_add(1)
            .ok_or(HandoffError::Exhausted)?;
        self.last_session = session;
        self.phase = Phase::Offering(Offer {
            deadline,
            last_seen: now,
            tx: Transmission::Pending,
        });
        Ok(Msg::SessionOffer { session })
    }

    /// Stops/reset/cancellation drop all eligibility, retaining counters so
    /// another explicit drain cannot accidentally reuse an issued identity.
    pub fn disarm(&mut self) {
        self.phase = Phase::Disarmed;
    }

    pub const fn motion_permitted(&self) -> bool {
        matches!(self.phase, Phase::Ready)
    }

    pub const fn operation(&self) -> Option<u64> {
        match self.phase {
            Phase::Barrier(barrier) => Some(barrier.operation),
            _ => None,
        }
    }

    /// Enter safe mode and discard all old motion that has not started framing.
    /// A started frame retains ownership and finishes before this barrier.
    pub fn begin_on_transport(
        &mut self,
        operation: u64,
        sequence: u8,
        now: u64,
        timeout: u64,
        tx: &mut TxState,
    ) -> Result<(BarrierIdentity, MotorDiscards), HandoffError> {
        let identity = self.begin(operation, sequence, now, timeout)?;
        let mut discarded = tx.clear_motor();
        discarded.frame = tx.cancel_unsent().frame;
        Ok((identity, discarded))
    }

    /// Caller gives trusted stop frames priority before calling this. The
    /// existing TxState owns bytes; this mailbox only tracks their correlation.
    /// `transport_now` belongs to TxState's transport timestamp domain and is
    /// deliberately not compared with this handoff's physical-counter deadline.
    pub fn enqueue(
        &mut self,
        tx: &mut TxState,
        transport_now: u64,
    ) -> Result<Option<HandoffFrame>, HandoffError> {
        if let Some(message) = self.outbound() {
            let frame = HandoffFrame {
                message,
                operation: self.operation(),
            };
            if tx.start_handoff(frame, transport_now) {
                self.started(message)?;
                return Ok(Some(frame));
            }
        }
        Ok(None)
    }

    pub fn begin(
        &mut self,
        operation: u64,
        sequence: u8,
        now: u64,
        timeout: u64,
    ) -> Result<BarrierIdentity, HandoffError> {
        match self.phase {
            Phase::Disarmed | Phase::Offering(_) => return Err(HandoffError::NotEstablished),
            Phase::Barrier(_) => return Err(HandoffError::Busy),
            Phase::Ready => {}
        }
        if operation == 0 {
            return Err(HandoffError::BadIdentity);
        }
        if timeout == 0 {
            return Err(HandoffError::InvalidTimeout);
        }
        let deadline = now.checked_add(timeout).ok_or(HandoffError::Exhausted)?;
        let correlation = self
            .last_correlation
            .checked_add(1)
            .ok_or(HandoffError::Exhausted)?;
        let identity = BarrierIdentity {
            session: self.last_session,
            correlation,
            sequence,
        };
        self.last_correlation = correlation;
        self.phase = Phase::Barrier(Barrier {
            identity,
            operation,
            deadline,
            last_seen: now,
            tx: Transmission::Pending,
            acknowledged_at: None,
        });
        Ok(identity)
    }

    /// Complete message to prioritize after any already-started UART frame.
    pub fn outbound(&self) -> Option<Msg> {
        match self.phase {
            Phase::Offering(Offer {
                tx: Transmission::Pending,
                ..
            }) => Some(Msg::SessionOffer {
                session: self.last_session,
            }),
            Phase::Barrier(Barrier {
                tx: Transmission::Pending,
                identity,
                ..
            }) => Some(identity.message()),
            _ => None,
        }
    }

    /// Call only after TxState takes ownership of this exact whole frame.
    pub fn started(&mut self, message: Msg) -> Result<(), HandoffError> {
        if self.outbound() != Some(message) {
            return Err(HandoffError::Stale);
        }
        match &mut self.phase {
            Phase::Offering(offer) => offer.tx = Transmission::Started,
            Phase::Barrier(barrier) => barrier.tx = Transmission::Started,
            _ => return Err(HandoffError::Stale),
        }
        Ok(())
    }

    pub const fn has_started_frame(&self) -> bool {
        self.started_frame().is_some()
    }

    /// Eligible transaction's started message; TX owns completion independently.
    pub const fn started_frame(&self) -> Option<Msg> {
        match self.phase {
            Phase::Offering(Offer {
                tx: Transmission::Started,
                ..
            }) => Some(Msg::SessionOffer {
                session: self.last_session,
            }),
            Phase::Barrier(Barrier {
                tx: Transmission::Started,
                identity,
                ..
            }) => Some(identity.message()),
            _ => None,
        }
    }

    /// All frame bytes accepted by local UART, not remote delivery/sink safety.
    pub fn sent(&mut self, now: u64) -> Result<(), HandoffError> {
        self.check(now)?;
        match &mut self.phase {
            Phase::Offering(Offer {
                tx: tx @ Transmission::Started,
                ..
            }) => *tx = Transmission::Sent,
            Phase::Barrier(Barrier {
                tx: tx @ Transmission::Started,
                ..
            }) => *tx = Transmission::Sent,
            _ => return Err(HandoffError::Stale),
        }
        Ok(())
    }

    pub fn on_reply(&mut self, msg: Msg, received_at: u64) -> Result<bool, HandoffError> {
        self.check(received_at)?;
        match (&mut self.phase, msg) {
            (
                Phase::Offering(Offer {
                    tx: Transmission::Sent,
                    ..
                }),
                Msg::SessionReady { session },
            ) if session == self.last_session => {
                self.phase = Phase::Ready;
                Ok(true)
            }
            (
                Phase::Barrier(barrier),
                Msg::SafeAck {
                    session,
                    correlation,
                    sequence,
                },
            ) if matches!(barrier.tx, Transmission::Sent)
                && barrier.acknowledged_at.is_none()
                && barrier.identity
                    == (BarrierIdentity {
                        session,
                        correlation,
                        sequence,
                    }) =>
            {
                barrier.acknowledged_at = Some(received_at);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Called both while waiting and at commitment, so waiting for the next
    /// eligible release is included in the operational timeout.
    pub fn check(&mut self, now: u64) -> Result<(), HandoffError> {
        let bound = match &mut self.phase {
            Phase::Offering(offer) => Some((offer.deadline, &mut offer.last_seen)),
            Phase::Barrier(barrier) => Some((barrier.deadline, &mut barrier.last_seen)),
            Phase::Disarmed | Phase::Ready => None,
        };
        let Some((deadline, last_seen)) = bound else {
            return Ok(());
        };
        let error = if now < *last_seen {
            Some(HandoffError::ClockReversed)
        } else if now >= deadline {
            Some(HandoffError::TimedOut)
        } else {
            None
        };
        if let Some(error) = error {
            self.disarm();
            return Err(error);
        }
        *last_seen = now;
        Ok(())
    }

    pub fn take_ready(
        &mut self,
        scheduled: u64,
        actual: u64,
    ) -> Result<Option<SafeReceipt>, HandoffError> {
        self.check(actual)?;
        if scheduled > actual {
            self.disarm();
            return Err(HandoffError::ClockReversed);
        }
        if let Phase::Barrier(barrier) = self.phase {
            if barrier
                .acknowledged_at
                .is_some_and(|ready| ready <= scheduled)
            {
                self.phase = Phase::Ready;
                return Ok(Some(SafeReceipt {
                    identity: barrier.identity,
                    operation: barrier.operation,
                }));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> Handoff {
        let mut h = Handoff::new();
        let offer = h.offer_after_drain(0, 80).unwrap();
        assert_eq!(offer, Msg::SessionOffer { session: 1 });
        assert!(!h.on_reply(Msg::SessionReady { session: 1 }, 0).unwrap());
        h.started(offer).unwrap();
        h.sent(0).unwrap();
        assert!(h.on_reply(Msg::SessionReady { session: 1 }, 0).unwrap());
        assert!(h.motion_permitted());
        h
    }

    fn ack(key: BarrierIdentity) -> Msg {
        Msg::SafeAck {
            session: key.session,
            correlation: key.correlation,
            sequence: key.sequence,
        }
    }

    #[test]
    fn only_matching_ack_after_whole_frame_makes_next_boundary_eligible_once() {
        let mut h = ready();
        let key = h.begin(42, 9, 100, 80).unwrap();
        assert!(!h.motion_permitted());
        assert_eq!(h.begin(43, 10, 101, 80), Err(HandoffError::Busy));
        assert!(!h.on_reply(ack(key), 101).unwrap());
        let barrier = h.outbound().unwrap();
        h.started(barrier).unwrap();
        assert_eq!(h.outbound(), None);
        assert!(!h.on_reply(ack(key), 102).unwrap());
        h.sent(120).unwrap();
        for wrong in [
            Msg::SafeAck {
                session: 2,
                correlation: key.correlation,
                sequence: key.sequence,
            },
            Msg::SafeAck {
                session: 1,
                correlation: key.correlation + 1,
                sequence: key.sequence,
            },
            Msg::SafeAck {
                session: 1,
                correlation: key.correlation,
                sequence: 8,
            },
        ] {
            assert!(!h.on_reply(wrong, 121).unwrap());
        }
        assert!(h.on_reply(ack(key), 132).unwrap());
        assert!(!h.on_reply(ack(key), 133).unwrap());
        assert!(h.take_ready(130, 134).unwrap().is_none());
        let receipt = h.take_ready(140, 141).unwrap().unwrap();
        assert_eq!(receipt.operation(), 42);
        assert_eq!(receipt.identity(), key);
        assert!(h.motion_permitted());
        assert!(h.take_ready(150, 151).unwrap().is_none());
    }

    #[test]
    fn timeout_includes_wait_for_next_boundary_and_reversed_time_disarms() {
        for (ack_at, boundary, actual, expected) in [
            (179, 180, 180, HandoffError::TimedOut),
            (131, 140, 130, HandoffError::ClockReversed),
        ] {
            let mut h = ready();
            let key = h.begin(42, 9, 100, 80).unwrap();
            h.started(h.outbound().unwrap()).unwrap();
            h.sent(120).unwrap();
            assert!(h.on_reply(ack(key), ack_at).unwrap());
            assert_eq!(h.take_ready(boundary, actual).unwrap_err(), expected);
            assert!(!h.motion_permitted());
            assert!(h.outbound().is_none());
            assert!(!h.on_reply(ack(key), 181).unwrap());
        }
        let mut h = ready();
        h.begin(42, 9, 100, 80).unwrap();
        assert_eq!(h.check(180), Err(HandoffError::TimedOut));
    }

    #[test]
    fn disarm_clears_ack_mailbox_and_new_sessions_never_reuse_local_ids() {
        let mut h = ready();
        let old = h.begin(42, 9, 100, 80).unwrap();
        h.started(h.outbound().unwrap()).unwrap();
        h.sent(110).unwrap();
        h.on_reply(ack(old), 120).unwrap();
        h.disarm();
        assert!(!h.motion_permitted());
        assert!(h.take_ready(130, 130).unwrap().is_none());
        let offer = h.offer_after_drain(200, 80).unwrap();
        assert_eq!(offer, Msg::SessionOffer { session: 2 });
        assert!(!h.on_reply(Msg::SessionReady { session: 1 }, 200).unwrap());
        h.started(offer).unwrap();
        h.sent(201).unwrap();
        assert!(h.on_reply(Msg::SessionReady { session: 2 }, 202).unwrap());
        let new = h.begin(43, 9, 203, 80).unwrap();
        assert_ne!(new.correlation, old.correlation);
        h.started(h.outbound().unwrap()).unwrap();
        h.sent(204).unwrap();
        assert!(!h.on_reply(ack(old), 205).unwrap());
        assert!(h.on_reply(ack(new), 206).unwrap());
    }

    #[test]
    fn bad_ids_and_exhausted_counters_reject_before_reserving_a_barrier() {
        let mut h = ready();
        assert_eq!(h.begin(0, 9, 100, 80), Err(HandoffError::BadIdentity));
        assert_eq!(h.begin(1, 9, 100, 0), Err(HandoffError::InvalidTimeout));
        assert_eq!(h.begin(1, 9, u64::MAX, 80), Err(HandoffError::Exhausted));
        assert!(h.motion_permitted());
        h.last_correlation = u64::MAX;
        assert_eq!(h.begin(1, 9, 100, 80), Err(HandoffError::Exhausted));
        h.disarm();
        h.last_session = u32::MAX;
        assert_eq!(h.offer_after_drain(200, 80), Err(HandoffError::Exhausted));
        assert!(!h.motion_permitted());
        assert!(h.outbound().is_none());
    }

    #[test]
    fn session_offer_is_bounded_before_during_and_after_transmission() {
        let mut pending = Handoff::new();
        let pending_offer = pending.offer_after_drain(100, 80).unwrap();
        assert_eq!(pending_offer, Msg::SessionOffer { session: 1 });
        assert_eq!(pending.check(180), Err(HandoffError::TimedOut));
        assert_eq!(pending.outbound(), None);

        let mut started = Handoff::new();
        let started_offer = started.offer_after_drain(100, 80).unwrap();
        started.started(started_offer).unwrap();
        assert_eq!(started.sent(180), Err(HandoffError::TimedOut));
        assert!(!started.has_started_frame());

        let mut sent = Handoff::new();
        let sent_offer = sent.offer_after_drain(100, 80).unwrap();
        sent.started(sent_offer).unwrap();
        sent.sent(120).unwrap();
        assert!(!sent
            .on_reply(Msg::SessionReady { session: 2 }, 130)
            .unwrap());
        assert_eq!(
            sent.on_reply(Msg::SessionReady { session: 1 }, 180),
            Err(HandoffError::TimedOut)
        );
        assert!(!sent
            .on_reply(Msg::SessionReady { session: 1 }, 181)
            .unwrap());

        let new_offer = sent.offer_after_drain(200, 80).unwrap();
        assert_eq!(new_offer, Msg::SessionOffer { session: 2 });
        assert!(!sent
            .on_reply(Msg::SessionReady { session: 1 }, 201)
            .unwrap());
    }

    #[test]
    fn invalid_session_bounds_and_reversed_clock_preserve_or_disarm_state() {
        let mut h = Handoff::new();
        assert_eq!(
            h.offer_after_drain(100, 0),
            Err(HandoffError::InvalidTimeout)
        );
        assert_eq!(
            h.offer_after_drain(u64::MAX, 1),
            Err(HandoffError::Exhausted)
        );
        assert_eq!(h.last_session, 0);
        assert_eq!(h.outbound(), None);

        let offer = h.offer_after_drain(100, 80).unwrap();
        assert_eq!(offer, Msg::SessionOffer { session: 1 });
        assert_eq!(h.check(99), Err(HandoffError::ClockReversed));
        assert!(!h.on_reply(Msg::SessionReady { session: 1 }, 101).unwrap());

        h.last_session = u32::MAX;
        assert_eq!(h.offer_after_drain(200, 80), Err(HandoffError::Exhausted));
        assert_eq!(h.last_session, u32::MAX);
        assert_eq!(h.outbound(), None);
    }

    #[test]
    fn cancelled_handoff_frame_keeps_completion_identity_at_every_byte_offset() {
        use crate::tx::FrameCompletion;
        for offering in [false, true] {
            let mut base = if offering { Handoff::new() } else { ready() };
            if offering {
                base.offer_after_drain(0, 80).unwrap();
            } else {
                base.begin(42, 255, 0, 80).unwrap();
            }
            let message = base.outbound().unwrap();
            let mut bytes = [0; crate::MAX_FRAME];
            let len = crate::encode(&message, &mut bytes).unwrap();
            for offset in 0..=len {
                let mut h = if offering { Handoff::new() } else { ready() };
                if offering {
                    h.offer_after_drain(0, 80).unwrap();
                } else {
                    h.begin(42, 255, 0, 80).unwrap();
                }
                let mut tx = TxState::new();
                let frame = h.enqueue(&mut tx, 0).unwrap().unwrap();
                assert_eq!(frame.message, message);
                assert_eq!(frame.operation, (!offering).then_some(42));
                assert_eq!(h.started_frame(), Some(message));
                assert_eq!(h.enqueue(&mut tx, 0).unwrap(), None);
                let mut completed = None;
                for _ in 0..offset {
                    let (_, done) = tx.next_byte_with_completion().unwrap();
                    if done.is_some() {
                        completed = done;
                    }
                }
                h.disarm();
                assert_eq!(h.operation(), None);
                assert_eq!(h.started_frame(), None);
                tx.cancel_unsent();
                while let Some((_, done)) = tx.next_byte_with_completion() {
                    if done.is_some() {
                        assert!(completed.is_none());
                        completed = done;
                    }
                }
                assert_eq!(
                    completed,
                    (offset > 0).then_some(FrameCompletion::Handoff(frame))
                );
                assert_eq!(tx.next_byte_with_completion(), None);
            }
        }
    }

    #[test]
    fn barrier_follows_a_whole_old_frame_at_every_offset_and_discards_unsent_motion() {
        use crate::tx::{MotorOrigin, MotorRequest};
        let old = Msg::MotorSetpoint {
            seq: 8,
            left: 200,
            right: -300,
        };
        let mut encoded = [0; crate::MAX_FRAME];
        let length = crate::encode(&old, &mut encoded).unwrap();
        for split in 0..=length {
            let mut handoff = ready();
            let mut tx = TxState::new();
            let mut wire = [0; crate::MAX_FRAME * 2];
            let mut count = 0;
            let origin = MotorOrigin {
                cycle: 100,
                generation: 7,
                artifact_handle: 0,
            };
            tx.replace_motor_request(MotorRequest {
                left: 200,
                right: -300,
                queued_at: 0,
                origin: Some(origin),
            });
            let frame = tx.start_pending_motor(8).unwrap();
            for _ in 0..split {
                wire[count] = tx.next_byte().unwrap();
                count += 1;
            }
            let pending = MotorRequest {
                left: 400,
                right: -500,
                queued_at: 1,
                origin: Some(MotorOrigin {
                    cycle: 101,
                    ..origin
                }),
            };
            tx.replace_motor_request(pending);
            let mut disarmed = Handoff::new();
            assert_eq!(
                disarmed.begin_on_transport(42, 9, 100, 80, &mut tx),
                Err(HandoffError::NotEstablished)
            );
            assert_eq!(tx.pending_motor(), Some(pending));
            assert_eq!(tx.active_motor(), (split < length).then_some(frame));
            let (key, discarded) = handoff.begin_on_transport(42, 9, 100, 80, &mut tx).unwrap();
            assert_eq!(discarded.pending, Some(pending));
            assert_eq!(discarded.frame, (split == 0).then_some(frame));
            assert_eq!(tx.pending_motor(), None);
            assert!(!handoff.motion_permitted());
            for _ in 0..2 {
                handoff.enqueue(&mut tx, 100).unwrap();
                while let Some(byte) = tx.next_byte() {
                    wire[count] = byte;
                    count += 1;
                }
                if handoff.has_started_frame() {
                    handoff.sent(110).unwrap();
                }
            }
            let mut decoder = crate::Decoder::new();
            let mut messages = [None; 2];
            let mut next = 0;
            for byte in &wire[..count] {
                if let Some(message) = decoder.push(*byte) {
                    messages[next] = Some(message.unwrap());
                    next += 1;
                }
            }
            let expected = if split == 0 {
                [Some(key.message()), None]
            } else {
                [Some(old), Some(key.message())]
            };
            assert_eq!(messages, expected, "split {split}");
            assert!(handoff.on_reply(ack(key), 120).unwrap());
            assert!(handoff.take_ready(120, 120).unwrap().is_some());
            // SafeBarrier updates the same pair history, so B does not need an
            // extra reversal-zero frame after the acknowledged zero interval.
            tx.replace_motor(-200, 300, 120);
            assert_eq!(tx.take_motor(), Some((-200, 300, 120)));
        }
    }
}
