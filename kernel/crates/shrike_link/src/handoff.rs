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

/// A consumed matching rearm, eligible for one local policy commit. No public
/// constructor or Clone: operation data alone cannot recreate eligibility.
#[derive(Debug, PartialEq, Eq)]
pub struct RearmReceipt {
    operation: u64,
    session: u32,
    received_at: u64,
}

impl RearmReceipt {
    pub const fn operation(&self) -> u64 {
        self.operation
    }

    pub const fn session(&self) -> u32 {
        self.session
    }

    pub const fn received_at(&self) -> u64 {
        self.received_at
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
    operation: Option<u64>,
    deadline: u64,
    last_seen: u64,
    tx: Transmission,
}

#[derive(Clone, Copy)]
struct PendingRearm {
    operation: u64,
    session: u32,
    received_at: u64,
    deadline: u64,
    last_seen: u64,
    issued: bool,
}

#[derive(Clone, Copy)]
enum Phase {
    Disarmed,
    Requalifying(Offer),
    Draining(Offer),
    Offering(Offer),
    PendingRearm(PendingRearm),
    Ready,
    Barrier(Barrier),
}

/// One session and one transaction. Times use one caller-supplied monotonic
/// tick domain, with separate requalification and offer/barrier deadlines.
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
        let offer = self.reserve_session(None, now, timeout)?;
        self.phase = Phase::Offering(offer);
        Ok(Msg::SessionOffer {
            session: self.last_session,
        })
    }

    fn reserve_session(
        &mut self,
        operation: Option<u64>,
        now: u64,
        timeout: u64,
    ) -> Result<Offer, HandoffError> {
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
        Ok(Offer {
            operation,
            deadline,
            last_seen: now,
            tx: Transmission::Pending,
        })
    }

    /// Start only on an explicit authorized rearm after local motion inhibition.
    /// Reserve the same session through Requalify/Prepared and Offer/Ready.
    /// The overall deadline includes peer configuration and both local drains;
    /// it is separate from the 80 ms controller handoff/offer timeout.
    pub fn requalify_on_transport(
        &mut self,
        now: u64,
        timeout: u64,
        tx: &mut TxState,
    ) -> Result<(u32, MotorDiscards), HandoffError> {
        self.requalify_with_operation(None, now, timeout, tx)
    }

    /// Start an operation-bound rearm. The operation stays local metadata; the
    /// wire messages remain correlated by the reserved session alone.
    pub fn rearm_on_transport(
        &mut self,
        operation: u64,
        now: u64,
        timeout: u64,
        tx: &mut TxState,
    ) -> Result<(u32, MotorDiscards), HandoffError> {
        if operation == 0 {
            return Err(HandoffError::BadIdentity);
        }
        self.requalify_with_operation(Some(operation), now, timeout, tx)
    }

    fn requalify_with_operation(
        &mut self,
        operation: Option<u64>,
        now: u64,
        timeout: u64,
        tx: &mut TxState,
    ) -> Result<(u32, MotorDiscards), HandoffError> {
        let request = self.reserve_session(operation, now, timeout)?;
        self.phase = Phase::Requalifying(request);
        let mut discarded = tx.clear_motor();
        discarded.frame = tx.cancel_unsent().frame;
        Ok((self.last_session, discarded))
    }

    /// A correlated Prepared permits the platform to start its fresh local
    /// drain, never to send an offer or enable motion without that drain.
    pub const fn needs_local_drain(&self) -> bool {
        matches!(self.phase, Phase::Draining(_))
    }

    /// Caller has completed the actual local UART/FIFO/decoder reset and at
    /// least 200 ms quiet after Prepared while the MCU remained silent. This
    /// method consumes that phase; elapsed time alone is not drain evidence.
    pub fn offer_after_requalification_drain(
        &mut self,
        now: u64,
        timeout: u64,
    ) -> Result<Msg, HandoffError> {
        self.check(now)?;
        let Phase::Draining(request) = self.phase else {
            return Err(HandoffError::NotEstablished);
        };
        if timeout == 0 {
            return Err(HandoffError::InvalidTimeout);
        }
        let deadline = now.checked_add(timeout).ok_or(HandoffError::Exhausted)?;
        self.phase = Phase::Offering(Offer {
            operation: request.operation,
            deadline: deadline.min(request.deadline),
            last_seen: now,
            tx: Transmission::Pending,
        });
        Ok(Msg::SessionOffer {
            session: self.last_session,
        })
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
            Phase::Requalifying(offer) | Phase::Draining(offer) | Phase::Offering(offer) => {
                offer.operation
            }
            Phase::PendingRearm(pending) => Some(pending.operation),
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
            Phase::Disarmed
            | Phase::Requalifying(_)
            | Phase::Draining(_)
            | Phase::Offering(_)
            | Phase::PendingRearm(_) => {
                return Err(HandoffError::NotEstablished);
            }
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
            Phase::Requalifying(Offer {
                tx: Transmission::Pending,
                ..
            }) => Some(Msg::Requalify {
                session: self.last_session,
            }),
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
            Phase::Requalifying(offer) | Phase::Offering(offer) => offer.tx = Transmission::Started,
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
            Phase::Requalifying(Offer {
                tx: Transmission::Started,
                ..
            }) => Some(Msg::Requalify {
                session: self.last_session,
            }),
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
            Phase::Requalifying(Offer {
                tx: tx @ Transmission::Started,
                ..
            })
            | Phase::Offering(Offer {
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
            (Phase::Requalifying(request), Msg::Prepared { session })
                if matches!(request.tx, Transmission::Sent) && session == self.last_session =>
            {
                self.phase = Phase::Draining(*request);
                Ok(true)
            }
            (
                Phase::Offering(
                    offer @ Offer {
                        tx: Transmission::Sent,
                        ..
                    },
                ),
                Msg::SessionReady { session },
            ) if session == self.last_session => {
                self.phase = match offer.operation {
                    Some(operation) => Phase::PendingRearm(PendingRearm {
                        operation,
                        session,
                        received_at,
                        deadline: offer.deadline,
                        last_seen: offer.last_seen,
                        issued: false,
                    }),
                    None => Phase::Ready,
                };
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
            Phase::Requalifying(offer) | Phase::Draining(offer) | Phase::Offering(offer) => {
                Some((offer.deadline, &mut offer.last_seen))
            }
            Phase::PendingRearm(pending) => Some((pending.deadline, &mut pending.last_seen)),
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

    /// Issue evidence for an operation-bound SessionReady exactly once. The
    /// handoff stays inhibited and deadline-bound until that receipt commits.
    pub fn take_rearm_ready(&mut self, now: u64) -> Result<Option<RearmReceipt>, HandoffError> {
        self.check(now)?;
        if let Phase::PendingRearm(pending) = &mut self.phase {
            if pending.issued {
                return Ok(None);
            }
            pending.issued = true;
            return Ok(Some(RearmReceipt {
                operation: pending.operation,
                session: pending.session,
                received_at: pending.received_at,
            }));
        }
        Ok(None)
    }

    /// Commit a still-current issued receipt after the caller's local policy
    /// checks. Stop, expiry, reversal, mismatches and replay cannot enter Ready.
    pub fn commit_rearm(&mut self, receipt: &RearmReceipt, now: u64) -> Result<(), HandoffError> {
        self.check(now)?;
        let exact = matches!(
            self.phase,
            Phase::PendingRearm(PendingRearm {
                operation,
                session,
                received_at,
                issued: true,
                ..
            }) if operation == receipt.operation
                && session == receipt.session
                && received_at == receipt.received_at
        );
        if !exact {
            return Err(HandoffError::Stale);
        }
        self.phase = Phase::Ready;
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

    fn advance_rearm_to_pending(
        handoff: &mut Handoff,
        tx: &mut TxState,
        operation: u64,
        started_at: u64,
        overall_timeout: u64,
    ) -> u32 {
        let (session, discarded) = handoff
            .rearm_on_transport(operation, started_at, overall_timeout, tx)
            .unwrap();
        assert_eq!(discarded, MotorDiscards::default());
        assert_eq!(handoff.operation(), Some(operation));

        let requalify = handoff.enqueue(tx, started_at + 1).unwrap().unwrap();
        assert_eq!(requalify.message, Msg::Requalify { session });
        assert_eq!(requalify.operation, Some(operation));
        while tx.next_byte().is_some() {}
        handoff.sent(started_at + 2).unwrap();
        assert!(handoff
            .on_reply(Msg::Prepared { session }, started_at + 3)
            .unwrap());

        let offer = handoff
            .offer_after_requalification_drain(started_at + 203, 80)
            .unwrap();
        assert_eq!(offer, Msg::SessionOffer { session });
        let offer_frame = handoff.enqueue(tx, started_at + 204).unwrap().unwrap();
        assert_eq!(offer_frame.message, offer);
        assert_eq!(offer_frame.operation, Some(operation));
        while tx.next_byte().is_some() {}
        handoff.sent(started_at + 205).unwrap();
        assert!(handoff
            .on_reply(Msg::SessionReady { session }, started_at + 206)
            .unwrap());
        session
    }

    #[test]
    fn rearm_rejects_zero_or_conflicting_operation_before_mutation() {
        let mut handoff = Handoff::new();
        let mut tx = TxState::new();
        tx.replace_motor(100, 200, 0);
        assert_eq!(
            handoff.rearm_on_transport(0, 0, 1_000, &mut tx),
            Err(HandoffError::BadIdentity)
        );
        assert_eq!(handoff.last_session, 0);
        assert_eq!(handoff.operation(), None);
        assert!(tx.pending_motor().is_some());

        assert_eq!(
            handoff.rearm_on_transport(41, 0, 1_000, &mut tx).unwrap().0,
            1
        );
        assert_eq!(handoff.operation(), Some(41));
        tx.replace_motor(300, 400, 1);
        assert_eq!(
            handoff.rearm_on_transport(42, 1, 1_000, &mut tx),
            Err(HandoffError::Busy)
        );
        assert_eq!(handoff.operation(), Some(41));
        assert!(tx.pending_motor().is_some());
    }

    #[test]
    fn rearm_receipt_requires_full_exchange_and_explicit_one_shot_consumption() {
        let mut handoff = Handoff::new();
        let mut tx = TxState::new();
        let (session, _) = handoff.rearm_on_transport(42, 100, 1_000, &mut tx).unwrap();
        assert!(!handoff.on_reply(Msg::Prepared { session }, 101).unwrap());
        assert!(handoff.take_rearm_ready(101).unwrap().is_none());

        let request = handoff.enqueue(&mut tx, 102).unwrap().unwrap();
        assert_eq!(request.operation, Some(42));
        tx.next_byte();
        assert!(!handoff.on_reply(Msg::Prepared { session }, 103).unwrap());
        while tx.next_byte().is_some() {}
        handoff.sent(104).unwrap();
        assert!(handoff.on_reply(Msg::Prepared { session }, 105).unwrap());

        let offer = handoff.offer_after_requalification_drain(305, 80).unwrap();
        assert!(!handoff
            .on_reply(Msg::SessionReady { session }, 306)
            .unwrap());
        let frame = handoff.enqueue(&mut tx, 307).unwrap().unwrap();
        assert_eq!(frame.message, offer);
        assert_eq!(frame.operation, Some(42));
        tx.next_byte();
        assert!(!handoff
            .on_reply(Msg::SessionReady { session }, 308)
            .unwrap());
        while tx.next_byte().is_some() {}
        handoff.sent(309).unwrap();
        assert!(!handoff.motion_permitted());
        assert!(handoff
            .on_reply(Msg::SessionReady { session }, 310)
            .unwrap());
        assert_eq!(handoff.operation(), Some(42));
        assert!(!handoff.motion_permitted());
        assert_eq!(
            handoff.begin(43, 1, 311, 80),
            Err(HandoffError::NotEstablished)
        );

        let receipt = handoff.take_rearm_ready(312).unwrap().unwrap();
        assert_eq!(receipt.operation(), 42);
        assert_eq!(receipt.session(), session);
        assert_eq!(receipt.received_at(), 310);
        assert!(!handoff.motion_permitted());
        assert_eq!(handoff.operation(), Some(42));
        assert!(handoff.take_rearm_ready(313).unwrap().is_none());
        assert_eq!(
            handoff.begin(43, 1, 313, 80),
            Err(HandoffError::NotEstablished)
        );
        handoff.commit_rearm(&receipt, 314).unwrap();
        assert!(handoff.motion_permitted());
        assert_eq!(handoff.operation(), None);
        assert_eq!(
            handoff.commit_rearm(&receipt, 315),
            Err(HandoffError::Stale)
        );
    }

    #[test]
    fn rearm_deadline_includes_pending_commit_delay_and_reversal() {
        for (commit_at, expected) in [
            (480, HandoffError::TimedOut),
            (470, HandoffError::ClockReversed),
        ] {
            let mut handoff = Handoff::new();
            let mut tx = TxState::new();
            // Narrow the offer deadline to 480 while retaining the overall
            // operation bound. The matching reply is not the local commit.
            let (session, _) = handoff.rearm_on_transport(42, 200, 280, &mut tx).unwrap();
            let request = handoff.enqueue(&mut tx, 201).unwrap().unwrap();
            while tx.next_byte().is_some() {}
            handoff.sent(202).unwrap();
            assert_eq!(request.message, Msg::Requalify { session });
            assert!(handoff.on_reply(Msg::Prepared { session }, 203).unwrap());
            handoff.offer_after_requalification_drain(400, 80).unwrap();
            handoff.enqueue(&mut tx, 401).unwrap().unwrap();
            while tx.next_byte().is_some() {}
            handoff.sent(402).unwrap();
            assert!(handoff
                .on_reply(Msg::SessionReady { session }, 470)
                .unwrap());
            let receipt = handoff.take_rearm_ready(471).unwrap().unwrap();
            assert!(!handoff.motion_permitted());
            assert_eq!(handoff.commit_rearm(&receipt, commit_at), Err(expected));
            assert!(!handoff.motion_permitted());
            assert_eq!(handoff.operation(), None);
        }
    }

    #[test]
    fn cancelled_rearms_revoke_receipts_across_reused_operation_ids() {
        let mut handoff = Handoff::new();
        let mut tx = TxState::new();

        let old_a = advance_rearm_to_pending(&mut handoff, &mut tx, 7, 0, 1_000);
        assert_eq!(old_a, 1);
        let stale_a = handoff.take_rearm_ready(207).unwrap().unwrap();
        handoff.disarm();
        assert_eq!(
            handoff.commit_rearm(&stale_a, 208),
            Err(HandoffError::Stale)
        );

        let old_b = advance_rearm_to_pending(&mut handoff, &mut tx, 8, 300, 1_000);
        assert_eq!(old_b, 2);
        handoff.disarm();
        assert!(handoff.take_rearm_ready(507).unwrap().is_none());

        let (new_a, _) = handoff.rearm_on_transport(7, 600, 1_000, &mut tx).unwrap();
        assert_eq!(new_a, 3);
        assert!(!handoff
            .on_reply(Msg::Prepared { session: old_a }, 601)
            .unwrap());
        let request = handoff.enqueue(&mut tx, 602).unwrap().unwrap();
        while tx.next_byte().is_some() {}
        handoff.sent(603).unwrap();
        assert!(!handoff
            .on_reply(Msg::Prepared { session: old_b }, 604)
            .unwrap());
        assert!(handoff
            .on_reply(Msg::Prepared { session: new_a }, 605)
            .unwrap());
        handoff.offer_after_requalification_drain(805, 80).unwrap();
        handoff.enqueue(&mut tx, 806).unwrap().unwrap();
        while tx.next_byte().is_some() {}
        handoff.sent(807).unwrap();
        for stale in [old_a, old_b] {
            assert!(!handoff
                .on_reply(Msg::SessionReady { session: stale }, 808)
                .unwrap());
        }
        assert!(handoff
            .on_reply(Msg::SessionReady { session: new_a }, 809)
            .unwrap());
        let receipt = handoff.take_rearm_ready(810).unwrap().unwrap();
        assert_eq!(receipt.operation(), 7);
        assert_eq!(receipt.session(), new_a);
        assert_eq!(stale_a.operation(), receipt.operation());
        assert_ne!(stale_a.session(), receipt.session());
        assert_eq!(
            handoff.commit_rearm(&stale_a, 811),
            Err(HandoffError::Stale)
        );
        assert!(!handoff.motion_permitted());
        handoff.commit_rearm(&receipt, 812).unwrap();
        assert!(handoff.motion_permitted());
        assert_eq!(
            handoff.commit_rearm(&receipt, 813),
            Err(HandoffError::Stale)
        );
        assert_eq!(request.operation, Some(7));
    }

    #[test]
    fn requalification_requires_sent_request_prepared_local_drain_and_sent_offer() {
        let mut h = Handoff::new();
        let mut tx = TxState::new();
        let (session, discarded) = h.requalify_on_transport(0, 1_000, &mut tx).unwrap();
        assert_eq!(session, 1);
        assert_eq!(discarded, MotorDiscards::default());
        assert!(!h.motion_permitted());
        assert!(!h.needs_local_drain());
        assert_eq!(
            h.offer_after_requalification_drain(0, 80),
            Err(HandoffError::NotEstablished)
        );
        assert!(!h.on_reply(Msg::Prepared { session }, 1).unwrap());
        let frame = h.enqueue(&mut tx, 1).unwrap().unwrap();
        assert_eq!(frame.message, Msg::Requalify { session });
        assert_eq!(frame.operation, None);
        tx.next_byte();
        assert!(!h.on_reply(Msg::Prepared { session }, 2).unwrap());
        while tx.next_byte().is_some() {}
        h.sent(3).unwrap();
        assert!(!h.on_reply(Msg::Prepared { session: 2 }, 200).unwrap());
        assert!(!h.on_reply(Msg::SessionReady { session }, 201).unwrap());
        assert!(h.on_reply(Msg::Prepared { session }, 202).unwrap());
        assert!(h.needs_local_drain());
        assert!(!h.motion_permitted());
        assert_eq!(h.outbound(), None);
        assert!(!h.on_reply(Msg::Prepared { session }, 203).unwrap());
        assert_eq!(h.begin(7, 1, 204, 80), Err(HandoffError::NotEstablished));
        // The platform owns the physical >=200 ms quiet interval and calls
        // this only after finishing its actual UART/software/decoder drain.
        let offer = h.offer_after_requalification_drain(404, 80).unwrap();
        assert_eq!(offer, Msg::SessionOffer { session });
        assert!(!h.needs_local_drain());
        assert!(!h.on_reply(Msg::SessionReady { session }, 405).unwrap());
        h.enqueue(&mut tx, 405).unwrap().unwrap();
        while tx.next_byte().is_some() {}
        h.sent(406).unwrap();
        assert!(h.on_reply(Msg::SessionReady { session }, 407).unwrap());
        assert!(h.motion_permitted());
    }

    #[test]
    fn requalification_deadline_spans_all_phases_and_cancellation_retains_session() {
        for phase in 0..4 {
            let mut h = Handoff::new();
            let mut tx = TxState::new();
            h.requalify_on_transport(100, 1_000, &mut tx).unwrap();
            if phase > 0 {
                h.enqueue(&mut tx, 101).unwrap().unwrap();
                while tx.next_byte().is_some() {}
                h.sent(102).unwrap();
            }
            if phase > 1 {
                assert!(h.on_reply(Msg::Prepared { session: 1 }, 300).unwrap());
            }
            if phase > 2 {
                h.offer_after_requalification_drain(1_050, 80).unwrap();
            }
            assert_eq!(h.check(1_100), Err(HandoffError::TimedOut), "phase {phase}");
            assert!(!h.motion_permitted());
            assert!(!h.needs_local_drain());
            assert!(!h.on_reply(Msg::Prepared { session: 1 }, 1_101).unwrap());
            assert!(!h.on_reply(Msg::SessionReady { session: 1 }, 1_101).unwrap());
            assert_eq!(
                h.requalify_on_transport(1_200, 1_000, &mut tx).unwrap().0,
                2
            );
            h.disarm();
            assert_eq!(
                h.offer_after_requalification_drain(1_201, 80),
                Err(HandoffError::NotEstablished)
            );
        }
    }

    #[test]
    fn requalification_preserves_started_frames_at_every_offset() {
        use crate::tx::FrameCompletion;
        let old = Msg::MotorSetpoint {
            seq: 3,
            left: 100,
            right: 200,
        };
        let mut bytes = [0; crate::MAX_FRAME];
        let len = crate::encode(&old, &mut bytes).unwrap();
        for split in 0..=len {
            let mut h = Handoff::new();
            let mut tx = TxState::new();
            assert!(tx.start(&old, 0));
            let mut wire = std::vec::Vec::new();
            for _ in 0..split {
                wire.push(tx.next_byte().unwrap());
            }
            tx.replace_motor(300, 400, 1);
            let (session, discarded) = h.requalify_on_transport(1, 1_000, &mut tx).unwrap();
            assert!(discarded.pending.is_some());
            assert_eq!(discarded.frame.is_some(), split == 0);
            while let Some(byte) = tx.next_byte() {
                wire.push(byte);
            }
            let request = h.enqueue(&mut tx, 2).unwrap().unwrap();
            let mut completed = None;
            while let Some((byte, completion)) = tx.next_byte_with_completion() {
                wire.push(byte);
                if completion.is_some() {
                    completed = completion;
                }
            }
            assert_eq!(completed, Some(FrameCompletion::Handoff(request)));
            h.sent(3).unwrap();
            let mut dec = crate::Decoder::new();
            let messages: std::vec::Vec<_> =
                wire.into_iter().filter_map(|byte| dec.push(byte)).collect();
            let mut expected = std::vec::Vec::new();
            if split != 0 {
                expected.push(Ok(old));
            }
            expected.push(Ok(Msg::Requalify { session }));
            assert_eq!(messages, expected);
        }
        let request = Msg::Requalify { session: 1 };
        let len = crate::encode(&request, &mut bytes).unwrap();
        for split in 0..=len {
            let mut h = Handoff::new();
            let mut tx = TxState::new();
            h.requalify_on_transport(0, 1_000, &mut tx).unwrap();
            let frame = h.enqueue(&mut tx, 0).unwrap().unwrap();
            let mut completion = None;
            for _ in 0..split {
                let (_, done) = tx.next_byte_with_completion().unwrap();
                completion = done.or(completion);
            }
            h.disarm();
            tx.cancel_unsent();
            while let Some((_, done)) = tx.next_byte_with_completion() {
                completion = done.or(completion);
            }
            assert_eq!(
                completion,
                (split != 0).then_some(FrameCompletion::Handoff(frame))
            );
            assert!(!h.on_reply(Msg::Prepared { session: 1 }, 1).unwrap());
        }
    }

    #[test]
    fn invalid_requalification_keeps_transport_and_clock_failure_disarms() {
        let mut h = Handoff::new();
        let mut tx = TxState::new();
        tx.replace_motor(100, 200, 0);
        for (now, timeout, error) in [
            (0, 0, HandoffError::InvalidTimeout),
            (u64::MAX, 1, HandoffError::Exhausted),
        ] {
            assert_eq!(h.requalify_on_transport(now, timeout, &mut tx), Err(error));
            assert!(tx.pending_motor().is_some());
            assert_eq!(h.last_session, 0);
        }
        h.last_session = u32::MAX;
        assert_eq!(
            h.requalify_on_transport(0, 1_000, &mut tx),
            Err(HandoffError::Exhausted)
        );
        assert!(tx.pending_motor().is_some());
        let mut h = Handoff::new();
        h.requalify_on_transport(100, 1_000, &mut tx).unwrap();
        assert_eq!(
            h.requalify_on_transport(101, 1_000, &mut tx),
            Err(HandoffError::Busy)
        );
        assert_eq!(h.check(99), Err(HandoffError::ClockReversed));
        assert_eq!(h.outbound(), None);
        assert_eq!(h.last_session, 1);
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
