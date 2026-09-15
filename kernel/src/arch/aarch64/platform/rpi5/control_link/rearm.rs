//! Bounded, explicit Pi requalification using the existing PL011 and handoff.
//! No liveness or ordinary commands may run until the owner commits the receipt.

use shrike_link::handoff::{Handoff, HandoffError};
use shrike_link::tx::{FrameCompletion, HandoffFrame, MotorDiscards, TxState};
use shrike_link::{Decoder, Msg};

use super::super::pl011::{InitError, Pl011};

const DRAIN_NS: u64 = 1_000_000_000;
const OVERALL_SECONDS: u64 = 2;
const OFFER_MS: u64 = 80;
const BYTES_PER_PASS: usize = 64;
const MAX_PASSES: u32 = 1_048_576;

pub(super) enum Event {
    Framed(HandoffFrame),
    Completed(FrameCompletion, u64, Result<(), HandoffError>),
    Reply(Msg, u64, Result<bool, HandoffError>),
}

enum Phase {
    FinishOld,
    InitialDrain,
    Exchange,
    FinalDrain,
}

pub(super) struct Rearm {
    operation: u64,
    frequency: u64,
    last_ticks: u64,
    passes: u32,
    phase: Phase,
    decoder: Decoder,
    partial: bool,
}

impl Rearm {
    pub(super) fn begin(
        operation: u64,
        now: u64,
        frequency: u64,
        handoff: &mut Handoff,
        tx: &mut TxState,
    ) -> Result<(Self, MotorDiscards), HandoffError> {
        if operation == 0 {
            return Err(HandoffError::BadIdentity);
        }
        let timeout = frequency
            .checked_mul(OVERALL_SECONDS)
            .filter(|value| *value != 0)
            .ok_or(HandoffError::InvalidTimeout)?;
        now.checked_add(timeout).ok_or(HandoffError::Exhausted)?;
        nanos(now, frequency)?;
        // The authorized owner has already inhibited the slot. A fresh attempt
        // revokes all old eligibility, but preserves a started TX frame.
        handoff.disarm();
        let (_, discarded) = handoff.rearm_on_transport(operation, now, timeout, tx)?;
        Ok((
            Self {
                operation,
                frequency,
                last_ticks: now,
                passes: 0,
                phase: Phase::FinishOld,
                decoder: Decoder::new(),
                partial: false,
            },
            discarded,
        ))
    }

    pub(super) const fn operation(&self) -> u64 {
        self.operation
    }

    fn sample(&mut self, clock: &mut impl FnMut() -> u64) -> Result<u64, HandoffError> {
        let ticks = clock();
        if ticks < self.last_ticks {
            return Err(HandoffError::ClockReversed);
        }
        self.last_ticks = ticks;
        Ok(ticks)
    }

    fn drain(
        &mut self,
        uart: &mut Pl011,
        begin: bool,
        clock: &mut impl FnMut() -> u64,
    ) -> Result<bool, HandoffError> {
        let quantum = 1_000_000_000u64.div_ceil(self.frequency);
        let mut clock_error = None;
        let mut ns_clock = || match self.sample(clock).and_then(|t| nanos(t, self.frequency)) {
            Ok(ns) => ns,
            Err(error) => {
                clock_error = Some(error);
                u64::MAX
            }
        };
        let result = if begin {
            uart.begin_quiescence(&mut ns_clock, DRAIN_NS, quantum)
                .map(|()| false)
        } else {
            uart.poll_quiescence(&mut ns_clock).and_then(|quiet| {
                if quiet {
                    uart.finish_quiescence(&mut ns_clock)?;
                }
                Ok(quiet)
            })
        };
        if let Some(error) = clock_error {
            return Err(error);
        }
        result.map_err(|error| match error {
            InitError::ClockRegression => HandoffError::ClockReversed,
            InitError::TimedOut => HandoffError::TimedOut,
            _ => HandoffError::NotEstablished,
        })
    }

    /// One pass: at most 64 RX and 64 TX bytes, or one bounded drain step.
    /// `true` requires a real idle observation after all currently available RX
    /// bytes. The caller must still consume/commit the exact handoff receipt.
    pub(super) fn poll(
        &mut self,
        uart: &mut Pl011,
        handoff: &mut Handoff,
        tx: &mut TxState,
        clock: &mut impl FnMut() -> u64,
        record: &mut impl FnMut(Event),
    ) -> Result<bool, HandoffError> {
        if handoff.operation() != Some(self.operation) {
            return Err(HandoffError::Stale);
        }
        if self.passes == MAX_PASSES {
            return Err(HandoffError::TimedOut);
        }
        self.passes += 1;
        handoff.check(self.sample(clock)?)?;
        if matches!(self.phase, Phase::InitialDrain | Phase::FinalDrain) {
            if self.drain(uart, false, clock)? {
                if matches!(self.phase, Phase::FinalDrain) {
                    let timeout = self
                        .frequency
                        .checked_mul(OFFER_MS)
                        .ok_or(HandoffError::Exhausted)?
                        .div_ceil(1000);
                    handoff.offer_after_requalification_drain(self.sample(clock)?, timeout)?;
                }
                self.phase = Phase::Exchange;
            }
            handoff.check(self.sample(clock)?)?;
            return Ok(false);
        }

        let finishing = matches!(self.phase, Phase::FinishOld);
        let mut rx_idle = false;
        for _ in 0..BYTES_PER_PASS {
            handoff.check(self.sample(clock)?)?;
            let byte = uart.read_byte().map_err(|_| HandoffError::NotEstablished)?;
            let observed = self.sample(clock)?;
            handoff.check(observed)?;
            let Some(byte) = byte else {
                rx_idle = true;
                break;
            };
            // Initial reset-era traffic has no authority. It is discarded
            // before the fresh quiet interval and new Requalify transmission.
            if finishing {
                continue;
            }
            self.partial = true;
            if let Some(decoded) = self.decoder.push(byte) {
                let message = decoded.map_err(|_| HandoffError::NotEstablished)?;
                self.partial = false;
                if matches!(
                    message,
                    Msg::Estop { .. }
                        | Msg::Sensor {
                            estop_line: true,
                            ..
                        }
                ) {
                    return Err(HandoffError::NotEstablished);
                }
                let result = handoff.on_reply(message, observed);
                record(Event::Reply(message, observed, result));
                result?;
            }
        }
        if !finishing {
            let now_ns = nanos(self.last_ticks, self.frequency)?;
            if let Some(frame) = handoff.enqueue(tx, now_ns)? {
                record(Event::Framed(frame));
            }
        }
        for _ in 0..BYTES_PER_PASS {
            let Some(byte) = tx.peek_byte() else { break };
            handoff.check(self.sample(clock)?)?;
            let written = uart.try_write_byte(byte);
            let observed = clock();
            // Retire the accepted byte even if the I/O crossed the deadline;
            // the stop path must not duplicate it or truncate this frame.
            let completion = written.then(|| tx.next_byte_with_completion()).flatten();
            let current = matches!(completion,
                Some((_, Some(FrameCompletion::Handoff(frame))))
                if handoff.operation() == frame.operation
                    && handoff.started_frame() == Some(frame.message));
            let time_result = if observed < self.last_ticks {
                Err(HandoffError::ClockReversed)
            } else {
                self.last_ticks = observed;
                handoff.check(observed)
            };
            if let Some((_, Some(completion))) = completion {
                let result = match completion {
                    FrameCompletion::Handoff(_) if current => {
                        time_result.and_then(|()| handoff.sent(observed))
                    }
                    FrameCompletion::Handoff(_) => Err(HandoffError::Stale),
                    FrameCompletion::Motor(_) => time_result,
                };
                record(Event::Completed(completion, observed, result));
                // Stale completion of the preserved OLD frame is expected.
                if !finishing {
                    result?;
                }
            }
            time_result?;
            if !written {
                break;
            }
        }
        let wire_idle = tx.is_idle() && uart.tx_idle();
        handoff.check(self.sample(clock)?)?;
        if wire_idle && (finishing || (handoff.needs_local_drain() && rx_idle && !self.partial)) {
            self.decoder = Decoder::new();
            self.drain(uart, true, clock)?;
            self.phase = if finishing {
                Phase::InitialDrain
            } else {
                Phase::FinalDrain
            };
            handoff.check(self.sample(clock)?)?;
            return Ok(false);
        }
        Ok(!finishing && rx_idle && wire_idle && !self.partial)
    }
}

fn nanos(ticks: u64, frequency: u64) -> Result<u64, HandoffError> {
    let ns = u128::from(ticks) * 1_000_000_000 / u128::from(frequency);
    u64::try_from(ns).map_err(|_| HandoffError::Exhausted)
}
