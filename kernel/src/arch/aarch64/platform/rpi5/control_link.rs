//! Pi5 <-> Shrike-lite control link transport (v0.4 M2–M4).
//!
//! The poller owns UART RX/TX framing. The managed timer only submits a bounded
//! complete pair under the same IRQ-masked link lock. Managed RX publishes one
//! trusted sample; legacy IIO observers and synchronous markers are separate.
//!
//! Layers:
//! - M2 dumb byte transport: `Pl011` + TX/RX rings + `shrike_link::Decoder`.
//! - M3 liveness/heartbeat/fail-safe via `shrike_link::session::LinkSession`.
//! - M4 actuation: ARM-A -> `MotorSetpoint` TX (link replaces local PWM for
//!   mapped channels; fail-closed); inbound `Sensor` -> IIO hook + hardware
//!   e-stop. `service()` decodes under the lock and returns a `PollOutcome`; the
//!   side-effects run AFTER the lock is released (no CONTROL_LINK<->BPF_MANAGER
//!   / APPLY_LOCK nesting).
//!
//! Dormant until `spawn()` (HW bring-up) brings up RP1_UART0 and starts the
//! poller. RP1 UART IRQ-driven RX is deferred (#65); the poller polls the FIFO.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

use conquer_once::spin::OnceCell;
#[cfg(feature = "managed-runtime")]
use kernel_abi::MANAGED_AUDIT_DISCARD_INHIBITED;
use kernel_abi::{
    MANAGED_AUDIT_DISCARD_EXPIRED, MANAGED_AUDIT_DISCARD_SAFE_PAIR, MANAGED_AUDIT_DISCARD_STOP,
    MANAGED_AUDIT_DISCARD_SUPERSEDED,
};
#[cfg(feature = "managed-runtime")]
use kernel_abi::{MANAGED_AUDIT_HANDOFF_FRAMED, MANAGED_AUDIT_HANDOFF_LOCAL_COMPLETE};
#[cfg(feature = "managed-runtime")]
use shrike_link::handoff::{Handoff, HandoffError, RearmReceipt};
#[cfg(feature = "managed-runtime")]
mod rearm;
use shrike_link::motor::MotorSide;
use shrike_link::ring::RingBuf;
use shrike_link::session::{LinkAction, LinkSession};
use shrike_link::tx::{MotorOrigin, MotorRequest, TxState};
use shrike_link::{Decoder, Msg};
use spin::Mutex;

use super::memory_map::RP1_UART0_BASE;
use super::pl011::{InitError, Pl011, DEFAULT_UART_CLK_HZ};
#[cfg(feature = "managed-runtime")]
use crate::bpf::recorder::events;
use crate::bpf::recorder::events::motor_discard;

/// RX ring capacity.
const RING_BYTES: usize = 256;
/// Link baud — MUST match the RP2040 firmware (`shrike_rp2040` UART_BAUD).
const LINK_BAUD: u32 = 115_200;
/// Per-service work caps (bound the work done per poller pass).
const RX_PER_POLL: usize = 64;
const TX_PER_POLL: usize = 64;
/// Inbound-silence timeout. Keep this below the RP2040 firmware LINK_TIMEOUT
/// (100 ms) so one-way Shrike->Pi silence stops Pi heartbeats before the MCU
/// watchdog deadline. (ns)
pub(crate) const LINK_TIMEOUT_NS: u64 = 80_000_000; // 80 ms
/// Local UART reset/quiet attempt bound, separate from the 80 ms handoff.
#[cfg(feature = "managed-runtime")]
const LOCAL_DRAIN_TIMEOUT_NS: u64 = 1_000_000_000;
/// Heartbeat period while the link is alive. (ns)
const HEARTBEAT_PERIOD_NS: u64 = 20_000_000; // 20 ms (50 Hz)

/// Actuation channel -> wheel map (kernel config, not loadable). Matches
/// `apply_pwm_value`'s 1..=2 channel range; chip 0.
const MOTOR_LEFT_CHANNEL: u8 = 1;
const MOTOR_RIGHT_CHANNEL: u8 = 2;
const MOTOR_CHIP: u8 = 0;

/// Synthetic IIO identifiers for the ultrasonic Sensor frame.
const ULTRASONIC_DEVICE_ID: u32 = 0x5072_0000; // "pr" + 0 (proximity dev)
const ULTRASONIC_CHANNEL: u32 = 0; // proximity / range

static CONTROL_LINK: OnceCell<Result<Mutex<ControlLink>, InitError>> = OnceCell::uninit();
static NEXT_SENSOR_SAMPLE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_LINK_LOSS_EVENT_ID: AtomicU64 = AtomicU64::new(1);
#[cfg(feature = "trace-control-link")]
static NEXT_CHUNK_ID: AtomicU64 = AtomicU64::new(1);
static LINK_UNINITIALIZED_REPORTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Map an actuation `(chip, channel)` to the wheel it drives, if it is a
/// link-owned motor. Unmapped channels keep local RP1 PWM.
#[must_use]
pub fn motor_side(chip: u8, channel: u8) -> Option<MotorSide> {
    // The unloaded PWM diagnostic reserves exactly this channel for local RP1
    // output. Ordinary builds retain signed-pair-only motor ownership.
    #[cfg(feature = "bench-pwm")]
    if crate::bench::is_bench_pwm_output(chip, channel) {
        return None;
    }
    if chip != MOTOR_CHIP {
        return None;
    }
    match channel {
        MOTOR_LEFT_CHANNEL => Some(MotorSide::Left),
        MOTOR_RIGHT_CHANNEL => Some(MotorSide::Right),
        _ => None,
    }
}

/// One architectural counter sample and its configured frequency.
fn counter_sample() -> (u64, u64) {
    let (cnt, frq): (u64, u64);
    // SAFETY: reading the virtual counter + its frequency is allowed in EL1.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) cnt);
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frq);
    }
    (cnt, frq)
}

/// Monotonic nanoseconds from the ARM generic timer (CNTVCT/CNTFRQ).
fn now_ns() -> u64 {
    let (cnt, frq) = counter_sample();
    if frq == 0 {
        return 0;
    }
    let secs = cnt / frq;
    let rem = cnt % frq;
    secs * 1_000_000_000 + (rem * 1_000_000_000) / frq
}

/// What a decode pass produced that must be acted on OUTSIDE the lock.
#[derive(Clone, Copy)]
struct PollOutcome {
    /// Hardware e-stop line asserted in an inbound Sensor frame.
    estop: bool,
    /// Latest ultrasonic echo time (µs), if a Sensor frame arrived.
    sensors: [Option<(u64, u16)>; RX_PER_POLL],
    sensor_count: usize,
    heartbeats: [Option<u16>; RX_PER_POLL],
    heartbeat_count: usize,
    overflow_count: usize,
    link_loss: bool,
}

impl Default for PollOutcome {
    fn default() -> Self {
        Self {
            estop: false,
            sensors: [None; RX_PER_POLL],
            sensor_count: 0,
            heartbeats: [None; RX_PER_POLL],
            heartbeat_count: 0,
            overflow_count: 0,
            link_loss: false,
        }
    }
}

#[derive(Clone, Copy)]
enum PendingEstop {
    Assert,
    Release,
    AssertThenRelease,
}

pub struct ControlLink {
    uart: Pl011,
    rx: RingBuf<RING_BYTES>,
    tx: TxState,
    dec: Decoder,
    rx_overflows: u32,
    session: LinkSession,
    motor_seq: u8,
    pending_estop: Option<PendingEstop>,
    link_loss_reported: bool,
    #[cfg(feature = "managed-runtime")]
    handoff: Handoff,
    #[cfg(feature = "managed-runtime")]
    local_quiescence: bool,
    #[cfg(feature = "managed-runtime")]
    rearm: Option<rearm::Rearm>,
    #[cfg(feature = "managed-runtime")]
    rearm_failure: Option<(u64, HandoffError)>,
}

impl ControlLink {
    #[cfg(feature = "managed-runtime")]
    fn poll_rearm(&mut self) -> Result<bool, HandoffError> {
        let pending = self.rearm.as_mut().ok_or(HandoffError::Stale)?;
        let operation = pending.operation();
        let result = pending.poll(
            &mut self.uart,
            &mut self.handoff,
            &mut self.tx,
            &mut crate::arch::aarch64::interrupts::physical_counter,
            &mut |event| match event {
                rearm::Event::Framed(frame) => events::handoff(
                    MANAGED_AUDIT_HANDOFF_FRAMED,
                    frame.operation,
                    frame.message,
                    None,
                    None,
                    None,
                ),
                rearm::Event::Completed(completion, observed, result) => match completion {
                    shrike_link::tx::FrameCompletion::Motor(frame) => events::motor_tx(frame, true),
                    shrike_link::tx::FrameCompletion::Handoff(frame) => events::handoff(
                        MANAGED_AUDIT_HANDOFF_LOCAL_COMPLETE,
                        frame.operation,
                        frame.message,
                        Some(observed),
                        None,
                        result.err(),
                    ),
                },
                rearm::Event::Reply(message, observed, result) => {
                    events::handoff_reply(Some(operation), message, observed, result);
                }
            },
        );
        if let Err(error) = result {
            self.handoff_failed(Some(operation), error);
            self.rearm_failure = Some((operation, error));
        }
        result
    }

    /// Drain UART -> decode -> liveness/heartbeat/fail-safe -> TX. Returns the
    /// inbound side-effects to run after the lock is dropped. No BPF/estop here.
    fn poll_decode(&mut self, now: u64) -> PollOutcome {
        let mut out = PollOutcome::default();
        #[cfg(feature = "managed-runtime")]
        if self.rearm.is_some() {
            if self.poll_rearm().is_err() {
                out.estop = true;
            }
            return out;
        }
        #[cfg(feature = "managed-runtime")]
        if self.local_quiescence {
            // Reset-era bytes never reach either decoder or liveness tracker.
            // Even successful local quiet stays silent until explicit peer/
            // FPGA requalification and operator rearm complete in the owner.
            if let Err(error) = self.uart.poll_quiescence(&mut now_ns) {
                self.link_failed(None, events::LinkFault::Quiescence(error.audit_code()));
                out.estop = true;
            }
            return out;
        }
        let overflow_before = self.rx_overflows;

        // RX: bounded pull from the UART FIFO into the ring, then decode.
        let mut got = 0;
        while got < RX_PER_POLL {
            match self.uart.read_byte() {
                Ok(Some(b)) => {
                    if !self.rx.push(b) {
                        self.rx_overflows = self.rx_overflows.wrapping_add(1);
                    }
                    got += 1;
                }
                Ok(None) => break,
                Err(_error) => {
                    // A lost/corrupt byte breaks framing and link eligibility.
                    // Discard even earlier bytes from this pull before decode;
                    // no buffered reply may authorize a handoff after the fault.
                    self.rx = RingBuf::new();
                    self.dec = Decoder::new();
                    out.link_loss = true;
                    out.estop = true;
                    #[cfg(feature = "managed-runtime")]
                    self.link_failed(
                        self.handoff.operation(),
                        events::LinkFault::Receive(_error.0),
                    );
                    #[cfg(not(feature = "managed-runtime"))]
                    self.queue_estop(true);
                    break;
                }
            }
        }
        out.overflow_count = self.rx_overflows.wrapping_sub(overflow_before) as usize;
        #[cfg(feature = "managed-runtime")]
        if out.overflow_count != 0 {
            // A dropped byte invalidates the entire buffered framing context.
            // Do not decode a previously buffered acknowledgement first.
            self.rx = RingBuf::new();
            self.dec = Decoder::new();
            self.link_failed(
                self.handoff.operation(),
                events::LinkFault::Overflow(out.overflow_count as u32),
            );
        }
        while let Some(b) = self.rx.pop() {
            let decoded = self.dec.push(b);
            #[cfg(feature = "managed-runtime")]
            if let Some(Err(error)) = decoded {
                self.link_failed(self.handoff.operation(), events::LinkFault::Decode(error));
                out.estop = true;
            }
            if let Some(Ok(msg)) = decoded {
                #[cfg(feature = "managed-runtime")]
                {
                    let operation = self.handoff.operation();
                    let observed = crate::arch::aarch64::interrupts::physical_counter();
                    let result = self.handoff.on_reply(msg, observed);
                    events::handoff_reply(operation, msg, observed, result);
                    if let Err(error) = result {
                        self.handoff_failed(operation, error);
                        out.estop = true;
                    }
                }
                self.session.on_inbound(now);
                self.link_loss_reported = false;
                if let Msg::Sensor {
                    ultrasonic_echo_us,
                    estop_line,
                    flags: _flags,
                } = msg
                {
                    #[cfg(feature = "managed-runtime")]
                    {
                        let sample = crate::bpf::control::SensorSnapshot::received(
                            crate::arch::aarch64::interrupts::physical_counter(),
                            ultrasonic_echo_us,
                            _flags,
                            estop_line,
                        );
                        crate::bpf::control::publish_sensor(sample);
                    }
                    if out.sensor_count == RX_PER_POLL {
                        out.overflow_count += 1;
                    } else {
                        out.sensors[out.sensor_count] = Some((
                            NEXT_SENSOR_SAMPLE_ID.fetch_add(1, Ordering::Relaxed),
                            ultrasonic_echo_us,
                        ));
                        out.sensor_count += 1;
                    }
                    out.estop |= estop_line;
                    #[cfg(feature = "managed-runtime")]
                    if estop_line {
                        self.link_failed(self.handoff.operation(), events::LinkFault::PeerEstop);
                    }
                }
                if let Msg::HeartbeatToPi { seq } = msg {
                    if out.heartbeat_count == RX_PER_POLL {
                        out.overflow_count += 1;
                    } else {
                        out.heartbeats[out.heartbeat_count] = Some(seq);
                        out.heartbeat_count += 1;
                    }
                }
            }
        }

        // Decide timeout before publishing pending motion. An assert cancels an
        // unsent frame; a partially transmitted frame finishes before stop.
        let action = self.session.tick(now);
        let heartbeat = match action {
            LinkAction::Heartbeat(seq) => Some(seq),
            LinkAction::SafeStop => {
                if !self.link_loss_reported {
                    out.link_loss = true;
                    self.link_loss_reported = true;
                }
                #[cfg(feature = "managed-runtime")]
                self.link_failed(self.handoff.operation(), events::LinkFault::InboundTimeout);
                #[cfg(not(feature = "managed-runtime"))]
                self.queue_estop(true);
                None
            }
            LinkAction::Idle => None,
        };
        #[cfg(feature = "managed-runtime")]
        {
            let operation = self.handoff.operation();
            if let Err(error) = self
                .handoff
                .check(crate::arch::aarch64::interrupts::physical_counter())
            {
                self.handoff_failed(operation, error);
                out.estop = true;
            }
        }
        #[cfg(feature = "managed-runtime")]
        if out.estop || out.link_loss || out.overflow_count != 0 {
            crate::bpf::control::invalidate_sensor();
            crate::bpf::installation::request_stop();
            self.queue_estop(true);
        }
        // This sender-side age bound is independent of the MCU receive
        // watchdog. A partial frame (and bytes already in the UART FIFO) cannot
        // be retracted, but obsolete work that has sent no byte is discarded.
        let discarded = self.tx.discard_expired_motor(now, LINK_TIMEOUT_NS);
        motor_discard(discarded, MANAGED_AUDIT_DISCARD_EXPIRED);
        self.cancel_unsent_for_stop();
        let estop_queue_empty = self.flush_pending_estop(now);
        if matches!(action, LinkAction::SafeStop) && !self.has_pending_estop_assert() {
            self.session.estop_sent();
        }
        #[cfg(feature = "managed-runtime")]
        if estop_queue_empty {
            match self.handoff.enqueue(&mut self.tx, now) {
                Ok(Some(frame)) => events::handoff(
                    MANAGED_AUDIT_HANDOFF_FRAMED,
                    frame.operation,
                    frame.message,
                    None,
                    None,
                    None,
                ),
                Ok(None) => {}
                Err(error) => {
                    self.handoff_failed(self.handoff.operation(), error);
                    out.estop = true;
                }
            }
        }
        if estop_queue_empty && self.tx.is_idle() {
            self.flush_pending_motor(now);
        }
        if estop_queue_empty && self.tx.is_idle() {
            if let Some(seq) = heartbeat {
                let _ = self.enqueue(&Msg::HeartbeatToShrike { seq }, now);
            }
        }

        // TX: bounded nonblocking attempts; preserve the same byte on pressure.
        let mut sent = 0;
        while sent < TX_PER_POLL {
            let Some(byte) = self.tx.peek_byte() else {
                break;
            };
            if !self.uart.try_write_byte(byte) {
                break;
            }
            let accepted = self.tx.next_byte_with_completion();
            #[cfg(feature = "managed-runtime")]
            if let Some((_, Some(completion))) = accepted {
                match completion {
                    shrike_link::tx::FrameCompletion::Motor(frame) => events::motor_tx(frame, true),
                    shrike_link::tx::FrameCompletion::Handoff(frame) => {
                        let observed = crate::arch::aarch64::interrupts::physical_counter();
                        let current = self.handoff.operation() == frame.operation
                            && self.handoff.started_frame() == Some(frame.message);
                        let result = if current {
                            self.handoff.sent(observed)
                        } else {
                            Err(HandoffError::Stale)
                        };
                        events::handoff(
                            MANAGED_AUDIT_HANDOFF_LOCAL_COMPLETE,
                            frame.operation,
                            frame.message,
                            Some(observed),
                            None,
                            result.err(),
                        );
                        if current {
                            if let Err(error) = result {
                                self.handoff_failed(frame.operation, error);
                                out.estop = true;
                            }
                        }
                    }
                }
            }
            #[cfg(not(feature = "managed-runtime"))]
            let _ = accepted;
            sent += 1;
        }
        out
    }

    /// Enqueue a whole frame, or nothing (never a partial/torn frame). Returns
    /// false if it doesn't fit.
    fn enqueue(&mut self, msg: &Msg, now: u64) -> bool {
        self.tx.start(msg, now)
    }

    #[cfg(feature = "managed-runtime")]
    fn handoff_failed(&mut self, operation: Option<u64>, error: HandoffError) {
        self.link_failed(operation, events::LinkFault::Handoff(error));
    }

    #[cfg(feature = "managed-runtime")]
    fn link_failed(&mut self, operation: Option<u64>, fault: events::LinkFault) {
        events::link_fault(operation, fault);
        crate::bpf::control::invalidate_sensor();
        let error = match fault {
            events::LinkFault::Handoff(error) => error,
            _ => HandoffError::NotEstablished,
        };
        if let Some(id) = operation {
            crate::bpf::installation::request_handoff_failure(id, error);
        } else {
            crate::bpf::installation::request_stop();
        }
        self.queue_estop(true);
    }

    fn request_estop(&mut self, assert: bool, now: u64) -> bool {
        self.queue_estop(assert);
        self.cancel_unsent_for_stop();
        self.flush_pending_estop(now)
    }

    fn queue_estop(&mut self, assert: bool) {
        if assert {
            #[cfg(feature = "managed-runtime")]
            if let Some(rearm) = self.rearm.take() {
                self.rearm_failure = Some((rearm.operation(), HandoffError::NotEstablished));
                self.local_quiescence = false;
            }
            let discarded = self.tx.clear_motor();
            motor_discard(discarded, MANAGED_AUDIT_DISCARD_STOP);
            #[cfg(feature = "managed-runtime")]
            self.handoff.disarm();
        }
        self.pending_estop = match (self.pending_estop, assert) {
            (None, true) | (Some(PendingEstop::Release), true) => Some(PendingEstop::Assert),
            (None, false) | (Some(PendingEstop::Release), false) => Some(PendingEstop::Release),
            (Some(PendingEstop::Assert), true) | (Some(PendingEstop::AssertThenRelease), true) => {
                Some(PendingEstop::Assert)
            }
            (Some(PendingEstop::Assert), false)
            | (Some(PendingEstop::AssertThenRelease), false) => {
                Some(PendingEstop::AssertThenRelease)
            }
        };
    }

    fn cancel_unsent_for_stop(&mut self) {
        if self.has_pending_estop_assert() {
            let discarded = self.tx.cancel_unsent();
            motor_discard(discarded, MANAGED_AUDIT_DISCARD_STOP);
        }
    }

    fn flush_pending_estop(&mut self, now: u64) -> bool {
        if let Some(pending) = self.pending_estop {
            let assert = match pending {
                PendingEstop::Assert | PendingEstop::AssertThenRelease => true,
                PendingEstop::Release => false,
            };
            if !self.enqueue(&Msg::Estop { assert }, now) {
                return false;
            }
            self.pending_estop = match pending {
                PendingEstop::Assert | PendingEstop::Release => None,
                PendingEstop::AssertThenRelease => Some(PendingEstop::Release),
            };
        }
        true
    }

    fn has_pending_estop_assert(&self) -> bool {
        matches!(
            self.pending_estop,
            Some(PendingEstop::Assert | PendingEstop::AssertThenRelease)
        )
    }

    fn set_motor_pair(
        &mut self,
        left: i16,
        right: i16,
        now: u64,
        origin: Option<MotorOrigin>,
    ) -> bool {
        #[cfg(feature = "managed-runtime")]
        if !self.handoff.motion_permitted() {
            return false;
        }
        if self.has_pending_estop_assert() && (left != 0 || right != 0) {
            return false;
        }
        let discarded = self.tx.replace_motor_request(MotorRequest {
            left,
            right,
            queued_at: now,
            origin,
        });
        motor_discard(discarded, MANAGED_AUDIT_DISCARD_SUPERSEDED);
        true
    }

    fn set_safe_motor_pair(&mut self, now: u64, origin: Option<MotorOrigin>) -> bool {
        #[cfg(feature = "managed-runtime")]
        if !self.handoff.motion_permitted() {
            return false;
        }
        let discarded = self.tx.prioritize_motor_request(MotorRequest {
            left: 0,
            right: 0,
            queued_at: now,
            origin,
        });
        motor_discard(discarded, MANAGED_AUDIT_DISCARD_SAFE_PAIR);
        true
    }

    fn flush_pending_motor(&mut self, _now: u64) -> bool {
        #[cfg(feature = "managed-runtime")]
        if !self.handoff.motion_permitted() {
            let discarded = self.tx.clear_motor();
            motor_discard(discarded, MANAGED_AUDIT_DISCARD_INHIBITED);
            return true;
        }
        if self.tx.pending_motor().is_none() {
            return true;
        }
        let seq = self.motor_seq.wrapping_add(1);
        let Some(frame) = self.tx.start_pending_motor(seq) else {
            return false;
        };
        self.motor_seq = seq;
        #[cfg(feature = "managed-runtime")]
        crate::bpf::recorder::events::motor_tx(frame, false);
        #[cfg(not(feature = "managed-runtime"))]
        let _ = frame;
        true
    }
}

/// Run `f` with the `CONTROL_LINK` lock held and IRQs masked. Belt-and-suspenders:
/// the poller is a thread today, but masking keeps this correct if RP1 UART IRQ
/// RX is added later.
fn with_link<R>(f: impl FnOnce(&mut ControlLink) -> R) -> Option<R> {
    use crate::arch::aarch64::Aarch64;
    use crate::arch::traits::Architecture;

    let link = CONTROL_LINK.get()?.as_ref().ok()?;
    let were_enabled = Aarch64::are_interrupts_enabled();
    if were_enabled {
        Aarch64::disable_interrupts();
    }
    let r = f(&mut link.lock());
    if were_enabled {
        Aarch64::enable_interrupts();
    }
    Some(r)
}

/// One transport pass: decode under the lock, then run inbound side-effects
/// (IIO dispatch + hardware e-stop) in thread context with the lock released.
pub fn service() {
    let now = now_ns();
    let Some(out) = with_link(|l| l.poll_decode(now)) else {
        #[cfg(feature = "managed-runtime")]
        {
            events::link_fault(None, events::LinkFault::Unavailable);
            crate::bpf::control::invalidate_sensor();
            crate::bpf::installation::request_stop();
            crate::actuation::trigger_estop(kernel_bpf::actuation::AuditSource::ManagedControl);
        }
        #[cfg(not(feature = "managed-runtime"))]
        if !LINK_UNINITIALIZED_REPORTED.swap(true, Ordering::AcqRel) {
            #[cfg(feature = "trace-control-link")]
            let chunk_id = NEXT_CHUNK_ID.fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "trace-control-link")]
            crate::serial_println!("V04_CHUNK chunk_id={} stage=start ts_ns={}", chunk_id, now);
            crate::serial_println!(
                "V04_FAILURE reason=link_uninitialized count=1 ts_ns={}",
                now
            );
            #[cfg(feature = "trace-control-link")]
            crate::serial_println!(
                "V04_CHUNK chunk_id={} stage=end ts_ns={}",
                chunk_id,
                now_ns()
            );
        }
        return;
    };

    #[cfg(feature = "managed-runtime")]
    if out.estop || out.link_loss || out.overflow_count != 0 {
        crate::actuation::trigger_estop(kernel_bpf::actuation::AuditSource::ManagedControl);
    }

    #[cfg(not(feature = "managed-runtime"))]
    {
        // Empty polls are work, not events. Trace them only when measuring link
        // cadence; their sustained text output can exceed the deferred UART drain.
        #[cfg(feature = "trace-control-link")]
        let chunk_id = NEXT_CHUNK_ID.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "trace-control-link")]
        crate::serial_println!("V04_CHUNK chunk_id={} stage=start ts_ns={}", chunk_id, now);
        // Side-effects OUTSIDE the CONTROL_LINK lock (thread context).
        if out.overflow_count != 0 {
            crate::serial_println!(
                "V04_FAILURE reason=input_overflow count={} ts_ns={}",
                out.overflow_count,
                now
            );
        }
        if out.estop {
            crate::actuation::watchdog_estop_trigger();
        }
        for seq in out.heartbeats[..out.heartbeat_count].iter().flatten() {
            crate::serial_println!("V04_HEARTBEAT seq={} ts_ns={}", seq, now_ns());
        }
        if out.link_loss {
            let timestamp = now_ns();
            crate::serial_println!(
                "V04_LINK_LOSS event_id={} reason=timeout ts_ns={}",
                NEXT_LINK_LOSS_EVENT_ID.fetch_add(1, Ordering::Relaxed),
                timestamp
            );
            crate::serial_println!(
                "V04_ESTOP event_id={} source=link stage=assert ts_ns={}",
                crate::actuation::next_v04_estop_event_id(),
                timestamp
            );
        }
        for (sample_id, echo) in out.sensors[..out.sensor_count].iter().flatten() {
            let timestamp = now_ns();
            crate::serial_println!(
                "V04_ECHO_DONE sample_id={} echo_us={} ts_ns={}",
                sample_id,
                echo,
                timestamp
            );
            dispatch_ultrasonic(timestamp, *echo, *sample_id);
        }
        #[cfg(feature = "trace-control-link")]
        crate::serial_println!(
            "V04_CHUNK chunk_id={} stage=end ts_ns={}",
            chunk_id,
            now_ns()
        );
    }
}

/// Inject an ultrasonic reading as a synthetic IIO event so `ATTACH_TYPE_IIO`
/// BPF behaviors see it (bypasses the stub `IioAttach::attach`).
#[cfg(not(feature = "managed-runtime"))]
fn dispatch_ultrasonic(now: u64, echo_us: u16, sample_id: u64) {
    use kernel_bpf::attach::IioEvent;
    if let Some(mgr) = crate::driver::iio::IIO_MANAGER.get() {
        let event = IioEvent {
            timestamp: now,
            device_id: ULTRASONIC_DEVICE_ID,
            channel: ULTRASONIC_CHANNEL,
            value: echo_us as i32,
            scale: 1_000_000, // 1.0 (raw µs); behavior converts to range
            offset: 0,
            reserved: 0,
        };
        if !mgr.lock().dispatch_v04_event(event, sample_id) {
            crate::serial_println!("V04_FAILURE reason=context_reentry count=1 ts_ns={}", now);
        }
    }
}

/// Bring up the dedicated link UART. Called by `spawn()` at HW bring-up — NOT in
/// early boot. Retain either success or failure; no automatic retry/rearm.
fn init() -> Result<(), InitError> {
    CONTROL_LINK
        .get_or_init(|| {
            LINK_UNINITIALIZED_REPORTED.store(false, Ordering::Release);
            // SAFETY: RP1_UART0 is a mapped RP1 peripheral on the Pi5; single owner.
            let mut uart = unsafe { Pl011::new(RP1_UART0_BASE) };
            uart.init(LINK_BAUD, DEFAULT_UART_CLK_HZ)?;
            #[allow(unused_mut)]
            let mut link = ControlLink {
                uart,
                rx: RingBuf::new(),
                tx: TxState::new(),
                dec: Decoder::new(),
                rx_overflows: 0,
                session: LinkSession::new(LINK_TIMEOUT_NS, HEARTBEAT_PERIOD_NS),
                motor_seq: 0,
                pending_estop: None,
                link_loss_reported: false,
                #[cfg(feature = "managed-runtime")]
                handoff: Handoff::new(),
                #[cfg(feature = "managed-runtime")]
                local_quiescence: true,
                #[cfg(feature = "managed-runtime")]
                rearm: None,
                #[cfg(feature = "managed-runtime")]
                rearm_failure: None,
            };
            #[cfg(feature = "managed-runtime")]
            let quantum_ns = match counter_sample().1 {
                0 => 0,
                frequency => 1_000_000_000u64.div_ceil(frequency),
            };
            #[cfg(feature = "managed-runtime")]
            if let Err(error) =
                link.uart
                    .begin_quiescence(&mut now_ns, LOCAL_DRAIN_TIMEOUT_NS, quantum_ns)
            {
                // Retain the failed driver for bounded status/explicit recovery;
                // do not reinterpret a failed reset as an uninitialized UART.
                events::link_fault(None, events::LinkFault::Quiescence(error.audit_code()));
            }
            Ok(Mutex::new(link))
        })
        .as_ref()
        .map(|_| ())
        .map_err(|error| *error)
}

/// Poller task entry: bring up the link, then service it forever. `wfi` sleeps
/// until the next interrupt (the timer tick), giving ~per-tick service cadence
/// at low CPU.
extern "C" fn poller_entry(_arg: *mut core::ffi::c_void) {
    #[cfg(feature = "managed-runtime")]
    crate::actuation::trigger_estop(kernel_bpf::actuation::AuditSource::ManagedControl);
    if let Err(error) = init() {
        #[cfg(feature = "managed-runtime")]
        crate::bpf::control::invalidate_sensor();
        #[cfg(feature = "managed-runtime")]
        crate::actuation::trigger_estop(kernel_bpf::actuation::AuditSource::ManagedControl);
        #[cfg(not(feature = "managed-runtime"))]
        crate::actuation::trigger_estop(kernel_bpf::actuation::AuditSource::Watchdog);
        #[cfg(not(feature = "managed-runtime"))]
        log::error!("control_link: UART initialization failed: {:?}", error);
        #[cfg(feature = "managed-runtime")]
        let _ = error;
    }
    loop {
        service();
        // SAFETY: wait-for-interrupt; the periodic timer wakes us.
        unsafe { core::arch::asm!("wfi") };
    }
}

/// Spawn the control-link poller as a kernel task. Call once at boot (rpi5).
pub fn spawn() {
    use crate::mcore::mtask::process::Process;
    use crate::mcore::mtask::scheduler::run_queue::RunQueues;
    use crate::mcore::mtask::task::Task;

    match Task::create_new(Process::root(), poller_entry, core::ptr::null_mut()) {
        Ok(task) => RunQueues::enqueue(Box::pin(task)),
        Err(e) => log::error!("control_link: failed to spawn poller task: {:?}", e),
    }
}

/// Count of RX bytes dropped to ring overflow (observability). 0 if link down.
pub fn rx_overflow_count() -> u32 {
    with_link(|l| l.rx_overflows).unwrap_or(0)
}

/// True iff the RP2040 peer is alive (inbound seen within the timeout).
pub fn link_alive() -> bool {
    let now = now_ns();
    with_link(|l| l.session.alive(now)).unwrap_or(false)
}

/// Retain the latest monitor-approved complete pair for `MotorSetpoint` TX.
/// `true` means queued locally; the Shrike/FPGA has not acknowledged application.
pub fn send_motor_pair(left: i16, right: i16) -> bool {
    send_motor_pair_with_origin(left, right, None)
}

pub fn send_motor_pair_with_origin(left: i16, right: i16, origin: Option<MotorOrigin>) -> bool {
    let now = now_ns();
    with_link(|l| l.session.alive(now) && l.set_motor_pair(left, right, now, origin))
        .unwrap_or(false)
}

/// Put a fresh zero pair ahead of obsolete unsent motion without changing the
/// peer e-stop latch. A partially transmitted frame still finishes first.
pub fn send_safe_motor_pair() -> bool {
    send_safe_motor_pair_with_origin(None)
}

pub fn send_safe_motor_pair_with_origin(origin: Option<MotorOrigin>) -> bool {
    let now = now_ns();
    with_link(|l| l.session.alive(now) && l.set_safe_motor_pair(now, origin)).unwrap_or(false)
}

pub fn report_motor_queued(left: i16, right: i16) {
    if let Some(sample_id) = crate::driver::iio::take_v04_motor_sample_id() {
        crate::serial_println!(
            "V04_MOTOR_QUEUED sample_id={} left={} right={} ts_ns={}",
            sample_id,
            left,
            right,
            now_ns()
        );
    }
}

/// Command the RP2040 e-stop latch. Returns true if all pending e-stop commands
/// are queued; otherwise the poller will retry before heartbeats/motor setpoints.
pub fn command_estop(assert: bool) -> bool {
    let now = now_ns();
    with_link(|l| l.request_estop(assert, now)).unwrap_or(false)
}

/// Worker-only explicit rearm. The manager has already captured its stop epoch,
/// inhibited the installation and claimed the managed motor pair. This does not
/// release either peer's e-stop latch or run an ordinary installation.
#[cfg(feature = "managed-runtime")]
pub(crate) fn request_rearm(operation: u64) -> Result<(), HandoffError> {
    with_link(|link| {
        if link.rearm.is_some() {
            return Err(HandoffError::Busy);
        }
        let frequency = counter_sample().1;
        let (pending, discarded) = rearm::Rearm::begin(
            operation,
            crate::arch::aarch64::interrupts::physical_counter(),
            frequency,
            &mut link.handoff,
            &mut link.tx,
        )?;
        motor_discard(discarded, MANAGED_AUDIT_DISCARD_INHIBITED);
        link.pending_estop = None;
        link.rx = RingBuf::new();
        link.dec = Decoder::new();
        link.rearm_failure = None;
        link.rearm = Some(pending);
        // Rearm owns both fresh quiet intervals; the startup drain never counts
        // as peer qualification and does not keep ordinary liveness running.
        link.local_quiescence = true;
        crate::bpf::control::invalidate_sensor();
        Ok(())
    })
    .unwrap_or(Err(HandoffError::NotEstablished))
}

#[cfg(feature = "managed-runtime")]
pub(crate) fn cancel_rearm(operation: u64) -> Result<(), HandoffError> {
    with_link(|link| {
        if link
            .rearm
            .as_ref()
            .is_some_and(|pending| pending.operation() == operation)
        {
            link.queue_estop(true);
            Ok(())
        } else if link.rearm_failure.is_some_and(|(id, _)| id == operation) {
            Ok(())
        } else {
            Err(HandoffError::Stale)
        }
    })
    .unwrap_or(Err(HandoffError::NotEstablished))
}

#[cfg(feature = "managed-runtime")]
pub(crate) fn poll_rearm_result(operation: u64) -> Result<Option<RearmReceipt>, HandoffError> {
    with_link(|link| {
        if let Some((id, error)) = link.rearm_failure {
            if id == operation {
                return Err(error);
            }
        }
        if !link
            .rearm
            .as_ref()
            .is_some_and(|pending| pending.operation() == operation)
        {
            return Err(HandoffError::Stale);
        }
        if !link.poll_rearm()? {
            return Ok(None);
        }
        link.handoff
            .take_rearm_ready(crate::arch::aarch64::interrupts::physical_counter())
    })
    .unwrap_or(Err(HandoffError::NotEstablished))
}

/// The owner commits with CPU0 IRQs masked, after rechecking the operation,
/// generation and stop epoch, and before its local-only monitor release.
#[cfg(feature = "managed-runtime")]
pub(crate) fn commit_rearm(receipt: &RearmReceipt) -> Result<(), HandoffError> {
    with_link(|link| {
        if !link
            .rearm
            .as_ref()
            .is_some_and(|pending| pending.operation() == receipt.operation())
        {
            return Err(HandoffError::Stale);
        }
        // An RX byte/stop arriving since the issued receipt must be processed;
        // do not reset a decoder or silently erase it at this commit point.
        if !link.poll_rearm()? {
            return Err(HandoffError::Busy);
        }
        link.handoff.commit_rearm(
            receipt,
            crate::arch::aarch64::interrupts::physical_counter(),
        )?;
        link.rearm = None;
        link.local_quiescence = false;
        link.motor_seq = 0;
        link.rx = RingBuf::new();
        link.dec = Decoder::new();
        link.session = LinkSession::new(LINK_TIMEOUT_NS, HEARTBEAT_PERIOD_NS);
        link.session.on_inbound(now_ns());
        link.link_loss_reported = false;
        Ok(())
    })
    .unwrap_or(Err(HandoffError::NotEstablished))
}

/// Enqueue a message for transmission after any pending e-stop command.
/// False if link down, full, or an earlier e-stop command still cannot fit.
pub fn send(msg: &Msg) -> bool {
    // Managed traffic uses the pair mailbox, trusted stop or correlated
    // transaction owner. An arbitrary frame cannot bypass those boundaries.
    #[cfg(feature = "managed-runtime")]
    {
        let _ = msg;
        false
    }
    #[cfg(not(feature = "managed-runtime"))]
    {
        let now = now_ns();
        with_link(|l| l.flush_pending_estop(now) && l.enqueue(msg, now)).unwrap_or(false)
    }
}

/// Called with the slot already exclusively borrowed at the CPU0 boundary.
/// Session establishment remains closed until the physical drain/rearm adapter
/// supplies its prerequisites; peer liveness alone cannot enable this path.
#[cfg(feature = "managed-runtime")]
pub(crate) fn handoff_boundary(
    slot: &mut crate::bpf::installation::ControlSlot,
    release: kernel_time::periodic::PeriodicRelease,
    frequency: u64,
) -> Result<Option<u64>, HandoffError> {
    let result = with_link(|link| {
        if link.rearm.is_some() {
            // A rearm never resumes the retained installation. There is no
            // installation handoff to run while this management op owns TX.
            return Ok(None);
        }
        if link.pending_estop.is_some() {
            link.handoff.disarm();
        }
        slot.handoff_boundary(
            kernel_time::periodic::PeriodicRelease {
                actual: crate::arch::aarch64::interrupts::physical_counter(),
                ..release
            },
            frequency,
            &mut link.handoff,
            &mut link.tx,
            &mut link.motor_seq,
            now_ns(),
        )
    });
    result.unwrap_or_else(|| {
        if slot.needs_handoff_transport() {
            if let Some(id) = slot.snapshot().pending {
                slot.fail_handoff(id, HandoffError::NotEstablished);
            }
            Err(HandoffError::NotEstablished)
        } else {
            Ok(None)
        }
    })
}
