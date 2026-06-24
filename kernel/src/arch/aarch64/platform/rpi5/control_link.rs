//! Pi5 <-> Shrike-lite control link transport (v0.4 M2–M4).
//!
//! Runs in a dedicated KERNEL THREAD (the poller task), NOT the timer IRQ — so
//! the RX side-effects (IIO dispatch, e-stop) and the motor TX all happen in
//! thread context, where taking BPF_MANAGER / APPLY_LOCK is safe. The timer IRQ
//! does nothing here.
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

use conquer_once::spin::OnceCell;
use spin::Mutex;

use kernel_bpf::profile::{ActiveProfile, PhysicalProfile};
use shrike_link::motor::{duty_to_permille, MotorSide};
use shrike_link::ring::RingBuf;
use shrike_link::session::{LinkAction, LinkSession};
use shrike_link::{encode, Decoder, Msg, MAX_FRAME};

use super::memory_map::RP1_UART0_BASE;
use super::pl011::{Pl011, DEFAULT_UART_CLK_HZ};

/// TX/RX ring capacity (frames are <= MAX_FRAME ~ 22 bytes; 256 is ample).
const RING_BYTES: usize = 256;
/// Link baud — MUST match the RP2040 firmware (`shrike_rp2040` UART_BAUD).
const LINK_BAUD: u32 = 115_200;
/// Per-service work caps (bound the work done per poller pass).
const RX_PER_POLL: usize = 64;
const TX_PER_POLL: usize = 64;
/// Inbound-silence timeout. MUST be strictly > the RP2040 firmware LINK_TIMEOUT
/// (100 ms) so the peer's local watchdog fails the motors FIRST. (ns)
const LINK_TIMEOUT_NS: u64 = 150_000_000; // 150 ms
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

static CONTROL_LINK: OnceCell<Mutex<ControlLink>> = OnceCell::uninit();

/// Map an actuation `(chip, channel)` to the wheel it drives, if it is a
/// link-owned motor. Unmapped channels keep local RP1 PWM.
#[must_use]
pub fn motor_side(chip: u8, channel: u8) -> Option<MotorSide> {
    if chip != MOTOR_CHIP {
        return None;
    }
    match channel {
        MOTOR_LEFT_CHANNEL => Some(MotorSide::Left),
        MOTOR_RIGHT_CHANNEL => Some(MotorSide::Right),
        _ => None,
    }
}

/// Monotonic nanoseconds from the ARM generic timer (CNTVCT/CNTFRQ).
fn now_ns() -> u64 {
    let (cnt, frq): (u64, u64);
    // SAFETY: reading the virtual counter + its frequency is allowed in EL1.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) cnt);
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frq);
    }
    if frq == 0 {
        return 0;
    }
    let secs = cnt / frq;
    let rem = cnt % frq;
    secs * 1_000_000_000 + (rem * 1_000_000_000) / frq
}

/// What a decode pass produced that must be acted on OUTSIDE the lock.
#[derive(Default, Clone, Copy)]
struct PollOutcome {
    /// Hardware e-stop line asserted in an inbound Sensor frame.
    estop: bool,
    /// Latest ultrasonic echo time (µs), if a Sensor frame arrived.
    sensor_echo_us: Option<u16>,
}

pub struct ControlLink {
    uart: Pl011,
    rx: RingBuf<RING_BYTES>,
    tx: RingBuf<RING_BYTES>,
    dec: Decoder,
    rx_overflows: u32,
    session: LinkSession,
    /// Cached per-wheel setpoint (per-mille) — MotorSetpoint carries both, so a
    /// single-channel actuation keeps the other wheel's last value.
    motor_left: i16,
    motor_right: i16,
    motor_seq: u8,
}

impl ControlLink {
    /// Drain UART -> decode -> liveness/heartbeat/fail-safe -> TX. Returns the
    /// inbound side-effects to run after the lock is dropped. No BPF/estop here.
    fn poll_decode(&mut self, now: u64) -> PollOutcome {
        let mut out = PollOutcome::default();

        // RX: bounded pull from the UART FIFO into the ring, then decode.
        let mut got = 0;
        while got < RX_PER_POLL {
            match self.uart.read_byte() {
                Some(b) => {
                    if !self.rx.push(b) {
                        self.rx_overflows = self.rx_overflows.wrapping_add(1);
                    }
                    got += 1;
                }
                None => break,
            }
        }
        while let Some(b) = self.rx.pop() {
            if let Some(Ok(msg)) = self.dec.push(b) {
                self.session.on_inbound(now);
                if let Msg::Sensor {
                    ultrasonic_echo_us,
                    estop_line,
                    ..
                } = msg
                {
                    out.sensor_echo_us = Some(ultrasonic_echo_us);
                    out.estop |= estop_line;
                }
            }
        }

        // Liveness-driven heartbeat / fail-safe.
        match self.session.tick(now) {
            LinkAction::Heartbeat(seq) => {
                let _ = self.enqueue(&Msg::HeartbeatToShrike { seq });
            }
            LinkAction::SafeStop => {
                if self.enqueue(&Msg::Estop { assert: true }) {
                    self.session.estop_sent();
                }
            }
            LinkAction::Idle => {}
        }

        // TX: bounded drain. Stop when the FIFO is full (write_byte won't spin).
        let mut sent = 0;
        while sent < TX_PER_POLL && !self.uart.tx_full() {
            match self.tx.pop() {
                Some(b) => {
                    self.uart.write_byte(b);
                    sent += 1;
                }
                None => break,
            }
        }
        out
    }

    /// Enqueue a whole frame, or nothing (never a partial/torn frame). Returns
    /// false if it doesn't fit.
    fn enqueue(&mut self, msg: &Msg) -> bool {
        let mut buf = [0u8; MAX_FRAME];
        let n = match encode(msg, &mut buf) {
            Ok(n) => n,
            Err(_) => return false,
        };
        if RING_BYTES - self.tx.len() < n {
            return false;
        }
        for &b in &buf[..n] {
            self.tx.push(b);
        }
        true
    }

    /// Update one wheel and enqueue the combined `MotorSetpoint`.
    fn set_motor(&mut self, side: MotorSide, permille: i16) -> bool {
        match side {
            MotorSide::Left => self.motor_left = permille,
            MotorSide::Right => self.motor_right = permille,
        }
        self.motor_seq = self.motor_seq.wrapping_add(1);
        self.enqueue(&Msg::MotorSetpoint {
            seq: self.motor_seq,
            left: self.motor_left,
            right: self.motor_right,
        })
    }
}

/// Run `f` with the `CONTROL_LINK` lock held and IRQs masked. Belt-and-suspenders:
/// the poller is a thread today, but masking keeps this correct if RP1 UART IRQ
/// RX is added later.
fn with_link<R>(f: impl FnOnce(&mut ControlLink) -> R) -> Option<R> {
    use crate::arch::aarch64::Aarch64;
    use crate::arch::traits::Architecture;

    let link = CONTROL_LINK.get()?;
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
        return; // link not up
    };

    // Side-effects OUTSIDE the CONTROL_LINK lock (thread context).
    if out.estop {
        crate::actuation::watchdog_estop_trigger();
    }
    if let Some(echo) = out.sensor_echo_us {
        dispatch_ultrasonic(now, echo);
    }
}

/// Inject an ultrasonic reading as a synthetic IIO event so `ATTACH_TYPE_IIO`
/// BPF behaviors see it (bypasses the stub `IioAttach::attach`).
fn dispatch_ultrasonic(now: u64, echo_us: u16) {
    use kernel_bpf::attach::IioEvent;
    if let Some(mgr) = crate::driver::iio::IIO_MANAGER.get() {
        let event = IioEvent {
            timestamp: now,
            device_id: ULTRASONIC_DEVICE_ID,
            channel: ULTRASONIC_CHANNEL,
            value: echo_us as i32,
            scale: 1_000_000, // 1.0 (raw µs); behavior converts to range
            offset: 0,
        };
        mgr.lock().dispatch_event(event);
    }
}

/// Bring up the dedicated link UART. Called by `spawn()` at HW bring-up — NOT in
/// early boot. No-op if already initialized.
fn init() {
    CONTROL_LINK.init_once(|| {
        // SAFETY: RP1_UART0 is a mapped RP1 peripheral on the Pi5; single owner.
        let mut uart = unsafe { Pl011::new(RP1_UART0_BASE) };
        uart.init(LINK_BAUD, DEFAULT_UART_CLK_HZ);
        Mutex::new(ControlLink {
            uart,
            rx: RingBuf::new(),
            tx: RingBuf::new(),
            dec: Decoder::new(),
            rx_overflows: 0,
            session: LinkSession::new(LINK_TIMEOUT_NS, HEARTBEAT_PERIOD_NS),
            motor_left: 0,
            motor_right: 0,
            motor_seq: 0,
        })
    });
}

/// Poller task entry: bring up the link, then service it forever. `wfi` sleeps
/// until the next interrupt (the timer tick), giving ~per-tick service cadence
/// at low CPU.
extern "C" fn poller_entry(_arg: *mut core::ffi::c_void) {
    init();
    loop {
        service();
        // SAFETY: wait-for-interrupt; the periodic timer wakes us.
        unsafe { core::arch::asm!("wfi") };
    }
}

/// Spawn the control-link poller as a kernel task. Call once at boot (rpi5).
pub fn spawn() {
    use crate::mcore::mtask::process::Process;
    use crate::mcore::mtask::scheduler::global::GlobalTaskQueue;
    use crate::mcore::mtask::task::Task;

    match Task::create_new(Process::root(), poller_entry, core::ptr::null_mut()) {
        Ok(task) => GlobalTaskQueue::enqueue(Box::pin(task)),
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

/// Route a monitor-clamped motor duty to the link as a `MotorSetpoint`. Returns
/// true if the setpoint was enqueued. Forward-only (v0.4); `value` must be the
/// ARM-A-clamped duty.
pub fn send_motor(side: MotorSide, value: u32) -> bool {
    let permille = duty_to_permille(value, ActiveProfile::ACT_DUTY_MAX);
    with_link(|l| l.set_motor(side, permille)).unwrap_or(false)
}

/// Command the RP2040 to e-stop (used when ARM-A e-stops link-owned motors, so
/// the safe state reaches the peer, not just the local PWM). Best-effort.
pub fn command_estop() -> bool {
    with_link(|l| l.enqueue(&Msg::Estop { assert: true })).unwrap_or(false)
}

/// Enqueue a message for transmission (nonblocking). False if link down or full.
pub fn send(msg: &Msg) -> bool {
    with_link(|l| l.enqueue(msg)).unwrap_or(false)
}
