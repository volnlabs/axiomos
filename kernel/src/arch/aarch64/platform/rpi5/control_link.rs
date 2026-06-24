//! Pi5 <-> Shrike-lite control link transport (v0.4 M2 + M3).
//!
//! M2 = dumb byte transport (Pl011 + TX/RX rings + `shrike_link::Decoder`).
//! M3 = link liveness + heartbeat + fail-safe: tracks whether the RP2040 is
//! still talking (`LinkLiveness`), heartbeats it while alive, and on link-death
//! STOPS heartbeating and commands a safe state — so the RP2040's own watchdog
//! also trips (one-way RX-dead/TX-alive fault closed). Actuation TX (ARM-A ->
//! MotorSetpoint) and Sensor->IIO routing are M4.
//!
//! Driven by a poll on the timer tick; dormant until `init()` at HW bring-up.
//! RP1 UART IRQ-driven RX is deferred (#65 demux); the poll fills the RX ring
//! from the FIFO and drains it. Time is the ARM generic timer (monotonic).

use conquer_once::spin::OnceCell;
use spin::Mutex;

use shrike_link::ring::RingBuf;
use shrike_link::session::{LinkAction, LinkSession};
use shrike_link::{encode, Decoder, Msg, MAX_FRAME};

use super::memory_map::RP1_UART0_BASE;
use super::pl011::{Pl011, DEFAULT_UART_CLK_HZ};

/// TX/RX ring capacity (frames are <= MAX_FRAME ~ 22 bytes; 256 is ample).
const RING_BYTES: usize = 256;
/// Link baud — MUST match the RP2040 firmware (`shrike_rp2040` UART_BAUD).
const LINK_BAUD: u32 = 115_200;
/// Per-poll work caps. Bound IRQ-context work: never spin/loop unboundedly in
/// the timer handler if the peer floods (RX) or stalls (TX, no flow control).
const RX_PER_POLL: usize = 64;
const TX_PER_POLL: usize = 64;
/// Inbound-silence timeout: if the RP2040 sends nothing for this long, the link
/// is dead. MUST be strictly > the RP2040 firmware's own LINK_TIMEOUT (100 ms)
/// so the peer's local watchdog trips FIRST (cuts motors), and the Pi only then
/// declares the link dead. (ns)
const LINK_TIMEOUT_NS: u64 = 150_000_000; // 150 ms (> firmware 100 ms)
/// Heartbeat period while the link is alive. (ns)
const HEARTBEAT_PERIOD_NS: u64 = 20_000_000; // 20 ms (50 Hz)

static CONTROL_LINK: OnceCell<Mutex<ControlLink>> = OnceCell::uninit();

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

pub struct ControlLink {
    uart: Pl011,
    rx: RingBuf<RING_BYTES>,
    tx: RingBuf<RING_BYTES>,
    dec: Decoder,
    /// RX bytes dropped because the ring was full (observability; CRC rejects
    /// any frame truncated by such a drop, so it's safe but worth counting).
    rx_overflows: u32,
    /// Liveness + heartbeat/fail-safe decision logic (host-tested).
    session: LinkSession,
}

impl ControlLink {
    fn poll(&mut self, now: u64) {
        // RX: bounded pull from the UART FIFO into the ring (the IRQ path will
        // do this once RP1 UART IRQ demux exists), then decode complete frames.
        let mut got = 0;
        while got < RX_PER_POLL {
            match self.uart.read_byte() {
                Some(b) => {
                    if !self.rx.push(b) {
                        // ring full: this byte is dropped (CRC rejects the
                        // resulting truncated frame; decoder resyncs).
                        self.rx_overflows = self.rx_overflows.wrapping_add(1);
                    }
                    got += 1;
                }
                None => break,
            }
        }
        while let Some(b) = self.rx.pop() {
            if let Some(Ok(msg)) = self.dec.push(b) {
                // Any valid inbound frame refreshes liveness (M4 also routes
                // Sensor -> IIO here).
                self.session.on_inbound(now);
                handle_inbound(msg);
            }
            // decode errors are dropped; the decoder resyncs on the next frame.
        }

        // Liveness-driven heartbeat / fail-safe (decision logic host-tested in
        // shrike_link::session). On link death: stop heartbeating (so the
        // RP2040 watchdog trips) and command e-stop, retried until it's sent.
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

        // TX: bounded drain. Stop when the FIFO is full so write_byte never
        // actually spins in the IRQ handler (no peer flow control).
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
    }

    /// Enqueue a whole frame, or nothing. Never enqueues a partial frame (a torn
    /// frame on the wire would desync the peer). Returns false if it doesn't fit.
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
}

/// Inbound message handler. Liveness is already refreshed by the caller in
/// `poll()`. M4 routes `Sensor` -> IIO hook + e-stop here.
fn handle_inbound(_msg: Msg) {
    // ponytail: M3 only needs liveness (done in poll). M4 adds Sensor->IIO.
}

/// Bring up the dedicated link UART. Call once, at hardware bring-up — NOT in
/// early boot (it programs RP1_UART0 MMIO). No-op if already initialized.
pub fn init() {
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
        })
    });
}

/// Run `f` with the `CONTROL_LINK` lock held and IRQs masked. Required for any
/// thread-context access: the timer-IRQ `poll()` spin-locks the same mutex, so
/// a caller preempted mid-critical-section would livelock the IRQ. (`poll()`
/// itself runs in IRQ context with IRQs already masked, so it locks directly.)
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

/// Count of RX bytes dropped to ring overflow (observability). 0 if link down.
pub fn rx_overflow_count() -> u32 {
    with_link(|l| l.rx_overflows).unwrap_or(0)
}

/// True iff the RP2040 peer is alive (inbound seen within the timeout). False
/// if the link is down/uninitialized. M4's ARM-A gate consults this to refuse
/// actuation on a dead link. IRQ-safe.
pub fn link_alive() -> bool {
    let now = now_ns();
    with_link(|l| l.session.alive(now)).unwrap_or(false)
}

/// Poll the transport (RX decode + heartbeat/fail-safe + TX drain). Timer-tick
/// driven; no-op until [`init`] runs.
pub fn poll() {
    if let Some(link) = CONTROL_LINK.get() {
        let now = now_ns();
        link.lock().poll(now);
    }
}

/// Enqueue a message for transmission (nonblocking). Returns false if the link
/// is not up or the TX ring can't fit the whole frame. Safe to call from the
/// actuation path — never blocks.
///
/// IRQ-safe (via [`with_link`]): masks IRQs around the `CONTROL_LINK` critical
/// section so the timer-IRQ `poll()` can never livelock spinning on a held lock.
pub fn send(msg: &Msg) -> bool {
    with_link(|l| l.enqueue(msg)).unwrap_or(false)
}
