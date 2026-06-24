//! Dumb byte transport for the Pi5 <-> Shrike-lite control link (v0.4 M2).
//!
//! Moves bytes only — zero safety logic (that is the watchdog's job, M3+). Owns
//! the dedicated link `Pl011`, TX/RX byte rings, and the `shrike_link::Decoder`.
//! Driven by a poll called from the timer tick; dormant (no-op) until `init()`
//! is called at hardware bring-up, so it changes nothing on a normal boot.
//!
//! RP1 UART IRQ-driven RX is deferred (#65 demux); the poll currently both
//! fills the RX ring from the UART and drains it through the decoder. When IRQ
//! RX lands, the IRQ fills `rx` and the poll only drains.

use conquer_once::spin::OnceCell;
use spin::Mutex;

use shrike_link::ring::RingBuf;
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

static CONTROL_LINK: OnceCell<Mutex<ControlLink>> = OnceCell::uninit();

pub struct ControlLink {
    uart: Pl011,
    rx: RingBuf<RING_BYTES>,
    tx: RingBuf<RING_BYTES>,
    dec: Decoder,
    /// RX bytes dropped because the ring was full (observability; CRC rejects
    /// any frame truncated by such a drop, so it's safe but worth counting).
    rx_overflows: u32,
}

impl ControlLink {
    fn poll(&mut self) {
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
                handle_inbound(msg);
            }
            // decode errors are dropped; the decoder resyncs on the next frame.
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

/// Inbound message handler.
///
/// M2 is a dumb transport: decoded frames are dropped here. M3 feeds
/// `LinkLiveness`; M4 routes `Sensor` -> IIO hook + e-stop.
fn handle_inbound(_msg: Msg) {
    // ponytail: intentionally empty until M3/M4 wire liveness + Sensor routing.
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
        })
    });
}

/// Count of RX bytes dropped to ring overflow (observability). 0 if link down.
pub fn rx_overflow_count() -> u32 {
    CONTROL_LINK.get().map_or(0, |l| l.lock().rx_overflows)
}

/// Poll the transport (RX decode + TX drain). Timer-tick driven; no-op until
/// [`init`] runs.
pub fn poll() {
    if let Some(link) = CONTROL_LINK.get() {
        link.lock().poll();
    }
}

/// Enqueue a message for transmission (nonblocking). Returns false if the link
/// is not up or the TX ring can't fit the whole frame. Safe to call from the
/// actuation path — never blocks.
///
/// IRQ-safe: masks IRQs around the `CONTROL_LINK` critical section so the
/// timer-IRQ `poll()` (which spin-locks the same mutex) can never fire while
/// this caller holds it — without this, a timer IRQ during the hold would
/// livelock the kernel on the spinlock.
pub fn send(msg: &Msg) -> bool {
    use crate::arch::aarch64::Aarch64;
    use crate::arch::traits::Architecture;

    let Some(link) = CONTROL_LINK.get() else {
        return false;
    };
    let were_enabled = Aarch64::are_interrupts_enabled();
    if were_enabled {
        Aarch64::disable_interrupts();
    }
    let ok = link.lock().enqueue(msg);
    if were_enabled {
        Aarch64::enable_interrupts();
    }
    ok
}
