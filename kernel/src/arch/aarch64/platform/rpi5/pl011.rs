//! PL011 UART driver for the Pi5 <-> Shrike-lite control link (v0.4).
//!
//! Distinct from the debug console (`uart.rs`, UART10): this drives a DEDICATED
//! header UART (`RP1_UART0`, GPIO14/15) and does its OWN baud/line init — the
//! console `init()` is a firmware-preserved no-op, so reusing it would give the
//! wrong baud. Only the transport task uses `write_byte`/`read_byte`; the ARM-A
//! actuation seam must never block on this (it enqueues into a TX ring instead).
//!
//! Pinmux: GPIO14/15 must be in UART alt-function (firmware / `config.txt`).
//! IRQ-driven RX is deferred (needs the RP1 peripheral IRQ demux, #65); v0.4
//! runs a polled transport service.

use super::mmio::MmioReg;

/// Default RP1 UART reference clock (Hz). Bench knob if the firmware differs.
pub const DEFAULT_UART_CLK_HZ: u32 = 48_000_000;

mod reg {
    pub const DR: usize = 0x00; // data
    pub const RSRECR: usize = 0x04; // receive status / error clear
    pub const FR: usize = 0x18; // flags
    pub const IBRD: usize = 0x24; // integer baud divisor
    pub const FBRD: usize = 0x28; // fractional baud divisor
    pub const LCRH: usize = 0x2C; // line control
    pub const CR: usize = 0x30; // control
    pub const IMSC: usize = 0x38; // interrupt mask set/clear
    pub const ICR: usize = 0x44; // interrupt clear
}

mod fr {
    pub const TXFF: u32 = 1 << 5; // TX FIFO full
    pub const RXFE: u32 = 1 << 4; // RX FIFO empty
    pub const BUSY: u32 = 1 << 3; // transmitting
}

mod lcrh {
    pub const FEN: u32 = 1 << 4; // FIFO enable
    pub const WLEN_8: u32 = 0b11 << 5; // 8-bit word
}

mod cr {
    pub const UARTEN: u32 = 1 << 0;
    pub const TXE: u32 = 1 << 8;
    pub const RXE: u32 = 1 << 9;
}

/// RX interrupt mask bit (for the deferred IRQ-driven path).
const IMSC_RXIM: u32 = 1 << 4;
/// Clear-all mask for the interrupt-clear register.
const ICR_ALL: u32 = 0x7FF;
/// DR error bits [11:8]: framing / parity / break / overrun.
const DR_ERR_MASK: u32 = 0xF00;

/// A PL011 UART instance at a fixed MMIO base.
pub struct Pl011 {
    base: usize,
}

impl Pl011 {
    /// # Safety
    /// `base` must be the MMIO base of a real, mapped PL011, used by one owner.
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    #[inline]
    fn r(&self, off: usize) -> MmioReg<u32> {
        // SAFETY: base validated at construction; offset is a known register.
        unsafe { MmioReg::<u32>::new(self.base + off) }
    }

    /// Program 8N1 at `baud` from `uart_clk` and enable TX+RX. Unlike the
    /// console, this does the real init (the link UART is not firmware-set up).
    pub fn init(&mut self, baud: u32, uart_clk: u32) {
        // Disable while reconfiguring, and drain any in-flight TX.
        self.r(reg::CR).write(0);
        while self.r(reg::FR).read() & fr::BUSY != 0 {}

        // Baud divisor: clk / (16*baud), split integer + 6-bit fraction.
        // BAUDDIV = clk*4 / baud == 64*(clk/(16*baud)); low 6 bits = FBRD.
        // Round (ARM convention) rather than truncate to avoid a systematic
        // positive baud bias.
        let b = baud.max(1) as u64;
        let div64 = ((uart_clk as u64) * 4 + b / 2) / b;
        self.r(reg::IBRD).write((div64 >> 6) as u32);
        self.r(reg::FBRD).write((div64 & 0x3F) as u32);

        // 8 data bits, FIFOs on.
        self.r(reg::LCRH).write(lcrh::WLEN_8 | lcrh::FEN);
        // Mask all interrupts (polled v0.4) and clear any pending.
        self.r(reg::IMSC).write(0);
        self.r(reg::ICR).write(ICR_ALL);
        // Enable.
        self.r(reg::CR).write(cr::UARTEN | cr::TXE | cr::RXE);
    }

    /// Nonblocking RX of one byte, `None` if the RX FIFO is empty OR the byte
    /// carried a framing/parity/break/overrun error (a corrupt byte is dropped,
    /// never returned — the decoder must not see garbage; CRC is the last line).
    pub fn read_byte(&self) -> Option<u8> {
        if self.r(reg::FR).read() & fr::RXFE != 0 {
            return None;
        }
        let dr = self.r(reg::DR).read();
        if dr & DR_ERR_MASK != 0 {
            // Clear the sticky error latch and drop the byte.
            self.r(reg::RSRECR).write(0);
            return None;
        }
        Some((dr & 0xFF) as u8)
    }

    /// Blocking TX of one byte (spins on TX-FIFO-full). Transport task only —
    /// never call from the actuation path while holding APPLY_LOCK.
    pub fn write_byte(&self, b: u8) {
        while self.r(reg::FR).read() & fr::TXFF != 0 {}
        self.r(reg::DR).write(b as u32);
    }

    /// Enable RX interrupts (for the future IRQ-driven path, once RP1 IRQ
    /// demux exists). Unused by the v0.4 polled service.
    pub fn enable_rx_irq(&mut self) {
        self.r(reg::IMSC).write(IMSC_RXIM);
    }

    /// Clear all pending UART interrupts.
    pub fn clear_irq(&self) {
        self.r(reg::ICR).write(ICR_ALL);
    }
}
