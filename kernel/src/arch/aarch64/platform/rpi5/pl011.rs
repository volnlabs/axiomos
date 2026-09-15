//! PL011 UART driver for the Pi5 <-> Shrike-lite control link (v0.4).
//!
//! Distinct from the debug console (`uart.rs`, UART10): this drives a DEDICATED
//! header UART (`RP1_UART0`, GPIO14/15) and does its OWN baud/line init — the
//! console `init()` is a firmware-preserved no-op, so reusing it would give the
//! wrong baud. Only the transport task uses `try_write_byte`/`read_byte`; the ARM-A
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
    pub const DMACR: usize = 0x48; // DMA control
}

mod fr {
    pub const TXFE: u32 = 1 << 7; // TX FIFO empty (not shift-register empty)
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

/// Framing/parity/break/overrun flags in the low four bits, matching UARTRSR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiveError(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    BaudRate,
    NotIdle,
    Receive(ReceiveError),
    InvalidState,
    InvalidTimeout,
    ClockRegression,
    TimedOut,
}

impl InitError {
    /// Stable local-quiescence audit detail (ManagedAuditStopV1 category 5).
    pub const fn audit_code(self) -> u32 {
        match self {
            Self::BaudRate => 1,
            Self::NotIdle => 2,
            Self::InvalidState => 3,
            Self::InvalidTimeout => 4,
            Self::ClockRegression => 5,
            Self::TimedOut => 6,
            Self::Receive(ReceiveError(bits)) => 0x100 | bits as u32,
        }
    }
}

#[derive(Clone, Copy)]
enum DrainPhase {
    Settling,
    Quiet,
    Complete,
    Failed(InitError),
}

#[derive(Clone, Copy)]
struct Drain {
    phase: DrainPhase,
    last: u64,
    deadline: u64,
    since: u64,
    quantum_ns: u64,
}

impl Drain {
    fn sample(&mut self, clock: &mut impl FnMut() -> u64) -> Result<u64, InitError> {
        let now = clock();
        if now < self.last {
            return Err(InitError::ClockRegression);
        }
        if now >= self.deadline {
            return Err(InitError::TimedOut);
        }
        self.last = now;
        Ok(now)
    }
}

/// A PL011 UART instance at a fixed MMIO base.
pub struct Pl011 {
    base: usize,
    character_ns: Option<u64>,
    drain: Option<Drain>,
}

impl Pl011 {
    /// # Safety
    /// `base` must be the MMIO base of a real, mapped PL011, used by one owner.
    pub const unsafe fn new(base: usize) -> Self {
        Self {
            base,
            character_ns: None,
            drain: None,
        }
    }

    #[inline]
    fn r(&self, off: usize) -> MmioReg<u32> {
        // SAFETY: base validated at construction; offset is a known register.
        unsafe { MmioReg::<u32>::new(self.base + off) }
    }

    /// One bounded cold-start attempt. Reject a busy/nonempty UART without
    /// waiting or replaying its buffered bytes; every failure leaves it disabled.
    /// This is not the bilateral reset/drain or 200 ms session qualification.
    pub fn init(&mut self, baud: u32, uart_clk: u32) -> Result<(), InitError> {
        if self.drain.is_some() {
            return Err(InitError::InvalidState);
        }
        self.character_ns = None;
        self.disable();

        // Baud divisor: clk / (16*baud), split integer + 6-bit fraction.
        // BAUDDIV = clk*4 / baud == 64*(clk/(16*baud)); low 6 bits = FBRD.
        // Round (ARM convention) rather than truncate to avoid a systematic
        // positive baud bias.
        if baud == 0 {
            return Err(InitError::BaudRate);
        }
        let b = baud as u64;
        let div64 = ((uart_clk as u64) * 4 + b / 2) / b;
        // PL011 permits divisors 1..=65535; fraction must be zero at 65535.
        if !(64..=65535 * 64).contains(&div64) {
            return Err(InitError::BaudRate);
        }
        let flags = self.r(reg::FR).read();
        let errors = self.r(reg::RSRECR).read() & 0xF;
        if errors != 0 {
            self.r(reg::RSRECR).write(0);
            return Err(InitError::Receive(ReceiveError(errors as u8)));
        }
        if flags & (fr::TXFE | fr::RXFE | fr::BUSY) != fr::TXFE | fr::RXFE {
            return Err(InitError::NotIdle);
        }
        // Disable FIFO mode before programming. No old bytes are accepted as
        // part of a new session merely because this local setup succeeds.
        self.r(reg::LCRH).write(0);
        self.r(reg::IBRD).write((div64 >> 6) as u32);
        self.r(reg::FBRD).write((div64 & 0x3F) as u32);

        // 8 data bits, FIFOs on.
        self.r(reg::LCRH).write(lcrh::WLEN_8 | lcrh::FEN);
        // Clear pending interrupts; this owner remains polled with DMA off.
        self.r(reg::ICR).write(ICR_ALL);
        // Enable.
        self.r(reg::CR).write(cr::UARTEN | cr::TXE | cr::RXE);
        // Ten bits for the configured 8N1 format, using the actual rounded
        // divisor, rounded upward. Reset adds the caller's clock quantum.
        self.character_ns = Some((10 * div64 * 1_000_000_000).div_ceil(4 * u64::from(uart_clk)));
        Ok(())
    }

    fn disable(&self) {
        self.r(reg::CR).write(0);
        self.r(reg::IMSC).write(0);
        self.r(reg::DMACR).write(0);
    }

    /// Start the local half of reset after resolving old software frame
    /// ownership. The result requires both peers' inhibition and coordinated
    /// drain before use as a session prerequisite. Never normal handoff.
    /// ARM DDI0183G 3.3.8: disable, finish the current character, then flush FEN.
    /// No sleeping or polling here; timestamps use a qualified ns clock and
    /// quantum_ns bounds its resolution (ceil(1e9 / counter_frequency)).
    pub fn begin_quiescence(
        &mut self,
        clock: &mut impl FnMut() -> u64,
        timeout_ns: u64,
        quantum_ns: u64,
    ) -> Result<(), InitError> {
        let now = clock();
        let mut drain = Drain {
            phase: DrainPhase::Settling,
            last: now,
            deadline: now,
            since: now,
            quantum_ns,
        };
        self.disable();
        let result = (|| {
            let character = self
                .character_ns
                .ok_or(InitError::InvalidState)?
                .checked_add(quantum_ns)
                .ok_or(InitError::InvalidTimeout)?;
            if quantum_ns == 0
                || character
                    .checked_add(200_000_000)
                    .and_then(|v| v.checked_add(quantum_ns))
                    .is_none_or(|minimum| minimum >= timeout_ns)
            {
                return Err(InitError::InvalidTimeout);
            }
            drain.deadline = now
                .checked_add(timeout_ns)
                .ok_or(InitError::InvalidTimeout)?;
            // Include elapsed disable I/O; start the full character interval
            // after the last write, not before issuing the disable command.
            drain.since = drain
                .sample(clock)?
                .checked_add(character)
                .ok_or(InitError::InvalidTimeout)?;
            Ok(())
        })();
        if let Err(error) = result {
            drain.phase = DrainPhase::Failed(error);
        }
        self.drain = Some(drain);
        result
    }

    /// One bounded local drain pass. An error poisons this attempt until a new
    /// explicit begin. Quiet completion still leaves TX disabled and proves
    /// neither remote quiescence nor sink safety nor operator rearm authority.
    pub fn poll_quiescence(&mut self, clock: &mut impl FnMut() -> u64) -> Result<bool, InitError> {
        let mut drain = self.drain.ok_or(InitError::InvalidState)?;
        if let DrainPhase::Failed(error) = drain.phase {
            return Err(error);
        }
        let result = self.poll_drain(&mut drain, clock);
        if let Err(error) = result {
            self.disable();
            drain.phase = DrainPhase::Failed(error);
        }
        self.drain = Some(drain);
        result
    }

    fn poll_drain(
        &self,
        drain: &mut Drain,
        clock: &mut impl FnMut() -> u64,
    ) -> Result<bool, InitError> {
        let now = drain.sample(clock)?;
        if matches!(drain.phase, DrainPhase::Settling) {
            if now < drain.since {
                return Ok(false);
            }
            // BUSY can stay set for a disabled nonempty TX FIFO. Its old
            // contents must be flushed after the character wait, not replayed.
            self.r(reg::LCRH).write(0);
            self.r(reg::LCRH).write(lcrh::WLEN_8 | lcrh::FEN);
            self.r(reg::RSRECR).write(0);
            // FEN's documented TX flush is not used as proof that RX emptied.
            // RX is disabled; explicitly discard every retained byte/error.
            for _ in 0..64 {
                if self.r(reg::FR).read() & fr::RXFE != 0 {
                    break;
                }
                let _ = self.r(reg::DR).read();
            }
            if self.r(reg::FR).read() & (fr::TXFE | fr::RXFE | fr::BUSY) != fr::TXFE | fr::RXFE {
                return Err(InitError::NotIdle);
            }
            self.r(reg::RSRECR).write(0);
            self.r(reg::ICR).write(ICR_ALL);
            drain.sample(clock)?;
            self.r(reg::CR).write(cr::UARTEN | cr::RXE);
            drain.since = drain.sample(clock)?;
            drain.phase = DrainPhase::Quiet;
            return Ok(false);
        }
        if !self.tx_idle() {
            return Err(InitError::NotIdle);
        }
        for _ in 0..64 {
            let before = drain.sample(clock)?;
            let byte = self.read_byte().map_err(InitError::Receive)?;
            let after = drain.sample(clock)?;
            if byte.is_none() {
                if before - drain.since >= 200_000_000 + drain.quantum_ns {
                    drain.phase = DrainPhase::Complete;
                    return Ok(true);
                }
                return Ok(false);
            }
            drain.since = after;
            drain.phase = DrainPhase::Quiet;
        }
        Ok(false)
    }

    /// Explicitly consume local quiet readiness. The outer protocol must also
    /// establish peer/FPGA qualification before using the reopened transmitter.
    pub fn finish_quiescence(&mut self, clock: &mut impl FnMut() -> u64) -> Result<(), InitError> {
        if let DrainPhase::Failed(error) = self.drain.ok_or(InitError::InvalidState)?.phase {
            return Err(error);
        }
        let result = (|| {
            let complete = self
                .drain
                .is_some_and(|d| matches!(d.phase, DrainPhase::Complete));
            if !complete || !self.poll_quiescence(clock)? || !self.tx_idle() {
                return Err(InitError::NotIdle);
            }
            let drain = self.drain.as_mut().ok_or(InitError::InvalidState)?;
            drain.sample(clock)?;
            self.r(reg::CR).write(cr::UARTEN | cr::TXE | cr::RXE);
            self.drain.as_mut().unwrap().sample(clock)?;
            Ok(())
        })();
        if let Err(error) = result {
            self.disable();
            if let Some(drain) = self.drain.as_mut() {
                drain.phase = DrainPhase::Failed(error);
            }
        } else {
            self.drain = None;
        }
        result
    }

    /// Nonblocking RX. Only an error-free empty FIFO returns `Ok(None)`;
    /// receive faults must invalidate decoder/session and quiescence state.
    pub fn read_byte(&self) -> Result<Option<u8>, ReceiveError> {
        let flags = self.r(reg::FR).read();
        // Overrun is latched immediately, even before a data-register read.
        // Sample it after flags so an error at the empty observation is not idle.
        let status = self.r(reg::RSRECR).read() & 0xF;
        if status != 0 {
            self.r(reg::RSRECR).write(0);
            return Err(ReceiveError(status as u8));
        }
        if flags & fr::RXFE != 0 {
            return Ok(None);
        }
        let dr = self.r(reg::DR).read();
        if dr & DR_ERR_MASK != 0 {
            // Clear the sticky error latch and drop the byte.
            self.r(reg::RSRECR).write(0);
            return Err(ReceiveError(((dr & DR_ERR_MASK) >> 8) as u8));
        }
        Ok(Some((dr & 0xFF) as u8))
    }

    /// Both FIFO and the last transmitted stop bit have drained. This is a
    /// local UART observation, never a peer acknowledgement or safe-output proof.
    pub fn tx_idle(&self) -> bool {
        self.r(reg::FR).read() & (fr::TXFE | fr::BUSY) == fr::TXFE
    }

    /// One nonblocking acceptance attempt. The caller advances its frame only
    /// after `true`; FIFO backpressure leaves that same byte pending.
    pub fn try_write_byte(&self, b: u8) -> bool {
        if self.drain.is_some() {
            return false;
        }
        if self.r(reg::FR).read() & fr::TXFF != 0 {
            return false;
        }
        self.r(reg::DR).write(b as u32);
        true
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
