//! Exclusive mode-0 FPGA runtime transactions. Configuration streaming is separate.
//! Timing values require candidate qualification; no default enables this bus.
//! PL022 register/FIFO/BSY contract: RP2040 datasheet, section 4.4.
//! https://datasheets.raspberrypi.com/rp2040/rp2040-datasheet.pdf

const TFE: u32 = 1;
const TNF: u32 = 2;
const RNE: u32 = 4;
const BSY: u32 = 16;
const MAX_POLLS: u32 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Disabled,
    InvalidLength,
    InvalidTiming,
    DirtyBus,
    Overrun,
    Timeout,
    ClockRegression,
    PollLimit,
    ChipSelect,
    ResetNotReady,
}

#[derive(Clone, Copy)]
pub(crate) struct Timing {
    pub setup_us: u64,
    pub hold_us: u64,
    pub high_us: u64,
    pub timeout_us: u64,
}

// Private register seam, shared with the host model, as in the UART adapter.
pub(crate) trait Registers {
    fn now_us(&mut self) -> u64;
    fn enabled(&mut self) -> bool;
    fn flags(&mut self) -> u32;
    fn overrun(&mut self) -> bool;
    fn read_data(&mut self) -> u8;
    fn write_data(&mut self, byte: u8);
    fn select(&mut self, selected: bool) -> bool;
    fn disable(&mut self);
}

pub(crate) struct RuntimeSpi<R> {
    registers: R,
    timing: Option<Timing>,
}

struct Budget {
    last: u64,
    deadline: u64,
    remaining: u32,
}
impl Budget {
    fn sample(&mut self, registers: &mut impl Registers) -> Result<u64, Error> {
        if self.remaining == 0 {
            return Err(Error::PollLimit);
        }
        self.remaining -= 1;
        let now = registers.now_us();
        if now < self.last {
            return Err(Error::ClockRegression);
        }
        if now >= self.deadline {
            return Err(Error::Timeout);
        }
        self.last = now;
        Ok(now)
    }
    fn wait(&mut self, registers: &mut impl Registers, delay: u64) -> Result<(), Error> {
        let start = self.sample(registers)?;
        loop {
            // One extra timer tick covers quantization of the first sample.
            if self.sample(registers)? - start > delay {
                return Ok(());
            }
        }
    }
}

impl<R: Registers> RuntimeSpi<R> {
    pub(crate) fn new(registers: R) -> Self {
        Self {
            registers,
            timing: None,
        }
    }

    /// Only the FPGA configuration owner may supply calibrated timings after
    /// bus reinitialization. This does not enable hardware or release reset.
    pub(crate) fn set_timing(&mut self, timing: Timing) -> Result<(), Error> {
        self.timing = None;
        if timing.setup_us == 0
            || timing.hold_us == 0
            || timing.high_us == 0
            || timing
                .setup_us
                .checked_add(timing.hold_us)
                .and_then(|v| v.checked_add(timing.high_us))
                .and_then(|v| v.checked_add(3))
                .is_none_or(|v| v >= timing.timeout_us)
        {
            self.inhibit();
            return Err(Error::InvalidTiming);
        }
        self.timing = Some(timing);
        Ok(())
    }

    pub(crate) fn inhibit(&mut self) {
        self.timing = None;
        // Failure may truncate this FPGA transaction; the lifecycle caller
        // also asserts runtime reset and PWR/EN safe. No command is retried.
        let _ = self.registers.select(false);
        self.registers.disable();
    }

    pub(crate) fn transfer<const N: usize>(&mut self, bytes: &[u8; N]) -> Result<[u8; N], Error> {
        let result = self.transfer_inner(bytes);
        if result.is_err() {
            self.inhibit();
        }
        result
    }

    fn checked_flags(&mut self, budget: &mut Budget) -> Result<u32, Error> {
        budget.sample(&mut self.registers)?;
        let flags = self.registers.flags();
        if self.registers.overrun() {
            return Err(Error::Overrun);
        }
        budget.sample(&mut self.registers)?;
        Ok(flags)
    }

    fn transfer_inner<const N: usize>(&mut self, bytes: &[u8; N]) -> Result<[u8; N], Error> {
        if N != 2 && N != 12 {
            return Err(Error::InvalidLength);
        }
        let timing = self.timing.ok_or(Error::Disabled)?;
        if !self.registers.enabled() {
            return Err(Error::Disabled);
        }
        let now = self.registers.now_us();
        let mut budget = Budget {
            last: now,
            deadline: now
                .checked_add(timing.timeout_us)
                .ok_or(Error::InvalidTiming)?,
            remaining: MAX_POLLS,
        };
        if self.checked_flags(&mut budget)? & (TFE | RNE | BSY) != TFE {
            return Err(Error::DirtyBus);
        }
        if !self.registers.select(false) {
            return Err(Error::ChipSelect);
        }
        budget.wait(&mut self.registers, timing.high_us)?;
        if !self.registers.select(true) {
            return Err(Error::ChipSelect);
        }
        budget.wait(&mut self.registers, timing.setup_us)?;
        let mut reply = [0; N];
        for (&byte, received) in bytes.iter().zip(reply.iter_mut()) {
            loop {
                let flags = self.checked_flags(&mut budget)?;
                if flags & RNE != 0 {
                    return Err(Error::DirtyBus);
                }
                if flags & TNF != 0 {
                    break;
                }
            }
            self.registers.write_data(byte);
            while self.checked_flags(&mut budget)? & RNE == 0 {}
            *received = self.registers.read_data();
            // One byte in flight bounds RX occupancy independently of stalls.
            budget.sample(&mut self.registers)?;
        }
        loop {
            let flags = self.checked_flags(&mut budget)?;
            if flags & RNE != 0 {
                return Err(Error::DirtyBus);
            }
            if flags & (TFE | BSY) == TFE {
                break;
            }
        }
        budget.wait(&mut self.registers, timing.hold_us)?;
        // Include elapsed I/O and any late overrun before ending the frame.
        if self.checked_flags(&mut budget)? & (TFE | RNE | BSY) != TFE {
            return Err(Error::DirtyBus);
        }
        if !self.registers.select(false) {
            return Err(Error::ChipSelect);
        }
        budget.sample(&mut self.registers)?;
        Ok(reply)
    }
}

#[cfg(not(test))]
mod target {
    use embedded_hal::digital::{OutputPin, PinState};
    use rp2040_hal::gpio::bank0::{Gpio0, Gpio1, Gpio2, Gpio3};
    use rp2040_hal::gpio::{FunctionSio, FunctionSpi, Pin, PullDown, SioOutput};
    use rp2040_hal::pac;
    use rp2040_hal::spi::{Disabled, Spi};
    use shrike_control::MicrosClock;

    use super::{Error, Registers, RuntimeSpi, Timing};
    use crate::uart::TimerClock;

    type Pins = (
        Pin<Gpio3, FunctionSpi, PullDown>,
        Pin<Gpio0, FunctionSpi, PullDown>,
        Pin<Gpio2, FunctionSpi, PullDown>,
    );
    type ChipSelect = Pin<Gpio1, FunctionSio<SioOutput>, PullDown>;

    pub(crate) struct Spi0<'a> {
        peripheral: pac::SPI0,
        _pins: Pins,
        cs: ChipSelect,
        clock: &'a TimerClock,
    }

    impl<'a> RuntimeSpi<Spi0<'a>> {
        pub(crate) fn from_disabled(
            spi: Spi<Disabled, pac::SPI0, Pins, 8>,
            mut cs: ChipSelect,
            clock: &'a TimerClock,
            resets: &mut pac::RESETS,
        ) -> Result<Self, Error> {
            cs.set_high().map_err(|_| Error::ChipSelect)?;
            let (peripheral, pins) = spi.free();
            // Both frame engines/FIFOs must start empty. Bounded reset replaces
            // HAL init's unbounded wait; SSE stays clear and sends no clocks.
            resets.reset().modify(|_, w| w.spi0().set_bit());
            resets.reset().modify(|_, w| w.spi0().clear_bit());
            for _ in 0..16 {
                if resets.reset_done().read().spi0().bit_is_set() {
                    return Ok(Self::new(Spi0 {
                        peripheral,
                        _pins: pins,
                        cs,
                        clock,
                    }));
                }
            }
            resets.reset().modify(|_, w| w.spi0().set_bit());
            Err(Error::ResetNotReady)
        }

        /// Configuration owner only, after a qualified FPGA image is ready.
        /// SPI Hz = peripheral Hz / (prescale * (postdivide + 1)). No default
        /// rate or timings are qualified here. Never clears FPGA reset/e-stop.
        pub(crate) fn configure_runtime(
            &mut self,
            prescale: u8,
            postdivide: u8,
            timing: Timing,
        ) -> Result<(), Error> {
            self.inhibit();
            if prescale < 2 || prescale & 1 != 0 {
                return Err(Error::InvalidTiming);
            }
            if self.registers.flags() & (super::TFE | super::RNE | super::BSY) != super::TFE
                || self.registers.overrun()
            {
                return Err(Error::DirtyBus);
            }
            self.set_timing(timing)?;
            let spi = &self.registers.peripheral;
            // SAFETY: exclusive SPI0 owner, SSE clear; mode 0 Motorola, 8-bit
            // words, checked even prescale 2..254 and u8 postdivide. No reserved
            // bits, DMA requests, interrupts, slave or loopback modes enabled.
            unsafe {
                spi.sspimsc().write(|w| w.bits(0));
                spi.sspdmacr().write(|w| w.bits(0));
                spi.sspcr0()
                    .write(|w| w.bits((u32::from(postdivide) << 8) | 7));
                spi.sspcpsr().write(|w| w.bits(u32::from(prescale)));
            }
            spi.sspcr1().write(|w| w.sse().set_bit());
            Ok(())
        }
    }

    impl Registers for Spi0<'_> {
        fn now_us(&mut self) -> u64 {
            self.clock.now_us()
        }
        fn enabled(&mut self) -> bool {
            self.peripheral.sspcr1().read().sse().bit_is_set()
        }
        fn flags(&mut self) -> u32 {
            self.peripheral.sspsr().read().bits()
        }
        fn overrun(&mut self) -> bool {
            self.peripheral.sspris().read().rorris().bit_is_set()
        }
        fn read_data(&mut self) -> u8 {
            self.peripheral.sspdr().read().data().bits() as u8
        }
        fn write_data(&mut self, byte: u8) {
            // SAFETY: sole SPI0 owner; shared algorithm checked TNF and has at
            // most one byte in flight. u8 fits the data field, reserved bits zero.
            self.peripheral
                .sspdr()
                .write(|w| unsafe { w.data().bits(u16::from(byte)) });
        }
        fn select(&mut self, selected: bool) -> bool {
            self.cs
                .set_state(if selected {
                    PinState::Low
                } else {
                    PinState::High
                })
                .is_ok()
        }
        fn disable(&mut self) {
            self.peripheral.sspcr1().modify(|_, w| w.sse().clear_bit());
        }
    }
}
